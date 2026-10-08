# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Windows ACLs: `icacls` writes them and the Win32 API reads them back as SIDs.

`icacls` prints localised account names and `os.chmod` sets no ACL, so every grant here names a well-known SID and
every comparison is between SID strings. Errors surface as `OSError` or `subprocess.CalledProcessError`;
`ctl.perms` turns them into its own.
"""

import csv
import dataclasses
import io
import re
import subprocess
from collections.abc import Collection
from pathlib import Path

SID_EVERYONE = "S-1-1-0"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_LOCAL_SERVICE = "S-1-5-19"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_USERS = "S-1-5-32-545"

SID = re.compile(r"S-1-[0-9]+(-[0-9]+)+", re.ASCII)
INHERITED_ACE = 0x10
INHERIT_ONLY_ACE = 0x08
SE_DACL_PROTECTED = 0x1000
ACCESS_ALLOWED_ACE_TYPE = 0
DENY_ACE_TYPES = frozenset({1, 6, 10, 12})
FILE_ALL_ACCESS = 0x1F01FF
DIRECTORY_INHERIT = "(OI)(CI)"


@dataclasses.dataclass(frozen=True)
class Ace:
    """One allow entry. `flags` holds the ACE header flags, including inherit and inherited."""
    sid: str
    mask: int
    flags: int


@dataclasses.dataclass(frozen=True)
class Acl:
    aces: tuple[Ace, ...]
    protected: bool  # inheritance from the parent is broken

    @property
    def sids(self) -> frozenset[str]:
        return frozenset(ace.sid for ace in self.aces)


# Reading ==============================================================================================================


def current_user_sid() -> str:
    """The SID of the account running this process; elevation does not change it."""
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                            capture_output=True,
                            text=True,
                            errors="replace",
                            check=True)
    sid = next(csv.reader(io.StringIO(result.stdout)))[1]
    _check_sid(sid)
    return sid


def read_acl(path: Path) -> Acl:
    """The allow entries that apply to `path` itself, inherited ones included. A missing DACL grants everyone."""
    import ctypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    void_p, dword = ctypes.c_void_p, ctypes.c_uint32
    advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, dword, dword, void_p, void_p,
        ctypes.POINTER(void_p), void_p,
        ctypes.POINTER(void_p)
    ]
    advapi32.GetNamedSecurityInfoW.restype = dword
    advapi32.GetSecurityDescriptorControl.argtypes = [void_p, ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(dword)]
    advapi32.GetSecurityDescriptorControl.restype = ctypes.c_int
    advapi32.GetAclInformation.argtypes = [void_p, void_p, dword, dword]
    advapi32.GetAclInformation.restype = ctypes.c_int
    advapi32.GetAce.argtypes = [void_p, dword, ctypes.POINTER(void_p)]
    advapi32.GetAce.restype = ctypes.c_int
    advapi32.ConvertSidToStringSidW.argtypes = [void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [void_p]
    kernel32.LocalFree.restype = void_p

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [("AceCount", dword), ("AclBytesInUse", dword), ("AclBytesFree", dword)]

    se_file_object, dacl_security_information, acl_size_information = 1, 4, 2
    dacl, descriptor = void_p(), void_p()
    status = advapi32.GetNamedSecurityInfoW(
        str(path), se_file_object, dacl_security_information, None, None, ctypes.byref(dacl), None,
        ctypes.byref(descriptor)
    )
    if status:
        raise ctypes.WinError(status)
    try:
        control, revision = ctypes.c_uint16(), dword()
        if not advapi32.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        protected = bool(control.value & SE_DACL_PROTECTED)
        if not dacl.value:
            return Acl((Ace(SID_EVERYONE, FILE_ALL_ACCESS, 0), ), protected)
        size = AclSizeInformation()
        if not advapi32.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), acl_size_information):
            raise ctypes.WinError(ctypes.get_last_error())
        aces = []
        for index in range(size.AceCount):
            entry = void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(entry)):
                raise ctypes.WinError(ctypes.get_last_error())
            address = entry.value
            assert address is not None
            ace_type = ctypes.c_ubyte.from_address(address).value
            flags = ctypes.c_ubyte.from_address(address + 1).value
            if ace_type in DENY_ACE_TYPES or flags & INHERIT_ONLY_ACE:
                continue
            if ace_type != ACCESS_ALLOWED_ACE_TYPE:
                raise OSError(f"{path}: unsupported ACE type {ace_type}; refusing to guess who it grants")
            mask = ctypes.c_uint32.from_address(address + 4).value
            text = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(void_p(address + 8), ctypes.byref(text)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = text.value
            kernel32.LocalFree(ctypes.cast(text, void_p))
            assert sid is not None
            aces.append(Ace(sid, mask, flags))
        return Acl(tuple(aces), protected)
    finally:
        kernel32.LocalFree(descriptor)


# Writing ==============================================================================================================


def _check_sid(sid: str) -> None:
    if not SID.fullmatch(sid):
        raise ValueError(f"not a SID: {sid!r}")


def _icacls(*arguments: str | Path) -> None:
    subprocess.run(["icacls", *map(str, arguments), "/Q"], capture_output=True, text=True, errors="replace", check=True)


def apply(
    path: Path,
    *,
    directory: bool,
    operator: str | None,
    readers: Collection[str],
    writers: Collection[str],
    isolate: bool,
) -> frozenset[str]:
    """Make the explicit ACEs of `path` exactly Administrators, `operator`, `writers` and `readers`.

    With `isolate`, inheritance from the parent is broken too, so the result is the whole ACL. Without it the parent's
    ACEs still apply and only the explicit ones are converged. Returns the SIDs granted explicitly.

    Files give `operator` read and write, and `readers` read. Directories give `operator` and `writers` modify and
    `readers` read and execute, all inheritable by files and subdirectories.
    """
    suffix = DIRECTORY_INHERIT if directory else ""
    wanted = {SID_ADMINISTRATORS: f"{suffix}(F)"}
    if operator is not None:
        wanted.setdefault(operator, f"{suffix}(M)" if directory else "(R,W)")
    for sid in sorted(writers):
        wanted.setdefault(sid, f"{suffix}(M)")
    for sid in sorted(readers):
        wanted.setdefault(sid, f"{suffix}(RX)" if directory else "(R)")
    for sid in wanted:
        _check_sid(sid)
    grants = [f"*{sid}:{rights}" for sid, rights in wanted.items()]
    _icacls(path, "/inheritance:r" if isolate else "/inheritance:e", "/grant:r", *grants)
    for ace in read_acl(path).aces:
        if not ace.flags & INHERITED_ACE and ace.sid not in wanted:
            _icacls(path, "/remove:g", f"*{ace.sid}")
    return frozenset(wanted)


def grant_traversal(path: Path, sid: str) -> None:
    """Add an inheritable read-and-execute ACE for `sid`, leaving every other ACE and inheritance alone."""
    _check_sid(sid)
    _icacls(path, "/grant:r", f"*{sid}:{DIRECTORY_INHERIT}(RX)")


def reset_to_inherited(path: Path) -> None:
    """Replace the ACL of `path` and everything under it with what the parent grants."""
    _icacls(path, "/reset", "/T", "/L")
