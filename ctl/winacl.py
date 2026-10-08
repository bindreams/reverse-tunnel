# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Windows ACLs: written through an open handle with `NtSetSecurityObject`, read back as SIDs.

`os.chmod` sets no ACL and account names are localised, so every grant names a well-known SID and every comparison is
between SID strings.

The Win32 `SetSecurityInfo` and `SetNamedSecurityInfo` propagate inheritable ACEs to every child of a directory
before the caller can vet what is there. `NtSetSecurityObject` sets exactly one object's descriptor and propagates
nothing, so this module computes the inherited ACEs itself (`inherited_for`) and `ctl.perms_windows` writes them to
each object it has already opened and vetted.

A handle comes from `ctl._winfile`, which has already refused a reparse point. Failures surface as `OSError`;
`ctl.perms` turns them into its own. pywin32 and the Win32 libraries exist only on Windows, so they are loaded inside
the functions.
"""

import ctypes
import dataclasses
from collections.abc import Collection, Iterable, Sequence
from typing import Any, NamedTuple

SID_EVERYONE = "S-1-1-0"
SID_AUTHENTICATED_USERS = "S-1-5-11"
SID_LOCAL_SERVICE = "S-1-5-19"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_USERS = "S-1-5-32-545"

# The access masks `icacls` means by F, M, RX, R and R,W.
FULL = 0x1F01FF
MODIFY = 0x1301BF
READ_EXECUTE = 0x1200A9
READ = 0x120089
READ_WRITE = 0x12019F

OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
NO_PROPAGATE_INHERIT_ACE = 0x4
INHERIT_ONLY_ACE = 0x8
INHERITED_ACE = 0x10
SE_DACL_PROTECTED = 0x1000
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
DACL_SECURITY_INFORMATION = 0x4
SDDL_REVISION_1 = 1
# SDDL ACE flag tokens, in the order SDDL writes them.
SDDL_FLAGS = ((OBJECT_INHERIT_ACE, "OI"), (CONTAINER_INHERIT_ACE, "CI"), (NO_PROPAGATE_INHERIT_ACE, "NP"),
              (INHERIT_ONLY_ACE, "IO"), (INHERITED_ACE, "ID"))


class Entry(NamedTuple):
    """One ACE of either type: header type, header flags, access mask, SID string."""
    ace_type: int
    flags: int
    mask: int
    sid: str


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


# Inheritance ==========================================================================================================


def inherited_for(parent: Iterable[Entry], *, directory: bool) -> list[Entry]:
    """The ACEs a new child of `parent` inherits, as NTFS computes them.

    A file takes every object-inheritable ACE. A directory takes a container-inheritable one as it stands (still
    inheritable unless it is no-propagate), and an object-only one as an inherit-only ACE for its own files. Every
    result carries INHERITED_ACE. `parent` holds all of the parent's ACEs, its own inherited ones included.
    """
    result = []
    for ace in parent:
        flags = ace.flags
        if not directory:
            if flags & OBJECT_INHERIT_ACE:
                result.append(ace._replace(flags=INHERITED_ACE))
        elif flags & CONTAINER_INHERIT_ACE:
            propagate = 0 if flags & NO_PROPAGATE_INHERIT_ACE else flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            result.append(ace._replace(flags=INHERITED_ACE | propagate))
        elif flags & OBJECT_INHERIT_ACE and not flags & NO_PROPAGATE_INHERIT_ACE:
            result.append(ace._replace(flags=INHERITED_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE))
    return result


def explicit(entries: Iterable[Entry]) -> list[Entry]:
    return [ace for ace in entries if not ace.flags & INHERITED_ACE]


def canonical(entries: Iterable[Entry]) -> list[Entry]:
    """Explicit denies, explicit allows, inherited denies, inherited allows: the order Windows expects."""
    return sorted(entries, key=lambda ace: (bool(ace.flags & INHERITED_ACE), ace.ace_type == ACCESS_ALLOWED_ACE_TYPE))


def to_sddl(entries: Iterable[Entry], *, protected: bool) -> str:
    """The DACL as an SDDL string, which Windows turns into a self-relative descriptor."""
    parts = ["D:", "P" if protected else "", "AI"]
    for ace in canonical(entries):
        flags = "".join(token for bit, token in SDDL_FLAGS if ace.flags & bit)
        kind = "A" if ace.ace_type == ACCESS_ALLOWED_ACE_TYPE else "D"
        parts.append(f"({kind};{flags};{ace.mask:#x};;;{ace.sid})")
    return "".join(parts)


# Reading ==============================================================================================================


def owner_sid(handle: int) -> str:
    """The SID that owns the object behind `handle`, which needs READ_CONTROL."""
    import win32security

    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION
    )
    return win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())


def read_entries(handle: int) -> tuple[list[Entry], bool]:
    """Every ACE of the object behind `handle` (READ_CONTROL) and whether its inheritance is broken."""
    import win32security

    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    return _parse(descriptor, "<handle>")


def _parse(descriptor, source) -> tuple[list[Entry], bool]:
    import win32security

    control, _ = descriptor.GetSecurityDescriptorControl()
    protected = bool(control & SE_DACL_PROTECTED)
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:  # a missing DACL grants everyone everything
        return [Entry(ACCESS_ALLOWED_ACE_TYPE, 0, FULL, SID_EVERYONE)], protected
    entries = [
        Entry(ace_type, flags, mask, win32security.ConvertSidToStringSid(sid))
        for ace_type, flags, mask, sid in _entries(dacl, source)
    ]
    return entries, protected


def _acl(entries: Sequence[Entry], protected: bool) -> Acl:
    aces = (Ace(e.sid, e.mask, e.flags) for e in entries if e.ace_type == ACCESS_ALLOWED_ACE_TYPE)
    return Acl(tuple(ace for ace in aces if not ace.flags & INHERIT_ONLY_ACE), protected)


def read_acl(path) -> Acl:
    """The allow entries that apply to `path` itself, inherited ones included. A missing DACL grants everyone."""
    import win32security

    descriptor = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    return _acl(*_parse(descriptor, path))


def read_acl_handle(handle: int) -> Acl:
    """`read_acl` for the object behind `handle` (READ_CONTROL), so what is read is what was changed."""
    return _acl(*read_entries(handle))


def _entries(dacl, source) -> list[tuple[int, int, int, Any]]:
    """Every ACE of `dacl` as (type, flags, mask, sid). An unknown type is an error: it may grant something unseen."""
    entries = []
    for index in range(dacl.GetAceCount()):
        ace = dacl.GetAce(index)
        ace_type = ace[0][0]
        # Object and callback ACEs unpack differently and can grant in ways this module does not model.
        if ace_type not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE):
            raise OSError(f"{source}: unsupported ACE type {ace_type}; refusing to guess who it grants")
        (ace_type, flags), mask, sid = ace
        entries.append((ace_type, flags, mask, sid))
    return entries


# Writing ==============================================================================================================


def set_dacl(handle: int, entries: Iterable[Entry], *, protected: bool) -> None:
    """Replace the DACL of the object behind `handle` (WRITE_DAC) with `entries`, touching nothing else.

    `NtSetSecurityObject` sets one object and propagates to no child. The protected flag travels in the descriptor's
    control bits (SDDL `P`), and the caller verifies it by reading it back.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    void_p, dword = ctypes.c_void_p, ctypes.c_uint32
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, dword, ctypes.POINTER(void_p),
        ctypes.POINTER(dword)
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [void_p]
    kernel32.LocalFree.restype = void_p
    ntdll.NtSetSecurityObject.argtypes = [void_p, dword, void_p]
    ntdll.NtSetSecurityObject.restype = ctypes.c_int32
    ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
    ntdll.RtlNtStatusToDosError.restype = dword

    descriptor, size = void_p(), dword()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        to_sddl(entries, protected=protected), SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        status = ntdll.NtSetSecurityObject(handle, DACL_SECURITY_INFORMATION, descriptor)
    finally:
        kernel32.LocalFree(descriptor)
    if status < 0:
        raise ctypes.WinError(ntdll.RtlNtStatusToDosError(status))


def grants(
    *,
    directory: bool,
    operator: str | None,
    readers: Collection[str],
    writers: Collection[str],
) -> dict[str, int]:
    """The explicit grants: Administrators full, then `operator`, `writers` and `readers`, strongest first.

    Files give `operator` read and write, and `readers` read. Directories give `operator` and `writers` modify and
    `readers` read and execute.
    """
    wanted = {SID_ADMINISTRATORS: FULL}
    if operator is not None:
        wanted.setdefault(operator, MODIFY if directory else READ_WRITE)
    for sid in sorted(writers):
        wanted.setdefault(sid, MODIFY)
    for sid in sorted(readers):
        wanted.setdefault(sid, READ_EXECUTE if directory else READ)
    return wanted


def apply(
    handle: int,
    *,
    directory: bool,
    operator: str | None,
    readers: Collection[str],
    writers: Collection[str],
    isolate: bool,
    parent: Iterable[Entry] = (),
) -> frozenset[str]:
    """Make the explicit ACEs of the object exactly the `grants`, inheritable by children if it is a directory.

    With `isolate`, inheritance from the parent is broken, so the result is the whole ACL. Without it the ACEs
    `parent` (all of the parent's ACEs) passes down are included as inherited. Returns the SIDs granted explicitly.
    `handle` needs WRITE_DAC.
    """
    wanted = grants(directory=directory, operator=operator, readers=readers, writers=writers)
    inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE if directory else 0
    entries = [Entry(ACCESS_ALLOWED_ACE_TYPE, inherit, mask, sid) for sid, mask in wanted.items()]
    if not isolate:
        entries += inherited_for(parent, directory=directory)
    set_dacl(handle, entries, protected=isolate)
    return frozenset(wanted)
