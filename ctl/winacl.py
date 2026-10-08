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
SID_CREATOR_OWNER = "S-1-3-0"
SID_CREATOR_GROUP = "S-1-3-1"
# CREATOR OWNER SERVER and CREATOR GROUP SERVER have server-side semantics this module does not model.
SERVER_CREATOR_SIDS = frozenset({"S-1-3-2", "S-1-3-3"})

# The access masks `icacls` means by F, M, RX, R and R,W.
FULL = 0x1F01FF
MODIFY = 0x1301BF
READ_EXECUTE = 0x1200A9
READ = 0x120089
READ_WRITE = 0x12019F

# Generic rights and what they mean for a file.
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
GENERIC_RIGHTS = ((GENERIC_READ, 0x120089), (GENERIC_WRITE, 0x120116), (GENERIC_EXECUTE, 0x1200A0), (GENERIC_ALL, FULL))
GENERIC_MASK = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL

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


class UnsupportedInheritance(OSError):
    """An inheritable ACE whose inherited form this module cannot compute faithfully."""


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


def _effective(ace: Entry, owner: str | None, group: str | None) -> Entry:
    """`ace` as it applies to a child: the creator SIDs become the child's owner and group, generic rights are mapped."""
    sid, mask = ace.sid, ace.mask
    if sid in (SID_CREATOR_OWNER, SID_CREATOR_GROUP):
        principal = owner if sid == SID_CREATOR_OWNER else group
        if principal is None:
            raise ValueError(f"{sid} is inherited, so the child's owner and primary group are needed")
        sid = principal
    if mask & GENERIC_MASK:
        mapped = 0
        for generic, specific in GENERIC_RIGHTS:
            if mask & generic:
                mapped |= specific
        mask = mask & ~GENERIC_MASK | mapped
    return ace._replace(sid=sid, mask=mask, flags=INHERITED_ACE)


def inherited_for(
    parent: Iterable[Entry],
    *,
    directory: bool,
    owner: str | None = None,
    group: str | None = None,
    parent_label: str = "<parent>",
) -> list[Entry]:
    """The ACEs a new child of `parent` inherits, as NTFS computes them. `owner` and `group` are the child's.

    A file takes every object-inheritable ACE. A directory takes a container-inheritable one, and an object-only one
    as an inherit-only ACE for its own files. Every result carries INHERITED_ACE. The effective ACE for the child maps
    CREATOR OWNER and CREATOR GROUP to `owner` and `group` and generic rights to file rights. A directory that passes
    such an ACE on keeps the original, unmapped, as a second inherit-only ACE. OWNER RIGHTS is passed on as any other
    SID. The result follows the order of `parent`, which holds all of the parent's ACEs, its own inherited ones
    included, as they are on disk. An inheritable CREATOR OWNER SERVER or CREATOR GROUP SERVER ACE raises
    `UnsupportedInheritance` naming `parent_label`.
    """
    result = []
    for ace in parent:
        flags = ace.flags
        if flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) and ace.sid in SERVER_CREATOR_SIDS:
            raise UnsupportedInheritance(
                f"{parent_label}: grants {ace.sid}, which is inherited with server semantics this tool does not "
                "model; remove that ACE"
            )
        if not directory:
            if flags & OBJECT_INHERIT_ACE:
                result.append(_effective(ace, owner, group))
        elif flags & CONTAINER_INHERIT_ACE:
            propagate = 0 if flags & NO_PROPAGATE_INHERIT_ACE else flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            effective = _effective(ace, owner, group)
            if propagate and (ace.sid in (SID_CREATOR_OWNER, SID_CREATOR_GROUP) or ace.mask & GENERIC_MASK):
                result.append(effective)
                result.append(ace._replace(flags=INHERITED_ACE | INHERIT_ONLY_ACE | propagate))
            else:
                result.append(effective._replace(flags=INHERITED_ACE | propagate))
        elif flags & OBJECT_INHERIT_ACE and not flags & NO_PROPAGATE_INHERIT_ACE:
            result.append(ace._replace(flags=INHERITED_ACE | OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE))
    return result


def explicit(entries: Iterable[Entry]) -> list[Entry]:
    return [ace for ace in entries if not ace.flags & INHERITED_ACE]


def canonical(entries: Iterable[Entry]) -> list[Entry]:
    """The order a DACL is stored in: explicit denies, explicit allows, then inherited ACEs in the order given.

    NTFS keeps inherited ACEs in inheritance order, which follows the parent's, so they are never re-sorted.
    """
    entries = list(entries)
    own = sorted((e for e in entries if not e.flags & INHERITED_ACE),
                 key=lambda e: e.ace_type == ACCESS_ALLOWED_ACE_TYPE)
    return own + [e for e in entries if e.flags & INHERITED_ACE]


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


def owner_and_group(handle: int) -> tuple[str, str]:
    """The owner and primary group SIDs of the object behind `handle` (READ_CONTROL)."""
    import win32security

    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.GROUP_SECURITY_INFORMATION
    )
    # pywin32 has GetSecurityDescriptorGroup; its stubs omit it.
    group = descriptor.GetSecurityDescriptorGroup()  # ty: ignore[unresolved-attribute]
    return (
        win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()),
        win32security.ConvertSidToStringSid(group),
    )


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
    parent_label: str = "<parent>",
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
        owner, group = owner_and_group(handle)
        entries += inherited_for(parent, directory=directory, owner=owner, group=group, parent_label=parent_label)
    set_dacl(handle, entries, protected=isolate)
    return frozenset(wanted)
