# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Windows ACLs through pywin32: written through an open handle, read back as SIDs.

`os.chmod` sets no ACL and account names are localised, so every grant names a well-known SID and every comparison is
between SID strings. A handle comes from `ctl._winfile.open_handle`, which has already refused a reparse point, so what
is written to is what was checked. Failures surface as `OSError`; `ctl.perms` turns them into its own.

pywin32 exists only on Windows, so it is imported inside the functions.
"""

import dataclasses
from collections.abc import Collection
from typing import Any

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
INHERIT_ONLY_ACE = 0x8
INHERITED_ACE = 0x10
SE_DACL_PROTECTED = 0x1000
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1


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


def owner_sid(handle: int) -> str:
    """The SID that owns the object behind `handle`, which needs READ_CONTROL."""
    import win32security

    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION
    )
    return win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())


def read_acl(path) -> Acl:
    """The allow entries that apply to `path` itself, inherited ones included. A missing DACL grants everyone."""
    import win32security

    return _parse(
        win32security.GetNamedSecurityInfo(
            str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
        ), path
    )


def read_acl_handle(handle: int) -> Acl:
    """`read_acl` for the object behind `handle` (READ_CONTROL), so what is read is what was changed."""
    import win32security

    return _parse(
        win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION),
        "<handle>"
    )


def _parse(descriptor, source) -> Acl:
    import win32security

    control, _ = descriptor.GetSecurityDescriptorControl()
    protected = bool(control & SE_DACL_PROTECTED)
    dacl = descriptor.GetSecurityDescriptorDacl()
    if dacl is None:
        return Acl((Ace(SID_EVERYONE, FULL, 0), ), protected)
    aces = []
    for ace_type, flags, mask, sid in _entries(dacl, source):
        if ace_type == ACCESS_ALLOWED_ACE_TYPE and not flags & INHERIT_ONLY_ACE:
            aces.append(Ace(win32security.ConvertSidToStringSid(sid), mask, flags))
    return Acl(tuple(aces), protected)


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


def _build(entries):
    """An ACL holding `entries` in canonical order: explicit denies, explicit allows, inherited denies, allows."""
    import win32security

    dacl = win32security.ACL()
    for ace_type, flags, mask, sid in sorted(entries, key=lambda e: (bool(e[1] & INHERITED_ACE), e[0] == 0)):
        if ace_type == ACCESS_ALLOWED_ACE_TYPE:
            dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, flags, mask, sid)
        else:
            dacl.AddAccessDeniedAceEx(win32security.ACL_REVISION, flags, mask, sid)
    return dacl


def _current(handle):
    """The DACL of `handle` and whether its inheritance is broken."""
    import win32security

    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    control, _ = descriptor.GetSecurityDescriptorControl()
    return descriptor.GetSecurityDescriptorDacl(), bool(control & SE_DACL_PROTECTED)


def _set(handle, entries, *, protected: bool) -> None:
    import win32security

    information = win32security.DACL_SECURITY_INFORMATION | (
        win32security.PROTECTED_DACL_SECURITY_INFORMATION
        if protected else win32security.UNPROTECTED_DACL_SECURITY_INFORMATION
    )
    # pywin32 takes None for the parts it should leave alone; its stubs do not say so.
    win32security.SetSecurityInfo(
        handle,
        win32security.SE_FILE_OBJECT,
        information,
        None,  # ty: ignore[invalid-argument-type]
        None,  # ty: ignore[invalid-argument-type]
        _build(entries),
        None,  # ty: ignore[invalid-argument-type]
    )


def apply(
    handle: int,
    *,
    directory: bool,
    operator: str | None,
    readers: Collection[str],
    writers: Collection[str],
    isolate: bool,
) -> frozenset[str]:
    """Make the explicit ACEs of the object exactly Administrators, `operator`, `writers` and `readers`.

    With `isolate`, inheritance from the parent is broken too, so the result is the whole ACL. Without it the parent's
    ACEs still apply. Returns the SIDs granted explicitly.

    Files give `operator` read and write, and `readers` read. Directories give `operator` and `writers` modify and
    `readers` read and execute, all inheritable by files and subdirectories. `handle` needs READ_CONTROL and WRITE_DAC.
    """
    import win32security

    wanted = {SID_ADMINISTRATORS: FULL}
    if operator is not None:
        wanted.setdefault(operator, MODIFY if directory else READ_WRITE)
    for sid in sorted(writers):
        wanted.setdefault(sid, MODIFY)
    for sid in sorted(readers):
        wanted.setdefault(sid, READ_EXECUTE if directory else READ)
    inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE if directory else 0
    entries = [(ACCESS_ALLOWED_ACE_TYPE, inherit, mask, win32security.ConvertStringSidToSid(sid))
               for sid, mask in wanted.items()]
    if not isolate:
        dacl, _ = _current(handle)
        if dacl is not None:
            entries += [entry for entry in _entries(dacl, "<handle>") if entry[1] & INHERITED_ACE]
    _set(handle, entries, protected=isolate)
    return frozenset(wanted)


def grant_read(handle: int, sid: str) -> None:
    """Add an inheritable read-and-execute ACE for `sid`, leaving every other ACE and the inheritance state alone."""
    import win32security

    dacl, protected = _current(handle)
    target = win32security.ConvertStringSidToSid(sid)
    kept = [] if dacl is None else [
        entry for entry in _entries(dacl, "<handle>")
        if entry[1] & INHERITED_ACE or entry[0] != ACCESS_ALLOWED_ACE_TYPE or entry[3] != target
    ]
    kept.append((ACCESS_ALLOWED_ACE_TYPE, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, READ_EXECUTE, target))
    _set(handle, kept, protected=protected)


def reset_to_inherited(handle: int) -> None:
    """Drop every explicit ACE and re-enable inheritance, so the object holds what its parent grants."""
    _set(handle, [], protected=False)
