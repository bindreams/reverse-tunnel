# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The Windows half of `ctl.perms`.

Each path is opened once with `FILE_FLAG_OPEN_REPARSE_POINT`, which refuses a reparse point before anything is
changed, and its ACL is then set and read back through that handle, so the object that was checked is the object that
is changed. A directory whose entries are changed too, or that gains an inheritable ACE, is held open without
`FILE_SHARE_DELETE`; its entries are listed through that handle and opened relative to it, and every entry is vetted
before the first ACL is written.

ACLs are written with `NtSetSecurityObject`, which propagates to no child; the inherited ACEs of each object are
computed here (`winacl.inherited_for`) and written to that object through its own handle. The Win32 `SetSecurityInfo`
would instead walk the whole subtree before any of it could be vetted. Windows Server 2025 does not stop there: a new
inheritable ACE on a directory makes NTFS turn the inherited ACEs of its direct children into explicit, protected ones.
The repository root holds files `ctl` never opens, so the service's ACEs on it and on `bin` are never inheritable. The
one on `host` is inherited by the files created in it: `ctl` opens and vets every entry of `host`, and git recreates
`frpc.toml` there. An interruption between that write and `ctl` rewriting the entries leaves them protected. A file
that is protected is not refused and not unprotected (NTFS's doing cannot be told from the operator's): it stays so and
gets its own explicit ACE for the service.

The owner field of an object is deliberately left as created (Administrators when the process is elevated). Ownership
is expressed by the ACL alone, with explicit grants for the principals that matter; `operator_sid` names the one that
stands for the repository's owner.
"""

import dataclasses
import os
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from ctl import _winfile as winfile
from ctl import authz, winacl
from ctl.atomic import deferred_interrupts
from ctl.perms import (
    SID_LOCAL_SERVICE,
    Account,
    PermsError,
    check_destination,
    temporary_name,
    unlink_quietly,
    write_all,
)

ACL_ACCESS = winfile.READ_CONTROL | winfile.WRITE_DAC
LOCAL_SERVICE = "localservice"
# Groups in the token of a process LocalService runs as a service (measured on a Windows Server 2025 runner, with a task
# that runs as LocalService) that `authz.token` does not derive from the SID: LOCAL and CONSOLE LOGON. goetia gives its
# services no per-service SID (SERVICE_SID_TYPE_NONE), so there is none to add.
SERVICE_TOKEN_GROUPS = (winacl.SID_LOCAL, winacl.SID_CONSOLE_LOGON)
FLAT = "; remove it, this directory holds regular files only"
RETRY = "remove it, or close the process holding it, then rerun"


def _listed(names: list[str], wanted: tuple[str, ...], where: Path) -> dict[str, str]:
    """For each of `wanted` present in `names` (compared case-insensitively), the name as the directory lists it.

    A case-sensitive directory may hold `bin` and `Bin` at once; which one is meant cannot be told, so it is refused.
    """
    found: dict[str, str] = {}
    for name in wanted:
        spellings = [listed for listed in names if listed.casefold() == name.casefold()]
        if len(spellings) > 1:
            raise PermsError(f"{where}: holds {' and '.join(sorted(spellings))}; ambiguous, remove all but one")
        if spellings:
            found[name] = spellings[0]
    return found


def _unopenable(label: Path, exc: OSError) -> PermsError:
    return PermsError(f"{label}: listed but cannot be opened: {exc.strerror or exc}; {RETRY}")


@contextmanager
def _errors(path: Path) -> Generator[None]:
    """Report an OS failure as a `PermsError` naming `path`."""
    try:
        yield
    except OSError as exc:
        raise PermsError(f"{path}: {exc.strerror or exc}") from exc


@contextmanager
def _handle(
    path: Path,
    *,
    directory: bool,
    create: bool = False,
    single_link: bool = False,
    access: int = ACL_ACCESS,
    share: int = winfile.FILE_SHARE_ALL,
) -> Generator[int]:
    """A vetted handle to `path`, creating the directory first if `create`."""

    def open_it() -> int:
        return winfile.open_handle(
            path,
            access=access,
            disposition=winfile.OPEN_EXISTING,
            directory=directory,
            error=PermsError,
            single_link=single_link,
            share=share
        )

    try:
        handle = open_it()
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(path)
        handle = open_it()
    try:
        yield handle
    finally:
        winfile.close_handle(handle)


def _verify(handle: int, path: Path, wanted: frozenset[str], *, isolate: bool) -> None:
    """Fail loudly if the ACL is not what was meant: the whole ACL when isolated, at least the grants otherwise."""
    acl = winacl.read_acl_handle(handle)
    if acl.protected != isolate:
        found, expected = ("broken", "enabled") if acl.protected else ("enabled", "broken")
        raise PermsError(f"{path}: inheritance is {found}, expected {expected}")
    if isolate and acl.sids != wanted:
        raise PermsError(f"{path}: the ACL grants {sorted(acl.sids)}, expected {sorted(wanted)}")
    if not wanted <= acl.sids:
        raise PermsError(f"{path}: the ACL lacks {sorted(wanted - acl.sids)}")


def _parent_entries(directory: Path) -> list[winacl.Entry]:
    """Every ACE of `directory`, which its children inherit from."""
    with _handle(directory, directory=True, access=winfile.READ_CONTROL) as handle:
        return winacl.read_entries(handle)[0]


def operator_sid(root: Path) -> str:
    """The SID that owns the repository root: the operator, as `account_mode` takes `st_uid` on POSIX."""
    with _errors(root):
        handle = winfile.open_handle(
            root, access=winfile.READ_CONTROL, disposition=winfile.OPEN_EXISTING, directory=True, error=PermsError
        )
        try:
            return winacl.owner_sid(handle)
        finally:
            winfile.close_handle(handle)


def _operator(owner: Account | None, root: Path) -> str | None:
    """`owner=None` leaves the path the operator's, so the repository owner's SID is granted explicitly."""
    return operator_sid(root) if owner is None else None


def _sid_of(account: Account) -> str:
    if account.name.casefold() == LOCAL_SERVICE:
        return SID_LOCAL_SERVICE
    raise ValueError(f"no well-known SID for account {account.name!r}")


# Files ================================================================================================================


def harden_file(path: Path, owner: Account | None, readers: frozenset[str], root: Path) -> None:
    operator = _operator(owner, root)
    with _errors(path), _handle(path, directory=False, single_link=True) as handle:
        wanted = winacl.apply(
            handle, directory=False, operator=operator, readers=readers, writers=frozenset(), isolate=True
        )
        _verify(handle, path, wanted, isolate=True)


def _create_temporary(path: Path, owner: Account | None, readers: frozenset[str], root: Path) -> tuple[Path, int]:
    """Create a uniquely named file beside `path`, give it its ACL, and return it as a write-only descriptor."""
    import msvcrt

    operator = _operator(owner, root)
    while True:
        temporary = path.parent / temporary_name(path)
        try:
            handle = winfile.open_handle(
                temporary,
                access=winfile.GENERIC_WRITE | ACL_ACCESS,
                disposition=winfile.CREATE_NEW,
                directory=False,
                error=PermsError,
            )
        except FileExistsError:
            continue
        break
    try:
        wanted = winacl.apply(
            handle, directory=False, operator=operator, readers=readers, writers=frozenset(), isolate=True
        )
        _verify(handle, temporary, wanted, isolate=True)
        return temporary, msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
    except BaseException:
        winfile.close_handle(handle)
        unlink_quietly(str(temporary))
        raise


def write_secret(path: Path, data: bytes, owner: Account | None, readers: frozenset[str], root: Path) -> None:
    """Atomic, like POSIX: the ACL is set and checked on the temporary file before any byte is written."""
    with _errors(path):
        try:
            status = os.lstat(path)
        except FileNotFoundError:
            status = None
    check_destination(path, status)
    with _errors(path):
        temporary, fd = _create_temporary(path, owner, readers, root)
    try:
        try:
            write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        with _errors(path):
            os.replace(temporary, path)
    except BaseException:
        unlink_quietly(str(temporary))
        raise


# Directories ==========================================================================================================


def converge_dir(
    path: Path,
    owner: Account | None,
    readers: frozenset[str],
    writers: frozenset[str],
    isolate: bool,
    root: Path,
    service_read: Account | None = None
) -> None:
    """Converge the ACL of `path`, having opened and vetted every entry in it first.

    Windows Server 2025 makes NTFS rewrite the ACL of each direct child of a directory that gains an inheritable ACE,
    so `path` is held without `FILE_SHARE_DELETE`, each entry is opened relative to it (a subdirectory, a reparse point
    or a hard-linked file is refused before anything is written), and each is then written back through its own handle:
    an entry that inherits keeps its own ACEs and holds what it inherits from the new ACL, one whose inheritance is
    broken is left exactly as it was.

    With `service_read`, the DACL written to the directory and to each entry that inherits also holds that account's
    ACE for the object itself (not inheritable), so what the service must read is never without it, not even between
    two writes, and not when it held the access only by inheriting it. An entry whose inheritance is broken (NTFS does
    that to the children of a directory that just gained an inheritable ACE) stays so, and has that ACE added.
    Windows' own access check then judges, before the first write and after the last, that the service is granted
    read-and-execute under every DACL written: the sort of explicit denies before allows can turn an order that
    granted it into one that does not.
    """
    operator = _operator(owner, root)
    service_sid = None if service_read is None else _sid_of(service_read)
    service = [] if service_sid is None else _service_read([], service_sid)
    with _errors(path), ExitStack() as stack:
        token = None if service_sid is None else stack.enter_context(_service_token(service_sid))
        parent = [] if isolate else _parent_entries(path.parent)
        winacl.refuse_unsupported(parent, str(path.parent))  # before the directory is created
        held = stack.enter_context(
            _handle(
                path,
                directory=True,
                create=True,
                access=ACL_ACCESS | winfile.FILE_LIST_DIRECTORY,
                share=winfile.FILE_SHARE_READ_WRITE
            )
        )
        children = _open_entries(stack, held, path)
        owner_sid, group_sid = winacl.owner_and_group(held)
        planned, wanted = winacl.plan(
            directory=True,
            operator=operator,
            readers=readers,
            writers=writers,
            isolate=isolate,
            parent=parent,
            owner=owner_sid,
            group=group_sid,
            parent_label=str(path.parent),
            extra=service
        )
        # Everything that can be refused is computed before the first write.
        if token is not None:
            _require_planned(token, path, planned, isolate, owner_sid, group_sid)
        writes = []
        for handle, label in children:
            entries, protected = winacl.read_entries(handle)
            child_owner, child_group = winacl.owner_and_group(handle)
            if protected:  # left as it is, except that the service's ACE is on it: NTFS may have just protected it
                if service_sid is not None:
                    entries = _service_read(entries, service_sid)
            else:
                own = winacl.explicit(entries)
                if service_sid is not None:  # a file that held the service's access only by inheriting it keeps it
                    own = _service_read(own, service_sid)
                entries = winacl.canonical(
                    own + winacl.inherited_for(
                        planned, directory=False, owner=child_owner, group=child_group, parent_label=str(path)
                    )
                )
            if token is not None:
                _require_planned(token, label, entries, protected, child_owner, child_group)
            writes.append((handle, label, entries, protected))
        with deferred_interrupts():  # Ctrl-C waits for the last write
            winacl.set_dacl(held, planned, protected=isolate)
            _verify(held, path, wanted | {e.sid for e in service}, isolate=isolate)
            for handle, label, entries, protected in writes:
                if winacl.read_entries(handle) != (entries, protected):  # NTFS may already have written it so
                    winacl.set_dacl(handle, entries, protected=protected)
                if winacl.read_acl_handle(handle).protected != protected:
                    raise PermsError(f"{label}: inheritance is {'enabled' if protected else 'broken'} after the write")
            if token is not None:
                for handle, label in [(held, path), *children]:
                    _require_on_disk(token, handle, label)


def _open_entries(stack: ExitStack, directory: int, where: Path) -> list[tuple[int, Path]]:
    """Open every entry of the held directory relative to it, refusing anything but a single-link regular file.

    Handles are registered on `stack`, so a refusal part-way closes the ones already opened.
    """
    entries = []
    for name in winfile.list_names(directory):
        label = where / name
        try:
            handle = winfile.open_relative(
                directory, name, label=label, access=ACL_ACCESS, directory=False, single_link=True, error=PermsError
            )
        except PermsError as exc:
            raise PermsError(f"{exc}{FLAT}") from exc
        except OSError as exc:  # a name just listed that cannot be opened is not skipped: fail closed
            raise _unopenable(label, exc) from exc
        stack.callback(winfile.close_handle, handle)
        entries.append((handle, label))
    return entries


def converge_tree(path: Path, owner: Account | None, root: Path) -> None:
    """Converge `path` itself, then give each direct entry what it inherits; the service gets modify on all of it.

    `path` is held without `FILE_SHARE_DELETE`, its entries are listed through that handle and opened relative to it,
    and all of them are vetted before the first ACL is written. Each entry's ACL is then exactly what it inherits from
    the new ACL of `path`, written to its own handle.
    """
    writers = frozenset() if owner is None else frozenset({_sid_of(owner)})
    operator = _operator(owner, root)
    with _errors(path), ExitStack() as stack:
        parent = _parent_entries(path.parent)
        winacl.refuse_unsupported(parent, str(path.parent))  # before the directory is created
        held = stack.enter_context(
            _handle(
                path,
                directory=True,
                create=True,
                access=ACL_ACCESS | winfile.FILE_LIST_DIRECTORY,
                share=winfile.FILE_SHARE_READ_WRITE
            )
        )
        entries = _open_entries(stack, held, path)
        # Everything that can be refused is computed before the first write.
        owner_sid, group_sid = winacl.owner_and_group(held)
        planned, wanted = winacl.plan(
            directory=True,
            operator=operator,
            readers=frozenset(),
            writers=writers,
            isolate=False,
            parent=parent,
            owner=owner_sid,
            group=group_sid,
            parent_label=str(path.parent)
        )
        writes = []
        for handle, label in entries:
            entry_owner, entry_group = winacl.owner_and_group(handle)
            writes.append((
                handle, label,
                winacl.inherited_for(
                    planned, directory=False, owner=entry_owner, group=entry_group, parent_label=str(path)
                )
            ))
        with deferred_interrupts():  # Ctrl-C waits for the last write
            winacl.set_dacl(held, planned, protected=False)
            _verify(held, path, wanted, isolate=False)
            for handle, label, inherited in writes:
                winacl.set_dacl(handle, inherited, protected=False)
                if winacl.read_acl_handle(handle).protected:
                    raise PermsError(f"{label}: inheritance is still broken after the reset")


@dataclasses.dataclass
class _Target:
    handle: int
    label: Path
    directory: bool
    entries: list[winacl.Entry]
    parent: "_Target | None" = None
    inherited_read: bool = False  # for a directory: its files hold the service's read by inheriting it
    protected: bool = False  # inheritance is broken: NTFS does it to a file whose directory gains an inheritable ACE


def _without_service_read(entries: list[winacl.Entry], sid: str) -> list[winacl.Entry]:
    """`entries` less the explicit allows for the service."""
    return [
        e for e in entries
        if e.flags & winacl.INHERITED_ACE or e.sid != sid or e.ace_type != winacl.ACCESS_ALLOWED_ACE_TYPE
    ]


def _service_read(entries: list[winacl.Entry], sid: str, *, files: bool = False) -> list[winacl.Entry]:
    """`entries` with the service's read-and-execute ACE, which applies to the object alone and is never inherited.

    `files` adds a second ACE that the files created in the directory inherit and the directory itself does not apply:
    `OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE`. A subdirectory would get it as an inherit-only copy for its own files;
    `ctl` refuses subdirectories in `host`, so there is none.

    Only an earlier explicit allow for the service is replaced (including the inheritable one an older install wrote on
    the root); a deny for it, or an inherited ACE, stays.
    """
    kept = _without_service_read(entries, sid)
    granted = [winacl.Entry(winacl.ACCESS_ALLOWED_ACE_TYPE, 0, winacl.READ_EXECUTE, sid)]
    if files:
        flags = winacl.OBJECT_INHERIT_ACE | winacl.INHERIT_ONLY_ACE
        granted.append(winacl.Entry(winacl.ACCESS_ALLOWED_ACE_TYPE, flags, winacl.READ_EXECUTE, sid))
    return winacl.canonical(kept + granted)


@contextmanager
def _service_token(sid: str) -> Generator[authz.Token]:
    """The access-check context of the service: its SID with every group a service's token holds."""
    with authz.token(sid, SERVICE_TOKEN_GROUPS) as token:
        yield token


def _require_service_read(token: authz.Token, label: Path, descriptor: bytes) -> None:
    """Fail unless Windows' own access check grants the service read-and-execute under `descriptor`.

    A deny for the service or for any group its token holds is the usual cause, whichever ACE order the DACL has.
    """
    if not token.grants(descriptor, winacl.READ_EXECUTE):
        raise PermsError(
            f"{label}: the service is denied read-and-execute (an ACE denying it or a group it is in, explicit or "
            "inherited, or a DACL that does not grant it); remove that ACE, then rerun"
        )


def _require_planned(
    token: authz.Token, label: Path, entries: list[winacl.Entry], protected: bool, owner: str, group: str
) -> None:
    """`_require_service_read` for the DACL `entries` that is about to be written to an object of this owner and group,
    in the order that `winacl.set_dacl` writes them."""
    _require_service_read(token, label, authz.descriptor_for(entries, protected=protected, owner=owner, group=group))


def _require_on_disk(token: authz.Token, handle: int, label: Path) -> None:
    """`_require_service_read` for the DACL the object behind `handle` holds now."""
    _require_service_read(token, label, authz.descriptor_of(handle))


def _explicit_service_read(target: _Target, sid: str) -> list[winacl.Entry]:
    """The explicit ACEs `target` is left with. A file whose directory is inherited from holds no ACE of its own for
    the service: the one it inherits is what a file git creates there holds too."""
    entries = winacl.explicit(target.entries)
    if target.directory:
        return _service_read(entries, sid, files=target.inherited_read)
    assert target.parent is not None
    return (_without_service_read if target.parent.inherited_read else _service_read)(entries, sid)


def grant_service_read(root: Path, account: Account) -> None:
    """Give the service read-and-execute on exactly the objects it needs, each through its own vetted handle.

    The set is known: `root`, `bin` and its direct files, `host` and its direct files. `root` and `bin` and `host` are
    held without `FILE_SHARE_DELETE`; their files are opened relative to them. Everything is vetted (a subdirectory, a
    reparse point, a hard-linked file, or an object whose inheritance is broken is refused) before the first ACL is
    written. The root is written last, after `bin` and `host` and their files: each of those then holds its own access
    when the root stops granting it, and nothing else is touched by the root losing an inheritable ACE.

    `root` and `bin` get an ACE for themselves and each file in `bin` one of its own; nothing is inherited, so a file
    created or replaced in `bin` has no access until `ctl` gives it: `atomic.replace_file(service=)` before the rename.
    `bin` is written only by `ctl`. `host` is written by git as well: a `git pull` deletes
    and recreates `frpc.toml`, and a file with no ACE for the service would leave the tunnel down after the next
    restart. So `host` also gets an ACE that its files inherit, and its files hold the service's access only by
    inheriting it. That is safe where an inheritable ACE on the root is not because every entry of `host` has been
    opened and vetted here, so the rewrite NTFS makes of a directory's children touches nothing else.

    A file or directory in `root` that is `bin` or `host`, or a file in them, whose inheritance is broken (NTFS does
    that to the children of a directory that just gained an inheritable ACE, and an interruption can leave it so) is kept
    protected, with its own explicit ACE for the service added to what it holds (for `host`, both); it is not refused.

    Windows' own access check, for the service's token with its groups, judges every DACL before it is written and
    after: on the root, `bin` and `host` and their files, and on the DACL a file created in `host` would inherit. A
    deny for the service or a group it is in, wherever the ACE stands, fails the call with the path, nothing written.
    """
    sid = _sid_of(account)
    listing = ACL_ACCESS | winfile.FILE_LIST_DIRECTORY
    with _errors(root), ExitStack() as stack:
        token = stack.enter_context(_service_token(sid))
        root_handle = stack.enter_context(
            _handle(root, directory=True, access=listing, share=winfile.FILE_SHARE_READ_WRITE)
        )
        top = _Target(root_handle, root, True, [])
        targets: list[_Target] = []
        # A directory missing from the listing is absent, not unopenable: whatever is created there inherits normally.
        for key, name in _listed(winfile.list_names(root_handle), ("bin", "host"), root).items():
            label = root / name
            try:
                handle = winfile.open_relative(
                    root_handle,
                    name,
                    label=label,
                    access=listing,
                    directory=True,
                    error=PermsError,
                    share=winfile.FILE_SHARE_READ_WRITE
                )
            except OSError as exc:
                raise _unopenable(label, exc) from exc
            stack.callback(winfile.close_handle, handle)
            directory = _Target(handle, label, True, [], top, inherited_read=key == "host")
            targets.append(directory)
            targets += [_Target(h, where, False, [], directory) for h, where in _open_entries(stack, handle, label)]
        top.entries, root_protected = winacl.read_entries(root_handle)
        for target in targets:
            target.entries, target.protected = winacl.read_entries(target.handle)
        # Compute every object's resulting ACL, in the order it will have on disk, before writing any of them: a
        # refusal (an unsupported inheritable ACE anywhere, a deny for the service) then leaves nothing changed.
        # Parents come before children.
        top.entries = _service_read(top.entries, sid)
        _require_planned(token, top.label, top.entries, root_protected, *winacl.owner_and_group(root_handle))
        writes = []
        for target in targets:
            assert target.parent is not None
            owner_sid, group_sid = winacl.owner_and_group(target.handle)
            if target.protected:  # NTFS protected it: it keeps the flag and its ACEs, and holds its own ACE
                target.entries = _service_read(target.entries, sid, files=target.directory and target.inherited_read)
            else:
                target.entries = winacl.canonical(
                    _explicit_service_read(target, sid) + winacl.inherited_for(
                        target.parent.entries,
                        directory=target.directory,
                        owner=owner_sid,
                        group=group_sid,
                        parent_label=str(target.parent.label)
                    )
                )
            _require_planned(token, target.label, target.entries, target.protected, owner_sid, group_sid)
            if target.directory and target.inherited_read:  # a file created there inherits this
                created = winacl.inherited_for(
                    target.entries, directory=False, owner=owner_sid, group=group_sid, parent_label=str(target.label)
                )
                _require_planned(token, target.label / "<a new file>", created, False, owner_sid, group_sid)
            writes.append((target.handle, target.entries, target.protected))
        # The root is last: by then everything the service reads holds its own access.
        writes.append((root_handle, top.entries, root_protected))
        with deferred_interrupts():  # Ctrl-C waits for the last write
            for handle, entries, protected in writes:
                winacl.set_dacl(handle, entries, protected=protected)
            for target in [top, *targets]:
                _require_on_disk(token, target.handle, target.label)


def grant_service_read_handle(handle: int, label: Path, account: Account) -> None:
    """Give the service read-and-execute on the file open as `handle` (READ_CONTROL, WRITE_DAC), named `label` in errors.

    The file keeps every ACE it has; only an earlier explicit allow for the service is replaced. For a file that is not
    in place yet: `atomic.replace_file` calls it on its temporary file, so the final name never exists without the grant.
    """
    sid = _sid_of(account)
    with _errors(label), _service_token(sid) as token:
        entries, protected = winacl.read_entries(handle)
        granted = _service_read(entries, sid)
        _require_planned(token, label, granted, protected, *winacl.owner_and_group(handle))
        winacl.set_dacl(handle, granted, protected=protected)
        _require_on_disk(token, handle, label)
