# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The Windows half of `ctl.perms`.

Each path is opened once with `FILE_FLAG_OPEN_REPARSE_POINT`, which refuses a reparse point before anything is
changed, and its ACL is then set and read back through that handle, so the object that was checked is the object that
is changed. A directory whose entries are changed too is held open without `FILE_SHARE_DELETE`; its entries are listed
through that handle and opened relative to it, and every entry is vetted before the first ACL is written.

ACLs are written with `NtSetSecurityObject`, which propagates to no child; the inherited ACEs of each object are
computed here (`winacl.inherited_for`) and written to that object through its own handle. The Win32 `SetSecurityInfo`
would instead walk the whole subtree before any of it could be vetted.

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
from ctl import winacl
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
FLAT = "; remove it, this directory holds regular files only"


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
        raise PermsError(f"{path}: inheritance is {'enabled' if acl.protected else 'broken'}, expected the opposite")
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
    path: Path, owner: Account | None, readers: frozenset[str], writers: frozenset[str], isolate: bool, root: Path
) -> None:
    operator = _operator(owner, root)
    with _errors(path):
        parent = [] if isolate else _parent_entries(path.parent)
        with _handle(path, directory=True, create=True) as handle:
            wanted = winacl.apply(
                handle,
                directory=True,
                operator=operator,
                readers=readers,
                writers=writers,
                isolate=isolate,
                parent=parent
            )
            _verify(handle, path, wanted, isolate=isolate)


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
        except FileNotFoundError:
            continue
        except PermsError as exc:
            raise PermsError(f"{exc}{FLAT}") from exc
        except OSError as exc:
            raise PermsError(f"{label}: {exc.strerror or exc}") from exc
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
        wanted = winacl.apply(
            held, directory=True, operator=operator, readers=frozenset(), writers=writers, isolate=False, parent=parent
        )
        _verify(held, path, wanted, isolate=False)
        inherited = winacl.inherited_for(winacl.read_entries(held)[0], directory=False)
        for handle, label in entries:
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


def grant_service_read(root: Path, account: Account) -> None:
    """Give the service read-and-execute on exactly the objects it needs, each through its own vetted handle.

    The set is known: `root`, `bin` and its direct files, `host` and its direct files. `root` and `bin` and `host` are
    held without `FILE_SHARE_DELETE`; their files are opened relative to them. Everything is vetted (a subdirectory, a
    reparse point, a hard-linked file, or an object whose inheritance is broken is refused) before the first ACL is
    written, and each object's inherited ACEs are computed from its parent's new ACL, never propagated by the OS.
    """
    sid = _sid_of(account)
    listing = ACL_ACCESS | winfile.FILE_LIST_DIRECTORY
    with _errors(root), ExitStack() as stack:
        root_handle = stack.enter_context(
            _handle(root, directory=True, access=listing, share=winfile.FILE_SHARE_READ_WRITE)
        )
        top = _Target(root_handle, root, True, [])
        targets: list[_Target] = []
        for name in ("bin", "host"):
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
            except FileNotFoundError:
                continue
            stack.callback(winfile.close_handle, handle)
            directory = _Target(handle, label, True, [], top)
            targets.append(directory)
            targets += [_Target(h, where, False, [], directory) for h, where in _open_entries(stack, handle, label)]
        top.entries, root_protected = winacl.read_entries(root_handle)
        for target in targets:
            target.entries, protected = winacl.read_entries(target.handle)
            if protected:
                raise PermsError(f"{target.label}: inheritance is broken; the service could not read it")
        # Everything is vetted; write parents before children, each from its parent's new ACL.
        service = winacl.Entry(
            winacl.ACCESS_ALLOWED_ACE_TYPE,
            winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE,
            winacl.READ_EXECUTE,
            sid,
        )
        replaced = [e for e in top.entries if e.flags & winacl.INHERITED_ACE or e.sid != sid]
        top.entries = replaced + [service]
        winacl.set_dacl(root_handle, top.entries, protected=root_protected)
        for target in targets:
            assert target.parent is not None
            target.entries = winacl.explicit(
                target.entries
            ) + winacl.inherited_for(target.parent.entries, directory=target.directory)
            winacl.set_dacl(target.handle, target.entries, protected=False)
        for target in [top, *targets]:
            if sid not in winacl.read_acl_handle(target.handle).sids:
                raise PermsError(f"{target.label}: the service still has no access after the grant")
