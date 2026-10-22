# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The Windows half of `ctl.perms`.

Each path is opened once with `FILE_FLAG_OPEN_REPARSE_POINT`, which refuses a reparse point before anything is
changed, and its ACL is then set and read back through that handle, so the object that was checked is the object that
is changed; what is read back must be the whole ACL that was written. A directory whose entries are changed too, or
that gains an inheritable ACE, is held open without `FILE_SHARE_DELETE`; its entries are listed through that handle and
opened relative to it, then the entries of each subdirectory the same way, at every depth, and every entry is vetted
before the first ACL is written. An entry that is gone, or pending deletion, by the time it is opened has nothing to change and is skipped.

ACLs are written with `NtSetSecurityObject`, which propagates to no child; the inherited ACEs of each object are
computed here (`winacl.inherited_for`) and written to that object through its own handle. The Win32 `SetSecurityInfo`
would instead walk the whole subtree before any of it could be vetted. Windows Server 2025 does not stop there: a new
inheritable ACE on a directory makes NTFS turn the inherited ACEs of its direct children into explicit, protected ones.
That is why a directory is only ever given an inheritable ACE after every entry in it has been opened and vetted, and
why the repository root, which holds files `ctl` never opens, is only ever written to take an ACE away.

`bin`, `host` and `logs` are the install's own (`converge_owned`): each is protected, holds a fixed DACL with no deny
in it, and every entry in it, at every depth, is rewritten to inherit from its directory. The service has no ACE on the
repository root.

The owner field of an object is deliberately left as created (Administrators when the process is elevated). Ownership
is expressed by the ACL alone, with explicit grants for the principals that matter; `operator_sid` names the one that
stands for the repository's owner.
"""

import os
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import NamedTuple

from ctl import _winfile as winfile
from ctl import winacl
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
REMOVE = "; remove it, then rerun"
RETRY = "remove it, or close the process holding it, then rerun"


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


def _verify(handle: int, path: Path, entries: list[winacl.Entry], *, protected: bool) -> None:
    """Fail loudly unless the ACL reads back as exactly what was written: every ACE and the inheritance state."""
    found, found_protected = winacl.read_entries(handle)
    if found_protected != protected:
        was, expected = ("broken", "enabled") if found_protected else ("enabled", "broken")
        raise PermsError(f"{path}: inheritance is {was}, expected {expected}")
    if found != entries:
        raise PermsError(f"{path}: the ACL reads back as {found}, not what was written ({entries})")


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
        entries = winacl.apply(
            handle, directory=False, operator=operator, readers=readers, writers=frozenset(), isolate=True
        )
        _verify(handle, path, entries, protected=True)


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
        entries = winacl.apply(
            handle, directory=False, operator=operator, readers=readers, writers=frozenset(), isolate=True
        )
        _verify(handle, temporary, entries, protected=True)
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


class _Node(NamedTuple):
    """An entry below a held directory: opened and vetted, with the label of the directory that holds it."""
    handle: int
    label: Path
    parent: Path
    directory: bool


def _open_tree(stack: ExitStack, directory: int, where: Path) -> list[_Node]:
    """Open every entry below the held `directory`, at every depth, parents before the entries they hold.

    Each entry is opened relative to the directory that holds it and kept open on `stack`, so a refusal part-way closes
    the ones already opened. A reparse point or a hard-linked file anywhere is refused. An entry listed and gone (or pending
    deletion) by the time it is opened is skipped: there is nothing left to change. Every other failure refuses.
    """
    nodes: list[_Node] = []
    pending = [(directory, where)]
    while pending:
        held, label = pending.pop()
        for name in winfile.list_names(held):
            node = _open_entry(stack, held, name, label)
            if node is None:
                continue
            nodes.append(node)
            if node.directory:
                listing = _open_listing(stack, held, name, node)
                if listing is not None:
                    pending.append((listing, node.label))
    return nodes


def _open_entry(stack: ExitStack, directory: int, name: str, where: Path) -> _Node | None:
    label = where / name
    try:
        handle = winfile.open_relative(
            directory, name, label=label, access=ACL_ACCESS, directory=None, single_link=True, error=PermsError
        )
    except (FileNotFoundError, winfile.DeletePending):
        return None
    except PermsError as exc:
        raise PermsError(f"{exc}{REMOVE}") from exc
    except OSError as exc:  # a name just listed that cannot be opened is not skipped: fail closed
        raise _unopenable(label, exc) from exc
    stack.callback(winfile.close_handle, handle)
    return _Node(handle, label, where, winfile.is_directory(handle))


def _open_listing(stack: ExitStack, directory: int, name: str, node: _Node) -> int | None:
    """A handle to the subdirectory `node`, opened to list it; `None` if it is gone or pending deletion.

    It is the very directory `node.handle` holds, which is open without `FILE_SHARE_DELETE`: nothing can have replaced
    the name since. Identities are compared all the same.
    """
    try:
        listing = winfile.open_relative(
            directory,
            name,
            label=node.label,
            access=winfile.FILE_LIST_DIRECTORY,
            directory=True,
            error=PermsError,
        )
    except (FileNotFoundError, winfile.DeletePending):
        return None
    except PermsError as exc:
        raise PermsError(f"{exc}{REMOVE}") from exc
    except OSError as exc:
        raise _unopenable(node.label, exc) from exc
    stack.callback(winfile.close_handle, listing)
    if winfile.file_identity(listing) != winfile.file_identity(node.handle):
        raise PermsError(f"{node.label}: was replaced while it was being opened; {RETRY}")
    return listing


def converge_dir(
    path: Path,
    owner: Account | None,
    readers: frozenset[str],
    writers: frozenset[str],
    isolate: bool,
    root: Path,
) -> None:
    """Converge the ACL of `path`, having opened and vetted everything below it first.

    Windows Server 2025 makes NTFS rewrite the ACL of each direct child of a directory that gains an inheritable ACE,
    so `path` is held without `FILE_SHARE_DELETE`, each entry at every depth is opened relative to its directory (a
    reparse point or a hard-linked file is refused before anything is written), and each is then written back through
    its own handle, parents first: an entry that inherits keeps its own ACEs and holds what it inherits from its
    directory's new ACL, one whose inheritance is broken is left exactly as it was.
    """
    operator = _operator(owner, root)
    with _errors(path), ExitStack() as stack:
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
        nodes = _open_tree(stack, held, path)
        owner_sid, group_sid = winacl.owner_and_group(held)
        planned, _ = winacl.plan(
            directory=True,
            operator=operator,
            readers=readers,
            writers=writers,
            isolate=isolate,
            parent=parent,
            owner=owner_sid,
            group=group_sid,
            parent_label=str(path.parent),
        )
        # Everything that can be refused is computed before the first write.
        holds = {path: planned}  # what each directory will hold, which its entries inherit from
        writes = []
        for node in nodes:
            entries, protected = winacl.read_entries(node.handle)
            if not protected:
                child_owner, child_group = winacl.owner_and_group(node.handle)
                entries = winacl.canonical(
                    winacl.explicit(entries) + winacl.inherited_for(
                        holds[node.parent],
                        directory=node.directory,
                        owner=child_owner,
                        group=child_group,
                        parent_label=str(node.parent)
                    )
                )
            if node.directory:
                holds[node.label] = entries
            writes.append((node, entries, protected))
        with deferred_interrupts():  # Ctrl-C waits for the last write
            winacl.set_dacl(held, planned, protected=isolate)
            _verify(held, path, planned, protected=isolate)
            for node, entries, protected in writes:
                if winacl.read_entries(node.handle) != (entries, protected):  # NTFS may already have written it so
                    winacl.set_dacl(node.handle, entries, protected=protected)
                if winacl.read_acl_handle(node.handle).protected != protected:
                    raise PermsError(
                        f"{node.label}: inheritance is {'enabled' if protected else 'broken'} after the write"
                    )


def _write_exactly(handle: int, label: Path, entries: list[winacl.Entry], *, protected: bool) -> None:
    """Make the object behind `handle` hold exactly `entries`, writing nothing if it already does; fail loudly if not."""
    if winacl.read_entries(handle) == (entries, protected):
        return
    winacl.set_dacl(handle, entries, protected=protected)
    _verify(handle, label, entries, protected=protected)


def converge_owned(path: Path, service: Account, *, write: bool, root: Path) -> None:
    """Make `path` the install's own, whatever state it was left in: `bin`, `host` and `logs`.

    The DACL written is the whole of it and is protected (nothing comes from above): the operator and Administrators
    with full control, the service with read-and-execute, or with modify when `write`; all inheritable, and no deny.
    ACEs anyone else added are dropped. Every entry below it, at every depth, is then rewritten to exactly what it
    inherits from its directory, protected or not, so a file moved in from elsewhere (it keeps the DACL it had), or one
    NTFS protected, ends up readable by the service; and a file created in `path` afterwards (git replaces
    `host/frpc.toml`) inherits the same.

    `path` is held without `FILE_SHARE_DELETE`, its entries are listed through that handle and opened relative to it,
    and so are the entries of each subdirectory; all of them are vetted (a reparse point or a hard-linked file anywhere
    is refused: rewriting a hard-linked file would change a file outside `path`) before the first ACL is written. An
    entry that has gone by the time it is opened is skipped. `path` is written first, then each directory before the
    entries it holds, each once and only if it differs; the DACL of `path` holds the service's access, so no write
    leaves anything the service needs without it. Inheritance from the parent plays no part, so nothing on it is read.
    """
    sid = _sid_of(service)
    operator = operator_sid(root)
    with _errors(path), ExitStack() as stack:
        held = stack.enter_context(
            _handle(
                path,
                directory=True,
                create=True,
                access=ACL_ACCESS | winfile.FILE_LIST_DIRECTORY,
                share=winfile.FILE_SHARE_READ_WRITE
            )
        )
        nodes = _open_tree(stack, held, path)
        planned, _ = winacl.plan(
            directory=True,
            operator=None,
            readers=frozenset() if write else frozenset({sid}),
            writers=frozenset({sid}) if write else frozenset(),
            full=frozenset({operator}),
            isolate=True,
        )
        holds = {path: planned}  # what each directory will hold, which its entries inherit from
        inherited = []
        for node in nodes:
            entries = winacl.inherited_for(holds[node.parent], directory=node.directory)
            if node.directory:
                holds[node.label] = entries
            inherited.append((node, entries))
        with deferred_interrupts():  # Ctrl-C waits for the last write
            _write_exactly(held, path, planned, protected=True)
            for node, entries in inherited:
                _write_exactly(node.handle, node.label, entries, protected=False)


def _installed_grant(entry: winacl.Entry, sid: str) -> bool:
    """Whether `entry` is the read-and-execute allow for `sid` that an earlier install wrote on the repository root."""
    return (
        entry.ace_type == winacl.ACCESS_ALLOWED_ACE_TYPE and entry.sid == sid and entry.mask == winacl.READ_EXECUTE
        and not entry.flags & winacl.INHERITED_ACE
    )


def revoke_root(root: Path, service: Account) -> None:
    """Take from the repository root the service's read-and-execute ACE that an earlier install gave it.

    The service needs nothing on the root: its working directory is `logs`. Only that ACE is removed, wherever its
    inheritance flags stood; every other ACE and the inheritance state stay as they were, and nothing is written when
    the root holds none. The root is written through its own handle and no entry in it is opened: the other children of
    the root are not `ctl`'s. Call it after `bin`, `host` and `logs` are converged, which hold their own access.
    """
    sid = _sid_of(service)
    with _errors(root), _handle(root, directory=True) as handle:
        entries, protected = winacl.read_entries(handle)
        kept = [entry for entry in entries if not _installed_grant(entry, sid)]
        if len(kept) == len(entries):
            return
        with deferred_interrupts():
            winacl.set_dacl(handle, kept, protected=protected)
        found, found_protected = winacl.read_entries(handle)
        if found_protected != protected or any(_installed_grant(entry, sid) for entry in found):
            raise PermsError(f"{root}: the service's ACE is still there, or inheritance changed, after the write")
