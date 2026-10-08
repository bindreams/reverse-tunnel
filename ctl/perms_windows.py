# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The Windows half of `ctl.perms`.

Each path is opened once with `FILE_FLAG_OPEN_REPARSE_POINT`, which refuses a reparse point before anything is
changed, and its ACL is then set and read back through that handle, so the object that was checked is the object that
is changed.

The owner field of an object is deliberately left as created (Administrators when the process is elevated). Ownership
is expressed by the ACL alone, with explicit grants for the principals that matter; `operator_sid` names the one that
stands for the repository's owner.
"""

import os
from collections.abc import Generator
from contextlib import contextmanager
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
def _handle(path: Path, *, directory: bool, create: bool = False, single_link: bool = False) -> Generator[int]:
    """A vetted handle to `path` with the access an ACL change needs, creating the directory first if `create`."""

    def open_it() -> int:
        return winfile.open_handle(
            path,
            access=ACL_ACCESS,
            disposition=winfile.OPEN_EXISTING,
            directory=directory,
            error=PermsError,
            single_link=single_link
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
    actual = winacl.read_acl_handle(handle).sids
    if isolate and actual != wanted:
        raise PermsError(f"{path}: the ACL grants {sorted(actual)}, expected {sorted(wanted)}")
    if not wanted <= actual:
        raise PermsError(f"{path}: the ACL lacks {sorted(wanted - actual)}")


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
    with _errors(path), _handle(path, directory=True, create=True) as handle:
        wanted = winacl.apply(
            handle, directory=True, operator=operator, readers=readers, writers=writers, isolate=isolate
        )
        _verify(handle, path, wanted, isolate=isolate)


def _reset_entries(directory: Path) -> None:
    """Reset each direct entry to inherit from `directory`. Nothing is entered; only regular files are accepted."""
    with os.scandir(directory) as scan:
        entries = [Path(entry.path) for entry in scan]
    for entry in entries:
        try:
            with _handle(entry, directory=False, single_link=True) as handle:
                winacl.reset_to_inherited(handle)
        except FileNotFoundError:
            continue
        except PermsError as exc:
            raise PermsError(f"{exc}{FLAT}") from exc
        except OSError as exc:
            raise PermsError(f"{entry}: {exc.strerror or exc}") from exc


def converge_tree(path: Path, owner: Account | None, root: Path) -> None:
    """Converge `path` itself, then reset its direct entries; the service account gets modify on the whole of it."""
    writers = frozenset() if owner is None else frozenset({_sid_of(owner)})
    converge_dir(path, owner, frozenset(), writers, False, root)
    with _errors(path):
        _reset_entries(path)


def grant_service_read(root: Path, account: Account) -> None:
    sid = _sid_of(account)
    with _errors(root), _handle(root, directory=True) as handle:
        winacl.grant_read(handle, sid)
