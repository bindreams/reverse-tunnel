# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The Windows half of `ctl.perms`.

Each path is opened once with `FILE_FLAG_OPEN_REPARSE_POINT`, which refuses a reparse point before anything is
changed, and its ACL is then set through that handle, so the object that was checked is the object that is changed.
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
    principals,
    temporary_name,
    unlink_quietly,
    write_all,
)

ACL_ACCESS = winfile.READ_CONTROL | winfile.WRITE_DAC
LOCAL_SERVICE = "localservice"


@contextmanager
def _errors(path: Path) -> Generator[None]:
    """Report an OS failure as a `PermsError` naming `path`."""
    try:
        yield
    except OSError as exc:
        raise PermsError(f"{path}: {exc.strerror or exc}") from exc


@contextmanager
def _handle(path: Path, *, directory: bool, create: bool = False) -> Generator[int]:
    """A vetted handle to `path` with the access an ACL change needs, creating the directory first if `create`."""
    try:
        handle = winfile.open_handle(
            path, access=ACL_ACCESS, disposition=winfile.OPEN_EXISTING, directory=directory, error=PermsError
        )
    except FileNotFoundError:
        if not create:
            raise
        os.mkdir(path)
        handle = winfile.open_handle(
            path, access=ACL_ACCESS, disposition=winfile.OPEN_EXISTING, directory=directory, error=PermsError
        )
    try:
        yield handle
    finally:
        winfile.close_handle(handle)


def _verify(path: Path, wanted: frozenset[str], *, isolate: bool) -> None:
    """Fail loudly if the ACL is not what was meant: the whole ACL when isolated, at least the grants otherwise."""
    actual = principals(path)
    if isolate and actual != wanted:
        raise PermsError(f"{path}: the ACL grants {sorted(actual)}, expected {sorted(wanted)}")
    if not wanted <= actual:
        raise PermsError(f"{path}: the ACL lacks {sorted(wanted - actual)}")


def _operator(owner: Account | None) -> str | None:
    """`owner=None` leaves the path the operator's, so the operator's SID is granted explicitly."""
    return winacl.current_user_sid() if owner is None else None


def _sid_of(account: Account) -> str:
    if account.name.casefold() == LOCAL_SERVICE:
        return SID_LOCAL_SERVICE
    raise ValueError(f"no well-known SID for account {account.name!r}")


# Files ================================================================================================================


def harden_file(path: Path, owner: Account | None, readers: frozenset[str]) -> None:
    with _errors(path), _handle(path, directory=False) as handle:
        wanted = winacl.apply(
            handle, directory=False, operator=_operator(owner), readers=readers, writers=frozenset(), isolate=True
        )
    with _errors(path):
        _verify(path, wanted, isolate=True)


def _create_temporary(path: Path, owner: Account | None, readers: frozenset[str]) -> tuple[Path, int, frozenset[str]]:
    """Create a uniquely named file beside `path`, give it its ACL, and return it as a write-only descriptor."""
    import msvcrt

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
            handle, directory=False, operator=_operator(owner), readers=readers, writers=frozenset(), isolate=True
        )
        return temporary, msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY), wanted
    except BaseException:
        winfile.close_handle(handle)
        unlink_quietly(str(temporary))
        raise


def write_secret(path: Path, data: bytes, owner: Account | None, readers: frozenset[str]) -> None:
    """Atomic, like POSIX: the ACL is set on the temporary file before any byte is written, then it replaces `path`."""
    with _errors(path):
        try:
            status = os.lstat(path)
        except FileNotFoundError:
            status = None
    check_destination(path, status)
    with _errors(path):
        temporary, fd, wanted = _create_temporary(path, owner, readers)
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
    with _errors(path):
        _verify(path, wanted, isolate=True)


# Directories ==========================================================================================================


def converge_dir(
    path: Path, owner: Account | None, readers: frozenset[str], writers: frozenset[str], isolate: bool
) -> None:
    with _errors(path), _handle(path, directory=True, create=True) as handle:
        wanted = winacl.apply(
            handle, directory=True, operator=_operator(owner), readers=readers, writers=writers, isolate=isolate
        )
    with _errors(path):
        _verify(path, wanted, isolate=isolate)


def _reset_entries(directory: Path) -> None:
    with os.scandir(directory) as scan:
        entries = [(Path(entry.path), entry.is_dir(follow_symlinks=False)) for entry in scan]
    for path, is_directory in entries:
        with _errors(path), _handle(path, directory=is_directory) as handle:
            winacl.reset_to_inherited(handle)
        if is_directory:
            _reset_entries(path)


def converge_tree(path: Path) -> None:
    """Reset every entry under `path` to inherit from its parent, refusing a reparse point anywhere in the tree."""
    with _errors(path):
        with _handle(path, directory=True, create=True):
            pass
        _reset_entries(path)


def grant_traverse(path: Path, account: Account) -> None:
    sid = _sid_of(account)
    with _errors(path), _handle(path, directory=True) as handle:
        winacl.grant_traversal(handle, sid)
