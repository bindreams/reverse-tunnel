# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Ownership and permissions of the deployment tree.

`ctl install` runs elevated, so every path it touches is assigned an owner explicitly and every change goes through an
open descriptor: path-based `chown`/`chmod` follow symlinks, and an account that can write the checkout could aim root
at any file on the machine.

On POSIX the owner and mode express who may read what. On Windows `os.chmod` sets no ACL, so the same intent is an ACL
of well-known SIDs (see `ctl.winacl`): `owner=None` means the path stays the operator's and the operator's SID is
granted explicitly; `readers` and `writers` are the SIDs of the other accounts, and POSIX ignores them.
"""

import dataclasses
import enum
import errno
import os
import stat
import subprocess
import sys
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path

from ctl import winacl
from ctl.config import Config, ConfigError
# Re-exported: callers build the `readers` sets from these.
from ctl.winacl import (
    SID_ADMINISTRATORS,
    SID_AUTHENTICATED_USERS,
    SID_EVERYONE,
    SID_LOCAL_SERVICE,
    SID_USERS,
    current_user_sid,
)

SECRET_MODE = 0o600
LOCAL_SERVICE = "LocalService"
# `O_NONBLOCK` keeps a FIFO at the path from blocking the open; `O_BINARY` stops Windows translating line endings.
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
O_BINARY = getattr(os, "O_BINARY", 0)


class PermsError(Exception):
    """A path cannot be given the ownership or mode it is meant to have."""


@dataclasses.dataclass(frozen=True)
class Account:
    name: str
    uid: int | None  # None on Windows
    gid: int | None


class AccountMode(enum.StrEnum):
    SAME = "same-account"
    SEPARATE = "separate-account"


# Accounts =============================================================================================================


def _lookup_account(name: str) -> Account | None:
    """The account called `name`, or None. Windows has one service account, `LocalService`."""
    if sys.platform == "win32":
        if name.casefold() in {LOCAL_SERVICE.casefold(), f"NT AUTHORITY\\{LOCAL_SERVICE}".casefold()}:
            return Account(LOCAL_SERVICE, None, None)
        return None
    import pwd

    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        return None
    return Account(entry.pw_name, entry.pw_uid, entry.pw_gid)


def resolve_service_account(name: str) -> Account:
    account = _lookup_account(name)
    if account is None:
        raise ConfigError(f"RT_SERVICE_USER: there is no account named {name!r} on this machine")
    if account.uid == 0:
        raise ConfigError(
            f"RT_SERVICE_USER: {name!r} is root (uid 0). Running frpc as root is what the explicit service account "
            "exists to prevent; name an unprivileged account"
        )
    return account


def service_account(config: Config) -> Account:
    """The account the daemons run as: `RT_SERVICE_USER` on POSIX, `LocalService` on Windows."""
    if sys.platform == "win32":
        return resolve_service_account(LOCAL_SERVICE)
    return resolve_service_account(config.require("RT_SERVICE_USER"))


def account_mode(root: Path, service: Account) -> AccountMode:
    """Whether the daemons run as the repository's owner. Windows' `LocalService` never is."""
    if service.uid is None:
        return AccountMode.SEPARATE
    return AccountMode.SAME if os.stat(root).st_uid == service.uid else AccountMode.SEPARATE


# Descriptors ==========================================================================================================


def _failure(path: Path, exc: OSError, *, dir_fd: int | None = None, name: str | None = None) -> PermsError:
    """Describe a failed open; the `lstat` only picks the wording, the refusal has already happened."""
    try:
        is_link = stat.S_ISLNK(os.lstat(path if dir_fd is None else str(name), dir_fd=dir_fd).st_mode)
    except OSError:
        is_link = False
    if is_link or exc.errno in (errno.ELOOP, errno.EMLINK):
        return PermsError(f"{path}: is a symlink; refusing to follow it")
    if exc.errno == errno.ENOTDIR:
        return PermsError(f"{path}: not a directory")
    return PermsError(f"{path}: {exc.strerror or exc}")


def _open(path: Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None, name: str | None = None) -> int:
    try:
        if dir_fd is None:
            return os.open(path, flags | NOFOLLOW, mode)
        return os.open(str(name), flags | NOFOLLOW, mode, dir_fd=dir_fd)
    except OSError as exc:
        raise _failure(path, exc, dir_fd=dir_fd, name=name) from exc


def _chown(fd: int, owner: Account | None) -> None:
    if owner is None:
        return
    if owner.uid is None or owner.gid is None:
        raise ValueError(f"{owner.name} has no uid; it cannot own a POSIX path")
    os.fchown(fd, owner.uid, owner.gid)


def _require_regular(fd: int, path: Path) -> None:
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise PermsError(f"{path}: not a regular file")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


@contextmanager
def _converged(path: Path, owner: Account | None, mode: int) -> Generator[int]:
    """Open the directory at `path`, creating it if absent, and give it `owner` and `mode` through the descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY
    try:
        fd = _open(path, flags)
    except PermsError as err:
        if not isinstance(err.__cause__, FileNotFoundError):
            raise
        try:
            os.mkdir(path, 0o700)
        except OSError as exc:
            raise PermsError(f"{path}: {exc.strerror or exc}") from exc
        fd = _open(path, flags)
    try:
        _chown(fd, owner)
        os.fchmod(fd, mode)
        yield fd
    finally:
        os.close(fd)


def _converge_entries(directory_fd: int, directory: Path, owner: Account) -> None:
    with os.scandir(directory_fd) as scan:
        names = [entry.name for entry in scan]
    for name in names:
        path = directory / name
        fd = _open(path, os.O_RDONLY, dir_fd=directory_fd, name=name)
        try:
            _chown(fd, owner)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                _converge_entries(fd, path, owner)
        finally:
            os.close(fd)


# Windows ==============================================================================================================


def _reject_reparse_point(path: Path) -> None:
    """Refuse a symlink or junction. Windows has no `O_NOFOLLOW`, so this check precedes the act."""
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermsError(f"{path}: is a symlink or other reparse point; refusing to follow it")


def _reject_if_reparse_point(path: Path) -> None:
    try:
        _reject_reparse_point(path)
    except FileNotFoundError:
        pass


@contextmanager
def _acl_errors(path: Path) -> Generator[None]:
    try:
        yield
    except subprocess.CalledProcessError as exc:
        raise PermsError(f"{path}: icacls failed: {(exc.stderr or exc.stdout or '').strip()}") from exc
    except OSError as exc:
        raise PermsError(f"{path}: {exc.strerror or exc}") from exc


def _apply_acl(
    path: Path,
    *,
    directory: bool,
    owner: Account | None,
    readers: frozenset[str],
    writers: frozenset[str],
    isolate: bool,
) -> None:
    with _acl_errors(path):
        wanted = winacl.apply(
            path,
            directory=directory,
            operator=current_user_sid() if owner is None else None,
            readers=readers,
            writers=writers,
            isolate=isolate,
        )
        actual = principals(path)
    if isolate and actual != wanted:
        raise PermsError(f"{path}: the ACL grants {sorted(actual)}, expected {sorted(wanted)}")
    if not wanted <= actual:
        raise PermsError(f"{path}: the ACL lacks {sorted(wanted - actual)}")


def _sid_of(account: Account) -> str:
    if account.name.casefold() == LOCAL_SERVICE.casefold():
        return SID_LOCAL_SERVICE
    raise ValueError(f"no well-known SID for account {account.name!r}")


def _windows_directory(path: Path) -> None:
    try:
        _reject_reparse_point(path)
    except FileNotFoundError:
        try:
            os.mkdir(path)
        except OSError as exc:
            raise PermsError(f"{path}: {exc.strerror or exc}") from exc
        return
    if not path.is_dir():
        raise PermsError(f"{path}: not a directory")


def _windows_entries(directory: Path) -> Iterator[Path]:
    for entry in directory.iterdir():
        _reject_reparse_point(entry)
        yield entry
        if entry.is_dir():
            yield from _windows_entries(entry)


# Files ================================================================================================================


def write_secret(path: Path, data: bytes, owner: Account | None, readers: frozenset[str]) -> None:
    """Write `data` to `path`, never readable by anyone the final mode excludes, even for an instant.

    The file is created `0600`, so there is no window at `0666 & ~umask`, and `O_NOFOLLOW` stops a pre-existing symlink
    redirecting the secret. Ownership and mode are set on the descriptor before the first byte is written.
    """
    if sys.platform == "win32":
        _reject_if_reparse_point(path)
        fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_BINARY, SECRET_MODE)
        try:
            _apply_acl(path, directory=False, owner=owner, readers=readers, writers=frozenset(), isolate=True)
            _write_all(fd, data)
        finally:
            os.close(fd)
        return
    fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECRET_MODE)
    try:
        _require_regular(fd, path)
        _chown(fd, owner)
        os.fchmod(fd, SECRET_MODE)
        _write_all(fd, data)
    finally:
        os.close(fd)


def harden_file(path: Path, owner: Account | None, readers: frozenset[str]) -> None:
    """Make `path` owner-only (`0600`, or on Windows an ACL of exactly the operator, Administrators and `readers`).

    Refuses a symlink: the guarantee would otherwise be made about a different file than the one the operator hardened.
    """
    if sys.platform == "win32":
        try:
            _reject_reparse_point(path)
        except OSError as exc:
            raise PermsError(f"{path}: {exc.strerror or exc}") from exc
        if not path.is_file():
            raise PermsError(f"{path}: not a regular file")
        _apply_acl(path, directory=False, owner=owner, readers=readers, writers=frozenset(), isolate=True)
        return
    fd = _open(path, os.O_RDONLY)
    try:
        _require_regular(fd, path)
        _chown(fd, owner)
        os.fchmod(fd, SECRET_MODE)
    finally:
        os.close(fd)


# Directories ==========================================================================================================


def converge_dir(
    path: Path,
    owner: Account | None,
    mode: int,
    readers: frozenset[str],
    *,
    writers: frozenset[str] = frozenset(),
    isolate: bool = True,
) -> None:
    """Create `path` if absent and reassert its owner and mode, whatever state it was left in.

    Leaving an existing directory alone is wrong here: another account that owns, or can write to, `secrets/` can
    replace the token inside it regardless of the token's own mode. A symlink at `path` is refused, never repaired.
    On Windows `isolate` breaks inheritance; only `.env`, `secrets/` and the token do, never the repository root.
    """
    if sys.platform == "win32":
        _windows_directory(path)
        _apply_acl(path, directory=True, owner=owner, readers=readers, writers=writers, isolate=isolate)
        return
    with _converged(path, owner, mode):
        pass


def converge_tree(path: Path, owner: Account | None, mode: int) -> None:
    """`converge_dir` for `path`, then give `owner` every entry beneath it, keeping each entry's own mode.

    systemd opens a log's append target after dropping to `User=`, so a stale owner is `EACCES` and the daemon never
    starts. A symlink anywhere in the tree is refused: a service that can write `logs/` could plant one for root to chown.
    """
    if sys.platform == "win32":
        with _acl_errors(path):
            _windows_directory(path)
            entries = list(_windows_entries(path))
            for entry in entries:
                if entry.parent == path:
                    winacl.reset_to_inherited(entry)
        return
    with _converged(path, owner, mode) as fd:
        if owner is not None:
            _converge_entries(fd, path, owner)


def grant_traverse(path: Path, account: Account) -> None:
    """Let `account` reach what is under `path`: an inheritable read-and-execute ACE on Windows, nothing on POSIX.

    This is what lets `LocalService` reach a repository cloned under a user profile directory.
    """
    if sys.platform != "win32":
        return
    _reject_reparse_point(path)
    with _acl_errors(path):
        winacl.grant_traversal(path, _sid_of(account))


# Inspection ===========================================================================================================


def _owner_name(uid: int) -> str:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def principals(path: Path) -> frozenset[str]:
    """Everything `path` grants: its SIDs on Windows, `owner=<name>` and `mode=<octal>` on POSIX.

    Doctor compares this against the exact expected set, so an unexpected principal is a failure.
    """
    if sys.platform == "win32":
        return winacl.read_acl(path).sids
    status = os.lstat(path)
    return frozenset({f"owner={_owner_name(status.st_uid)}", f"mode={stat.S_IMODE(status.st_mode):04o}"})


def describe(path: Path) -> str:
    """`principals` for a human."""
    if sys.platform == "win32":
        acl = winacl.read_acl(path)
        inheritance = "inheritance broken" if acl.protected else "inheritance enabled"
        return f"grants {', '.join(sorted(acl.sids))}; {inheritance}"
    status = os.lstat(path)
    return f"owner {_owner_name(status.st_uid)}, mode {stat.S_IMODE(status.st_mode):04o}"
