# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Ownership and permissions of the deployment tree.

`ctl install` runs elevated, so every path it touches is assigned an owner explicitly and every change goes through an
open descriptor: path-based `chown`/`chmod` follow symlinks, and an account that can write the checkout could aim root
at any file on the machine.

On POSIX the owner and mode express who may read what. On Windows `os.chmod` sets no ACL, so the same intent is an ACL
of well-known SIDs (see `ctl.winacl`), set through a handle that `ctl._winfile` has already vetted: `owner=None` means
the path stays the operator's and the operator's SID is granted explicitly; `readers` and `writers` are the SIDs of the
other accounts, and POSIX ignores them.
"""

import dataclasses
import enum
import errno
import os
import secrets
import stat
import sys
from collections.abc import Generator
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
)

SECRET_MODE = 0o600
LOCAL_SERVICE = "LocalService"
# `O_NONBLOCK` keeps a FIFO at the path from blocking the open and `O_NOCTTY` a terminal from becoming ours; `O_BINARY` stops Windows translating line endings.
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
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
    if exc.errno == errno.ENXIO:  # a socket, or a FIFO with no reader, swapped in after the check
        return PermsError(f"{path}: not a regular file")
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


def _require_sole_regular_file(fd: int, path: Path) -> None:
    """Refuse anything but a regular file with one name: changing a hard-linked inode changes it for every link."""
    status = os.fstat(fd)
    if not stat.S_ISREG(status.st_mode):
        raise PermsError(f"{path}: not a regular file")
    if status.st_nlink > 1:
        raise PermsError(_hard_link_message(path, status.st_nlink))


def _hard_link_message(path: Path, links: int) -> str:
    return f"{path}: has {links} hard links; refusing to change a file that is also reachable under another name"


def write_all(fd: int, data: bytes) -> None:
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


def _refuse_entry(path: Path, status: os.stat_result, *, directory_device: int) -> None:
    """Refuse an entry of `logs/` that is not a regular file with one name on the directory's own filesystem.

    A hard-linked file would hand root's `chown` an inode that is also reachable from outside `logs/`, and so would
    a file on another filesystem.
    """
    if stat.S_ISLNK(status.st_mode):
        raise PermsError(f"{path}: is a symlink; remove it")
    if not stat.S_ISREG(status.st_mode):
        raise PermsError(f"{path}: not a regular file; remove it, this directory holds regular files only")
    if status.st_nlink > 1:
        raise PermsError(_hard_link_message(path, status.st_nlink) + "; remove it")
    if status.st_dev != directory_device:
        raise PermsError(f"{path}: is on another filesystem than its directory; remove it")


def _converge_entries(directory_fd: int, directory: Path, owner: Account | None) -> None:
    """Give `owner` each direct entry of the directory. The directory is flat: nothing is entered, so a subdirectory
    is refused rather than followed. Special files are refused before they are opened, since opening a FIFO or a
    socket can block or fail."""
    device = os.fstat(directory_fd).st_dev
    with os.scandir(directory_fd) as scan:
        names = [entry.name for entry in scan]
    for name in names:
        path = directory / name
        try:
            _refuse_entry(path, os.lstat(name, dir_fd=directory_fd), directory_device=device)
        except FileNotFoundError:
            continue
        if owner is None:
            continue
        fd = _open(path, os.O_RDONLY, dir_fd=directory_fd, name=name)
        try:
            _refuse_entry(path, os.fstat(fd), directory_device=device)
            _chown(fd, owner)
        finally:
            os.close(fd)


# Files ================================================================================================================


def check_destination(path: Path, status: os.stat_result | None) -> None:
    """Refuse a destination that is not a regular file with one name, or absent.

    A diagnostic, not a boundary: nothing here follows or writes through a link, and a swap after this call changes
    only which file the rename replaces.
    """
    if status is None:
        return
    if stat.S_ISLNK(status.st_mode) or getattr(status, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermsError(f"{path}: is a symlink; refusing to replace it")
    if not stat.S_ISREG(status.st_mode):
        raise PermsError(f"{path}: not a regular file")
    if status.st_nlink > 1:
        raise PermsError(_hard_link_message(path, status.st_nlink) + "; the other name would keep the old secret")


def unlink_quietly(name: str, *, dir_fd: int | None = None) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass


def temporary_name(path: Path) -> str:
    return f".{path.name}.{secrets.token_hex(8)}.tmp"


def write_secret(path: Path, data: bytes, owner: Account | None, readers: frozenset[str], *, root: Path) -> None:
    """Replace `path` with `data`, atomically and never readable by anyone the final mode excludes, even for an instant.

    The secret is written to a temporary file beside `path`, created `0600` with `O_EXCL|O_NOFOLLOW`, so there is no
    window at `0666 & ~umask` and nothing is written through a link. Ownership and mode are set on the descriptor before
    the first byte, the data is flushed, and `rename` swaps it in: a reader sees the old secret or the new one, never a
    truncated file, and a crash leaves the old one. `rename` replaces whatever is at the name without following it, so
    a symlink swapped in after the destination check is replaced, not written through.
    """
    if sys.platform == "win32":
        from ctl import perms_windows

        perms_windows.write_secret(path, data, owner, readers, root)
        return
    directory_fd = _open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            status = os.lstat(path.name, dir_fd=directory_fd)
        except FileNotFoundError:
            status = None
        check_destination(path, status)
        while True:
            name = temporary_name(path)
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, SECRET_MODE, dir_fd=directory_fd)
                break
            except FileExistsError:
                continue
            except OSError as exc:
                raise _failure(path.parent / name, exc) from exc
        try:
            try:
                _chown(fd, owner)
                os.fchmod(fd, SECRET_MODE)
                write_all(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.replace(name, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            except OSError as exc:
                raise PermsError(f"{path}: {exc.strerror or exc}") from exc
        except BaseException:
            unlink_quietly(name, dir_fd=directory_fd)
            raise
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def harden_file(path: Path, owner: Account | None, readers: frozenset[str], *, root: Path) -> None:
    """Make `path` owner-only (`0600`, or on Windows an ACL of exactly the operator, Administrators and `readers`).

    Refuses a symlink: the guarantee would otherwise be made about a different file than the one the operator hardened.
    """
    if sys.platform == "win32":
        from ctl import perms_windows

        perms_windows.harden_file(path, owner, readers, root)
        return
    fd = _open(path, os.O_RDONLY)
    try:
        _require_sole_regular_file(fd, path)
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
    root: Path,
) -> None:
    """Create `path` if absent and reassert its owner and mode, whatever state it was left in.

    Leaving an existing directory alone is wrong here: another account that owns, or can write to, `secrets/` can
    replace the token inside it regardless of the token's own mode. A symlink at `path` is refused, never repaired.
    On Windows `isolate` breaks inheritance; only `.env`, `secrets/` and the token do, never the repository root.
    """
    if sys.platform == "win32":
        from ctl import perms_windows

        perms_windows.converge_dir(path, owner, readers, writers, isolate, root)
        return
    with _converged(path, owner, mode):
        pass


def converge_tree(path: Path, owner: Account | None, mode: int, *, root: Path) -> None:
    """`converge_dir` for `path`, then the same for each of its direct entries, keeping each entry's own mode.

    The directory is flat. Every entry must be a regular file with one name; anything else (a subdirectory, a symlink or
    reparse point, a FIFO, a socket, a hard-linked file, on POSIX a file on another filesystem) is refused with a message
    telling the operator to remove it, and is never entered. A service that can write `logs/` could otherwise plant a link
    or a hard link to a file it does not own and have root change it.

    systemd opens a log's append target after dropping to `User=`, so a stale owner is `EACCES` and the daemon never
    starts. On Windows `owner` is the service account, which gets modify on the directory, and each entry is reset to
    inherit from it.
    """
    if sys.platform == "win32":
        from ctl import perms_windows

        perms_windows.converge_tree(path, owner, root)
        return
    with _converged(path, owner, mode) as fd:
        _converge_entries(fd, path, owner)


def grant_service_read(root: Path, account: Account) -> None:
    """Give `account` read-and-execute on the repository `root`, `bin`, `host` and their direct files; POSIX: nothing.

    `root` gets an inheritable ACE and each of the others the ACE it would inherit, written to it directly: nothing is
    propagated by the OS, so nothing unvetted is touched. A subdirectory, reparse point or hard-linked file inside `bin`
    or `host` is refused. Ancestors of `root` get no ACE: `LocalService` holds `SeChangeNotifyPrivilege`, which bypasses
    traverse checking, so a repository under a user profile is reachable without exposing the profile.
    """
    if sys.platform != "win32":
        return
    from ctl import perms_windows

    perms_windows.grant_service_read(root, account)


# Inspection ===========================================================================================================


def _owner_name(uid: int) -> str:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _read_acl(path: Path) -> winacl.Acl:
    try:
        return winacl.read_acl(path)
    except OSError as exc:
        raise PermsError(f"{path}: {exc.strerror or exc}") from exc


def principals(path: Path) -> frozenset[str]:
    """Everything `path` grants: its SIDs on Windows, `owner=<name>` and `mode=<octal>` on POSIX.

    Doctor compares this against the exact expected set, so an unexpected principal is a failure.
    """
    if sys.platform == "win32":
        return _read_acl(path).sids
    status = os.lstat(path)
    return frozenset({f"owner={_owner_name(status.st_uid)}", f"mode={stat.S_IMODE(status.st_mode):04o}"})


def describe(path: Path) -> str:
    """`principals` for a human."""
    if sys.platform == "win32":
        acl = _read_acl(path)
        inheritance = "inheritance broken" if acl.protected else "inheritance enabled"
        return f"grants {', '.join(sorted(acl.sids))}; {inheritance}"
    status = os.lstat(path)
    return f"owner {_owner_name(status.st_uid)}, mode {stat.S_IMODE(status.st_mode):04o}"
