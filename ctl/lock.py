# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""One install or uninstall at a time, and the detached child as the same one.

The lock is a file at the repository root. It is taken without waiting: a second run fails at once and says what holds
the lock, rather than queueing behind something that may be running for minutes with nobody watching.

The detached apply phase has to keep the lock when its parent exits, so the parent never releases it explicitly. It
passes the descriptor to the child, which holds the same open file description (POSIX `flock`) or the same handle
(Windows, where the file is opened with no sharing, so a second open fails for as long as any process holds a handle to
it). Closing the parent's copy then changes nothing.
"""

import dataclasses
import datetime
import errno
import os
import stat
import sys
from pathlib import Path
from types import TracebackType
from typing import Self

from ctl.errors import InstallError

LOCK_NAME = ".install.lock"
LOCK_MODE = 0o640
HOLDER_BYTES = 200


@dataclasses.dataclass
class InstallLock:
    """A held lock: a file descriptor on POSIX, a handle on Windows."""

    descriptor: int
    closed: bool = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if sys.platform == "win32":
            from ctl import _winfile

            _winfile.close_handle(self.descriptor)
        else:
            os.close(self.descriptor)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        self.close()


def _running(root: Path, holder: str) -> InstallError:
    return InstallError(
        f"another `ctl` install or uninstall is already running in {root}{f' ({holder})' if holder else ''}. Wait for it "
        "to finish; if it was started with --allow-self-disconnect its progress is in install.log"
    )


def _holder_text(command: str) -> str:
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    return f"pid {os.getpid()}: ctl {command}, started {now}\n"


# POSIX ================================================================================================================


def _open_root(root: Path) -> int:
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise InstallError(f"{root}: {exc.strerror or exc}") from exc


def _vet(fd: int, path: Path) -> os.stat_result:
    status = os.fstat(fd)
    if not stat.S_ISREG(status.st_mode):
        raise InstallError(f"{path}: not a regular file; remove it")
    if status.st_nlink > 1:
        raise InstallError(f"{path}: has {status.st_nlink} hard links; remove the other names")
    return status


def _hand_to_operator(fd: int, root: Path, status: os.stat_result) -> None:
    """Whoever created the file, it belongs to the repository's owner, who runs `doctor` and cleans up."""
    owner = os.stat(root)
    if (status.st_uid, status.st_gid) != (owner.st_uid, owner.st_gid) and os.geteuid() == 0:
        os.fchown(fd, owner.st_uid, owner.st_gid)
    if stat.S_IMODE(status.st_mode) != LOCK_MODE:
        os.fchmod(fd, LOCK_MODE)


def _flock(fd: int) -> bool:
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _announce(fd: int, command: str) -> None:
    os.ftruncate(fd, 0)
    os.pwrite(fd, _holder_text(command).encode(), 0)


def _acquire_posix(root: Path, command: str) -> InstallLock:
    path = root / LOCK_NAME
    directory = _open_root(root)
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY
        try:
            fd = os.open(LOCK_NAME, flags, LOCK_MODE, dir_fd=directory)
        except OSError as exc:
            if exc.errno == errno.ELOOP:  # a symlink
                raise InstallError(f"{path}: is a symlink; refusing to follow it. Remove it") from exc
            raise InstallError(f"{path}: {exc.strerror or exc}") from exc
    finally:
        os.close(directory)
    try:
        _hand_to_operator(fd, root, _vet(fd, path))
        if not _flock(fd):
            holder = os.pread(fd, HOLDER_BYTES, 0).decode(errors="replace").strip()
            raise _running(root, holder)
        _announce(fd, command)
    except BaseException:
        os.close(fd)
        raise
    return InstallLock(fd)


def _adopt_posix(root: Path, descriptor: int, command: str) -> InstallLock:
    path = root / LOCK_NAME
    try:
        inherited, named = os.fstat(descriptor), os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise InstallError(f"descriptor {descriptor} is not the install lock {path}: {exc.strerror or exc}") from exc
    if (inherited.st_dev, inherited.st_ino) != (named.st_dev, named.st_ino):
        raise InstallError(f"descriptor {descriptor} is not the install lock {path}")
    if not _flock(descriptor):
        raise InstallError(f"descriptor {descriptor} does not hold the install lock {path}; another run holds it")
    _announce(descriptor, command)
    return InstallLock(descriptor)


# Windows ==============================================================================================================


def _acquire_windows(root: Path, command: str) -> InstallLock:
    from ctl import _winfile as winfile

    path = root / LOCK_NAME
    try:
        handle = winfile.open_handle(
            path,
            access=winfile.GENERIC_READ | winfile.GENERIC_WRITE,
            disposition=winfile.OPEN_ALWAYS,
            directory=False,
            error=InstallError,
            single_link=True,
            share=0,  # nobody else may open it while this handle, or an inherited copy of it, exists
        )
    except OSError as exc:
        if getattr(exc, "winerror", None) in (32, 33):  # sharing and lock violations
            raise _running(root, "") from exc
        raise InstallError(f"{path}: {exc.strerror or exc}") from exc
    return InstallLock(handle)


def _adopt_windows(root: Path, descriptor: int, command: str) -> InstallLock:
    return InstallLock(descriptor)  # the handle the parent made inheritable; there is nothing to re-acquire


# Entry points =========================================================================================================


def acquire(root: Path, *, command: str) -> InstallLock:
    """Take the lock now or raise `InstallError` naming what holds it. Never waits."""
    return _acquire_windows(root, command) if sys.platform == "win32" else _acquire_posix(root, command)


def adopt(root: Path, descriptor: int, *, command: str) -> InstallLock:
    """Take over the lock a parent passed down as `descriptor`, after checking that it is the lock and is held."""
    return _adopt_windows(root, descriptor,
                          command) if sys.platform == "win32" else _adopt_posix(root, descriptor, command)
