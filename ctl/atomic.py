# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Replacing one file in a directory without ever following a link, for code that runs as root in an operator's tree.

The directory is opened once, refusing a link, and everything after is relative to that open directory: a descriptor with
`O_NOFOLLOW` on POSIX, a handle vetted by `ctl._winfile` on Windows. A path swapped for a symlink afterwards changes
nothing.
"""

import contextlib
import ctypes
import os
import secrets
import signal
import stat
import sys
import threading
from collections.abc import Generator
from pathlib import Path
from types import FrameType
from typing import IO

from ctl.errors import BinariesError
from ctl.perms import Account

CHUNK = 1 << 20
DEFAULT_MODE = 0o644
PERMISSION_BITS = 0o777  # a carried-over mode never keeps setuid, setgid or sticky
O_BINARY = getattr(os, "O_BINARY", 0)


def is_link(status: os.stat_result) -> bool:
    return stat.S_ISLNK(
        status.st_mode
    ) or bool(getattr(status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


DEFERRED_SIGNALS = ("SIGINT", "SIGBREAK")  # SIGBREAK exists on Windows only
_holding = False  # whether the main thread is inside an outermost `deferred_interrupts` block


@contextlib.contextmanager
def deferred_interrupts() -> Generator[None]:
    """Hold Ctrl-C (and Ctrl-Break on Windows) until the block ends, then raise `KeyboardInterrupt` if one arrived.

    A block that creates, writes, renames and cleans up files must not be torn in the middle: an interrupt between a
    system call returning and its result being stored would leak a handle or a temporary no matter how the code is
    ordered. The previous handlers are restored on exit, last installed first, and every restore runs even if one fails.
    Signals can only be handled on the main thread, so elsewhere the block simply runs; a signal whose handler is
    `SIG_IGN` stays ignored. Blocks nest: an inner one leaves the interrupt to the outermost, which alone raises.
    """
    global _holding
    if threading.current_thread() is not threading.main_thread() or _holding:
        yield
        return
    arrived: list[int] = []

    def record(number: int, frame: FrameType | None) -> None:
        arrived.append(number)

    _holding = True
    try:
        with contextlib.ExitStack() as restore:
            for name in DEFERRED_SIGNALS:
                number = getattr(signal, name, None)
                if number is not None and signal.getsignal(number) != signal.SIG_IGN:
                    previous = signal.signal(number, record)
                    restore.callback(signal.signal, number, signal.SIG_DFL if previous is None else previous)
            yield
    finally:
        _holding = False
        if arrived:
            raise KeyboardInterrupt


def require_directory(directory: Path) -> None:
    """Raise `BinariesError` unless `directory` is a real directory and not a link."""
    if sys.platform == "win32":
        from ctl import _winfile as winfile

        winfile.close_handle(_open_directory_windows(directory, winfile))
    else:
        os.close(_open_directory(directory))


def replace_file(
    directory: Path, name: str, source: IO[bytes], mode: int | None, *, service: Account | None = None
) -> Path:
    """Atomically make `directory/name` hold the bytes of `source`, with `mode` (kept from the old file if `None`).

    A symlink, a directory or anything else that is not a regular file at `name` is refused, never followed. Nothing but
    the old file or the complete new one is ever visible, and a failure leaves no temporary behind. On POSIX the mode is
    set on the open descriptor before the first byte, so the umask never matters; Windows has no mode to set.
    """
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise BinariesError(f"{directory / name}: not a single directory entry name")
    with deferred_interrupts():
        if sys.platform == "win32":
            _replace_windows(directory, name, source)
        else:
            _replace_posix(directory, name, source, mode)
    return directory / name


def read_file(directory: Path, name: str) -> bytes | None:
    """The bytes of the regular file `directory/name`, or `None` if the directory or the file does not exist.

    Like `replace_file`, nothing is followed: a link in place of the directory or the file is refused, and the file is
    opened relative to the open directory.
    """
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise BinariesError(f"{directory / name}: not a single directory entry name")
    with deferred_interrupts():
        return _read_windows(directory, name) if sys.platform == "win32" else _read_posix(directory, name)


# POSIX ================================================================================================================


def _open_directory(directory: Path, *, missing_ok: bool = False) -> int:
    try:
        return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if missing_ok:
            raise
        raise BinariesError(f"{directory}: not an existing directory") from None
    except OSError as exc:
        try:
            linked = stat.S_ISLNK(os.lstat(directory).st_mode)
        except OSError:
            linked = False
        what = "is a link; refusing to follow it" if linked else f"not an existing directory: {exc.strerror or exc}"
        raise BinariesError(f"{directory}: {what}") from exc


def _replace_posix(directory: Path, name: str, source: IO[bytes], mode: int | None) -> None:
    dir_fd = _open_directory(directory)
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    fd = -1
    try:
        try:
            status = os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            status = None
        if status is not None:
            if is_link(status):
                raise BinariesError(f"{directory / name}: is a link; refusing to replace it")
            if not stat.S_ISREG(status.st_mode):
                raise BinariesError(f"{directory / name}: not a regular file")
        if mode is None:
            mode = stat.S_IMODE(status.st_mode) & PERMISSION_BITS if status is not None else DEFAULT_MODE
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        except FileExistsError:
            temporary = ""  # not ours: leave it alone
            raise
        os.fchmod(fd, mode)
        _write(fd, source)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(dir_fd)


def _read_posix(directory: Path, name: str) -> bytes | None:
    try:
        dir_fd = _open_directory(directory, missing_ok=True)
    except FileNotFoundError:
        return None
    try:
        try:
            status = os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        if is_link(status):
            raise BinariesError(f"{directory / name}: is a link; refusing to follow it")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BinariesError(f"{directory / name}: {exc.strerror or exc}") from exc
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise BinariesError(f"{directory / name}: not a regular file")
            return stream.read()
    finally:
        os.close(dir_fd)


def _write(fd: int, source: IO[bytes]) -> None:
    while chunk := source.read(CHUNK):
        view = memoryview(chunk)
        while view:
            view = view[os.write(fd, view):]


# Windows ==============================================================================================================


def _open_directory_windows(directory: Path, winfile, *, missing_ok: bool = False, access: int | None = None) -> int:
    """The directory as a held handle: no reparse point, and nobody can rename or delete it while it is held."""
    try:
        return winfile.open_handle(
            directory,
            access=winfile.FILE_ADD_FILE | winfile.FILE_LIST_DIRECTORY if access is None else access,
            disposition=winfile.OPEN_EXISTING,
            directory=True,
            error=BinariesError,
            share=winfile.FILE_SHARE_READ_WRITE,
        )
    except FileNotFoundError:
        if missing_ok:
            raise
        raise BinariesError(f"{directory}: not an existing directory") from None
    except OSError as exc:
        raise BinariesError(f"{directory}: not an existing directory: {exc.strerror or exc}") from exc


def _replace_windows(directory: Path, name: str, source: IO[bytes]) -> None:
    import msvcrt

    from ctl import _winfile as winfile

    handle = _open_directory_windows(directory, winfile)
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    created = ctypes.c_void_p()  # the kernel writes the new file's handle here
    fd = -1
    try:
        _vet_destination(handle, directory, name, winfile)
        winfile.create_relative(
            handle,
            temporary,
            label=directory / temporary,
            access=winfile.GENERIC_WRITE | winfile.DELETE,
            error=BinariesError,
            into=created
        )
        assert created.value is not None
        fd = msvcrt.open_osfhandle(created.value, os.O_WRONLY | O_BINARY)  # the descriptor now owns the handle
        created.value = None
        _write(fd, source)
        os.fsync(fd)
        winfile.rename_over(msvcrt.get_osfhandle(fd), handle, name, label=directory / name, error=BinariesError)
        os.close(fd)
        fd = -1
    except BaseException:
        _discard_windows(fd, created, temporary, winfile)
        raise
    finally:
        winfile.close_handle(handle)


def _discard_windows(fd: int, created: ctypes.c_void_p, temporary: str, winfile) -> None:
    """Delete the temporary through its own handle, then close it; nothing is resolved by path.

    The handle is asked for its name rather than trusting a record of what was done: only a file still called
    `temporary` is deleted, so a completed rename can never take the destination with it.
    """
    import msvcrt

    owned = created.value
    with contextlib.suppress(OSError):
        if fd >= 0:
            owned = msvcrt.get_osfhandle(fd)
    if owned is not None:
        with contextlib.suppress(OSError):
            if winfile.final_name(owned) == temporary:
                winfile.delete_now(owned)
    if fd >= 0:
        os.close(fd)
    elif created.value is not None:
        winfile.close_handle(created.value)


def _vet_destination(handle: int, directory: Path, name: str, winfile) -> None:
    """Refuse an existing destination that is a reparse point, not a regular file, or has more than one name."""
    try:
        existing = winfile.open_relative(
            handle, name, label=directory / name, access=0, directory=False, error=BinariesError, single_link=True
        )
    except FileNotFoundError:
        return
    winfile.close_handle(existing)


def _read_windows(directory: Path, name: str) -> bytes | None:
    import msvcrt

    from ctl import _winfile as winfile

    try:
        handle = _open_directory_windows(
            directory, winfile, missing_ok=True, access=winfile.FILE_LIST_DIRECTORY | winfile.READ_CONTROL
        )
    except FileNotFoundError:
        return None
    try:
        try:
            file = winfile.open_relative(
                handle, name, label=directory / name, access=winfile.GENERIC_READ, directory=False, error=BinariesError
            )
        except FileNotFoundError:
            return None
        try:
            fd = msvcrt.open_osfhandle(file, os.O_RDONLY | O_BINARY)
        except BaseException:
            winfile.close_handle(file)
            raise
        with os.fdopen(fd, "rb") as stream:
            return stream.read()
    finally:
        winfile.close_handle(handle)
