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
import stat
import sys
from pathlib import Path
from typing import IO

from ctl.archive import CHUNK
from ctl.errors import BinariesError

DEFAULT_MODE = 0o644
PERMISSION_BITS = 0o777  # a carried-over mode never keeps setuid, setgid or sticky
O_BINARY = getattr(os, "O_BINARY", 0)


def is_link(status: os.stat_result) -> bool:
    return stat.S_ISLNK(
        status.st_mode
    ) or bool(getattr(status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def require_directory(directory: Path) -> None:
    """Raise `BinariesError` unless `directory` is a real directory and not a link."""
    if sys.platform == "win32":
        from ctl import _winfile as winfile

        winfile.close_handle(_open_directory_windows(directory, winfile))
    else:
        os.close(_open_directory(directory))


def replace_file(directory: Path, name: str, source: IO[bytes], mode: int | None) -> Path:
    """Atomically make `directory/name` hold the bytes of `source`, with `mode` (kept from the old file if `None`).

    A symlink, a directory or anything else that is not a regular file at `name` is refused, never followed. Nothing but
    the old file or the complete new one is ever visible, and a failure leaves no temporary behind. On POSIX the mode is
    set on the open descriptor before the first byte, so the umask never matters; Windows has no mode to set.
    """
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise BinariesError(f"{directory / name}: not a single directory entry name")
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
    if sys.platform == "win32":
        return _read_windows(directory, name)
    return _read_posix(directory, name)


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


def _open_directory_windows(directory: Path, winfile, *, missing_ok: bool = False) -> int:
    """The directory as a held handle: no reparse point, and nobody can rename or delete it while it is held."""
    try:
        return winfile.open_handle(
            directory,
            access=winfile.FILE_ADD_FILE | winfile.FILE_LIST_DIRECTORY,
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
    created = ctypes.c_void_p()  # the kernel writes the new file's handle here, so no interrupt can lose it
    fd = -1
    renaming = False
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
        _write(fd, source)
        os.fsync(fd)
        renaming = True  # from here the handle may name the destination, which must never be deleted
        try:
            winfile.rename_over(msvcrt.get_osfhandle(fd), handle, name, label=directory / name, error=BinariesError)
        except Exception:
            renaming = False
            raise
        os.close(fd)
        fd = -1
    except BaseException:
        _discard_windows(fd, created, renaming, winfile)
        raise
    finally:
        winfile.close_handle(handle)


def _discard_windows(fd: int, created: ctypes.c_void_p, renaming: bool, winfile) -> None:
    """Delete the temporary through its own handle, then close it; nothing is resolved by path."""
    import msvcrt

    owned = created.value
    with contextlib.suppress(OSError):
        owned = msvcrt.get_osfhandle(fd) if fd >= 0 else created.value
    if owned is not None and not renaming:
        with contextlib.suppress(OSError):
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
        handle = _open_directory_windows(directory, winfile, missing_ok=True)
    except FileNotFoundError:
        return None
    try:
        try:
            file = winfile.open_relative(
                handle, name, label=directory / name, access=winfile.GENERIC_READ, directory=False, error=BinariesError
            )
        except FileNotFoundError:
            return None
        fd = msvcrt.open_osfhandle(file, os.O_RDONLY | O_BINARY)
        with os.fdopen(fd, "rb") as stream:
            return stream.read()
    finally:
        winfile.close_handle(handle)
