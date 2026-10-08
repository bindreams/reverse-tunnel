# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Replacing one file in a directory without ever following a link, for code that runs as root in an operator's tree.

On POSIX the directory is opened once with `O_NOFOLLOW` and everything after is relative to that descriptor, so a path
swapped for a symlink afterwards changes nothing. Windows has no equivalent: there the directory and the destination
are checked for reparse points before use.
"""

import os
import secrets
import stat
import sys
from typing import IO

from pathlib import Path

from ctl.archive import CHUNK
from ctl.errors import BinariesError

DEFAULT_MODE = 0o644
O_BINARY = getattr(os, "O_BINARY", 0)


def is_link(status: os.stat_result) -> bool:
    return stat.S_ISLNK(
        status.st_mode
    ) or bool(getattr(status, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def open_directory(directory: Path) -> int | None:
    """A descriptor for `directory`, which must be a real directory and not a link; `None` on Windows."""
    if sys.platform == "win32":
        try:
            status = os.lstat(directory)
        except OSError as exc:
            raise BinariesError(f"{directory}: not an existing directory: {exc.strerror or exc}") from exc
        if is_link(status) or not stat.S_ISDIR(status.st_mode):
            raise BinariesError(f"{directory}: must be a directory and not a link")
        return None
    try:
        return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        try:
            linked = stat.S_ISLNK(os.lstat(directory).st_mode)
        except OSError:
            linked = False
        what = "is a link; refusing to follow it" if linked else f"not an existing directory: {exc.strerror or exc}"
        raise BinariesError(f"{directory}: {what}") from exc


def require_directory(directory: Path) -> None:
    """Raise `BinariesError` unless `directory` is a real directory and not a link."""
    fd = open_directory(directory)
    if fd is not None:
        os.close(fd)


def replace_file(directory: Path, name: str, source: IO[bytes], mode: int | None) -> Path:
    """Atomically make `directory/name` hold the bytes of `source`, with `mode` (kept from the old file if `None`).

    A symlink, a directory or anything else that is not a regular file at `name` is refused, never followed. The mode is
    set on the open descriptor before the first byte, so the umask and a racing observer never matter. Nothing but the
    old file or the complete new one is ever visible, and a failure leaves no temporary behind.
    """
    dir_fd = open_directory(directory)
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"

    def at(entry: str) -> str:
        return entry if dir_fd is not None else str(directory / entry)

    fd = -1
    try:
        try:
            status = os.lstat(at(name), dir_fd=dir_fd)
        except FileNotFoundError:
            status = None
        if status is not None:
            if is_link(status):
                raise BinariesError(f"{directory / name}: is a link; refusing to replace it")
            if not stat.S_ISREG(status.st_mode):
                raise BinariesError(f"{directory / name}: not a regular file")
        if mode is None:
            mode = stat.S_IMODE(status.st_mode) if status is not None else DEFAULT_MODE
        try:
            fd = os.open(
                at(temporary),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BINARY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=dir_fd
            )
        except FileExistsError:
            temporary = ""  # not ours: leave it alone
            raise
        if sys.platform != "win32":
            os.fchmod(fd, mode)
        while chunk := source.read(CHUNK):
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(at(temporary), at(name), src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        if dir_fd is not None:
            os.fsync(dir_fd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(at(temporary), dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return directory / name
