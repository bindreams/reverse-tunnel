# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Removing a directory that `install` created, without ever following a link or entering a mount.

`secrets/`, `bin/` and `logs/` are flat: files and nothing else. So the removal is flat too. It unlinks each entry and
`rmdir`s each subdirectory, but never descends into one: a bind mount inside the tree answers `rmdir` with `EBUSY`
before any of its contents is touched, where a recursive delete would have emptied the mounted filesystem first.
Everything is relative to a descriptor (POSIX) or a vetted handle (Windows), so a path swapped for a link afterwards
changes nothing.
"""

import errno
import os
import stat
import sys
from pathlib import Path

from ctl.errors import InstallError

MANUAL = "remove it yourself"


def remove_directory(parent: Path, name: str) -> bool:
    """Remove `parent/name` and its direct entries; False when it is absent.

    A symlink, a file, or a subdirectory that is not empty is an `InstallError` and nothing past it is removed.
    """
    if sys.platform == "win32":
        return _remove_windows(parent, name)
    return _remove_posix(parent, name)


# POSIX ================================================================================================================


def _symlink(path: Path) -> InstallError:
    return InstallError(f"{path}: is a symlink; refusing to remove through it ({MANUAL} if the link itself should go)")


def _open_directory(path: Path, *, dir_fd: int | None = None, name: str | None = None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        return os.open(path if dir_fd is None else str(name), flags, dir_fd=dir_fd)
    except OSError as exc:
        # An open that refused a link is the guarantee; the `lstat` only picks the words for it.
        try:
            linked = stat.S_ISLNK(os.lstat(path).st_mode)
        except OSError:
            linked = False
        if linked or exc.errno in (errno.ELOOP, errno.EMLINK):
            raise _symlink(path) from exc
        raise InstallError(f"{path}: {exc.strerror or exc}") from exc


def _remove_posix(parent: Path, name: str) -> bool:
    parent_fd = _open_directory(parent)
    path = parent / name
    try:
        try:
            status = os.lstat(name, dir_fd=parent_fd)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(status.st_mode):
            raise _symlink(path)
        if not stat.S_ISDIR(status.st_mode):
            raise InstallError(f"{path}: not a directory ({MANUAL})")
        fd = _open_directory(path, dir_fd=parent_fd, name=name)
        try:
            _empty(fd, path)
        finally:
            os.close(fd)
        _rmdir(path, name, parent_fd)
        return True
    finally:
        os.close(parent_fd)


def _empty(directory_fd: int, path: Path) -> None:
    with os.scandir(directory_fd) as scan:
        names = [entry.name for entry in scan]
    for entry in names:
        try:
            status = os.lstat(entry, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        try:
            if stat.S_ISDIR(status.st_mode):
                os.rmdir(entry, dir_fd=directory_fd)
            else:
                os.unlink(entry, dir_fd=directory_fd)  # a link is unlinked itself, never followed
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise InstallError(f"{path / entry}: {exc.strerror or exc}; it must be empty, {MANUAL}") from exc


def _rmdir(path: Path, name: str, parent_fd: int) -> None:
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise InstallError(f"{path}: {exc.strerror or exc}") from exc


# Windows ==============================================================================================================


def _remove_windows(parent: Path, name: str) -> bool:
    from ctl import _winfile as winfile

    try:
        held = winfile.open_handle(
            parent,
            access=winfile.FILE_LIST_DIRECTORY,
            disposition=winfile.OPEN_EXISTING,
            directory=True,
            error=InstallError,
            share=winfile.FILE_SHARE_READ_WRITE,
        )
    except OSError as exc:
        raise InstallError(f"{parent}: {exc.strerror or exc}") from exc
    try:
        wanted = [listed for listed in winfile.list_names(held) if listed.casefold() == name.casefold()]
        if not wanted:
            return False
        if len(wanted) > 1:
            raise InstallError(f"{parent}: holds {' and '.join(wanted)}; ambiguous, {MANUAL}")
        path = parent / wanted[0]
        directory = winfile.open_relative(
            held,
            wanted[0],
            label=path,
            access=winfile.FILE_LIST_DIRECTORY | winfile.DELETE,
            directory=True,
            error=InstallError
        )
        try:
            for entry in winfile.list_names(directory):
                _delete_entry_windows(winfile, directory, entry, path / entry)
            _delete_windows(winfile, directory, path)
        finally:
            winfile.close_handle(directory)
        return True
    finally:
        winfile.close_handle(held)


def _delete_entry_windows(winfile, directory: int, entry: str, path: Path) -> None:
    """Delete one entry through a handle opened relative to its directory. Which kind it is only picks the open."""
    try:
        is_directory = stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return
    handle = winfile.open_relative(
        directory, entry, label=path, access=winfile.DELETE, directory=is_directory, error=InstallError
    )
    try:
        _delete_windows(winfile, handle, path, hint=f"it must be empty, {MANUAL}" if is_directory else MANUAL)
    finally:
        winfile.close_handle(handle)


def _delete_windows(winfile, handle: int, path: Path, hint: str = "") -> None:
    try:
        winfile.delete_now(handle)
    except OSError as exc:
        raise InstallError(f"{path}: {exc.strerror or exc}" + (f"; {hint}" if hint else "")) from exc
