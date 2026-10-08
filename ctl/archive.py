# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Archive shapes, and reading one regular file out of an archive: hashing it, or copying it to a fresh target.

Neither ever uses an archive's own paths to create anything on disk, so a hostile entry has nothing to write through.
It still refuses the whole archive for one: a link, a special file, an unsafe name, or two entries a case-insensitive
or Windows extraction would merge. The same scan serves `refresh` and `fetch`, so a pin that is accepted is fetchable.
"""

import contextlib
import enum
import hashlib
import lzma
import os
import stat
import tarfile
import unicodedata
import zipfile
import zlib
from collections import Counter
from collections.abc import Callable, Iterator
from functools import partial
from typing import IO, Literal, TypeVar
from pathlib import Path, PurePosixPath, PureWindowsPath

from ctl.atomic import CHUNK, deferred_interrupts
from ctl.errors import BinariesError


class ArchiveFormat(enum.StrEnum):
    TAR_GZ = "tar.gz"
    TAR_XZ = "tar.xz"
    ZIP = "zip"
    BARE = "bare"


TAR_MODES: dict[ArchiveFormat, Literal["r:gz", "r:xz"]] = {
    ArchiveFormat.TAR_GZ: "r:gz",
    ArchiveFormat.TAR_XZ: "r:xz",
}
T = TypeVar("T")


def is_safe_member(name: str) -> bool:
    """A relative, forward-slash path with no `..`, so it cannot name anything outside a destination."""
    if not name or "\\" in name or "\0" in name:
        return False
    if PurePosixPath(name).is_absolute() or PureWindowsPath(name).drive:
        return False
    return ".." not in PurePosixPath(name).parts


def hash_binary(path: Path, fmt: ArchiveFormat, filename: str) -> tuple[str, str]:
    """The full in-archive path and sha256 of the one regular file named `filename`.

    Streams the member and writes nothing. Links and directories never count as a match, and a match is refused if
    any other entry of any type shares its path, so extraction cannot land on something other than what was hashed.
    """
    if fmt is ArchiveFormat.BARE:
        raise ValueError("a bare binary has no archive to read")
    what = f"regular file named {filename}"
    return _find(path, fmt, lambda name: PurePosixPath(name).name == filename, _sha256, what)


def extract_member(path: Path, fmt: ArchiveFormat, member: str, target: Path) -> str:
    """Copy the one regular file at the in-archive path `member` to the new file `target`; returns its sha256.

    `target` must not exist and its parent must be a real directory (not a link). Only `target` is ever created, and
    on any failure it is removed, so nothing is left behind.
    """
    if fmt is ArchiveFormat.BARE:
        raise ValueError("a bare binary has no archive to read")
    if not is_safe_member(member):
        raise BinariesError(f"{path.name}: unsafe member path {member!r}")
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise BinariesError(f"{target}: the parent must be an existing directory and not a link")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    copied: list[str] = []
    fd, out, created = -1, None, False

    def copy(stream: IO[bytes]) -> str:
        if copied:
            raise BinariesError(f"{path.name}: more than one regular file at {member!r}")
        copied.append(member)
        assert out is not None
        return _copy_hashing(stream, out)

    try:
        with deferred_interrupts():  # creating, writing and cleaning up are one unit
            try:
                fd = os.open(target, flags, 0o600)
                created = True
                out = os.fdopen(fd, "wb")
                _, digest = _find(path, fmt, lambda name: name == member, copy, f"regular file at {member!r}")
                _flush(out)
                _close(out)
            except BaseException:
                if out is not None:
                    with contextlib.suppress(
                        OSError, ValueError
                    ):  # already closed, or closing again fails the same way
                        out.close()
                elif fd >= 0:
                    os.close(fd)
                if created:
                    target.unlink(missing_ok=True)
                raise
    except KeyboardInterrupt:
        if created:  # a Ctrl-C deferred until the copy had finished: the caller is leaving, so leave nothing
            with deferred_interrupts():
                target.unlink(missing_ok=True)
        raise
    return digest


def _find(path: Path, fmt: ArchiveFormat, select: Callable[[str], bool], consume: Callable[[IO[bytes]], T],
          what: str) -> tuple[str, T]:
    """Walk every entry once, `consume` the one regular file `select` picks, and refuse any hostile entry."""
    matches: list[tuple[str, T]] = []
    keys: Counter[tuple[str, ...]] = Counter()
    try:
        for name, kind, open_entry in _entries(path, fmt):
            _refuse_unsafe(path, name, kind)
            keys[_collision_key(name)] += 1
            if kind == "file" and select(name):
                with open_entry() as stream:
                    matches.append((name, consume(stream)))
    except (
        tarfile.TarError, zipfile.BadZipFile, lzma.LZMAError, zlib.error, EOFError, OSError, RuntimeError,
        NotImplementedError
    ) as exc:
        raise BinariesError(f"{path.name}: not a readable {fmt} archive: {exc}") from exc
    if not matches:
        raise BinariesError(f"{path.name}: no {what}")
    if len(matches) > 1:
        raise BinariesError(f"{path.name}: more than one {what}: {', '.join(name for name, _ in matches)}")
    ((member, result), ) = matches
    if keys[_collision_key(member)] > 1:
        raise BinariesError(f"{path.name}: more than one entry at {member!r}")
    return member, result


def _entries(path: Path, fmt: ArchiveFormat) -> Iterator[tuple[str, str, Callable[[], IO[bytes]]]]:
    """Each entry's name, its kind (`file`, `dir`, `link` or `other`) and a way to open its content."""
    if fmt is ArchiveFormat.ZIP:
        with zipfile.ZipFile(path) as zipped:
            for entry in zipped.infolist():
                yield entry.filename, _zip_kind(entry), partial(zipped.open, entry)
    else:
        with tarfile.open(path, TAR_MODES[fmt]) as tarred:
            for member in tarred:
                yield member.name, _tar_kind(member), partial(_tar_stream, tarred, member)


def _tar_kind(member: tarfile.TarInfo) -> str:
    if member.isreg():
        return "file"
    if member.isdir():
        return "dir"
    return "link" if member.issym() or member.islnk() else "other"


def _tar_stream(archive: tarfile.TarFile, member: tarfile.TarInfo) -> IO[bytes]:
    stream = archive.extractfile(member)
    assert stream is not None
    return stream


def _zip_kind(entry: zipfile.ZipInfo) -> str:
    """Zip stores a unix file type in the high attribute bits, or none at all when written on Windows."""
    file_type = stat.S_IFMT(entry.external_attr >> 16)
    if file_type == stat.S_IFLNK:
        return "link"
    if entry.is_dir() or file_type == stat.S_IFDIR:
        return "dir"
    return "file" if file_type in (0, stat.S_IFREG) else "other"


def _refuse_unsafe(path: Path, name: str, kind: str) -> None:
    if not is_safe_member(name):
        raise BinariesError(f"{path.name}: unsafe entry name {name!r}")
    if kind == "link":
        raise BinariesError(f"{path.name}: {name!r} is a link; no release ships one")
    if kind == "other":
        raise BinariesError(f"{path.name}: {name!r} is neither a file nor a directory")


def _collision_key(name: str) -> tuple[str, ...]:
    """The path as a case-insensitive, normalization-insensitive filesystem that drops trailing dots and spaces sees it."""
    parts = PurePosixPath(name).parts
    return tuple(
        unicodedata.normalize("NFD",
                              unicodedata.normalize("NFD", part).casefold()).rstrip(". ") for part in parts
    )


def _copy_hashing(stream: IO[bytes], out: IO[bytes]) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK):
        digest.update(chunk)
        try:
            out.write(chunk)
        except OSError as exc:
            raise BinariesError(f"cannot write the extracted file: {exc}") from exc
    return digest.hexdigest()


def _close(out: IO[bytes]) -> None:
    try:
        out.close()
    except OSError as exc:
        raise BinariesError(f"cannot write the extracted file: {exc}") from exc


def _flush(out: IO[bytes]) -> None:
    try:
        out.flush()
    except OSError as exc:
        raise BinariesError(f"cannot write the extracted file: {exc}") from exc


def hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        return _sha256(stream)


def _sha256(stream: IO[bytes]) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK):
        digest.update(chunk)
    return digest.hexdigest()
