# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Archive shapes and reading a binary's digest out of one without extracting anything."""

import enum
import hashlib
import lzma
import stat
import tarfile
import zipfile
import zlib
from typing import IO, Literal
from pathlib import Path, PurePosixPath, PureWindowsPath

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
CHUNK = 1 << 20


def is_safe_member(name: str) -> bool:
    """A relative, forward-slash path with no `..`, so it cannot name anything outside a destination."""
    if not name or "\\" in name or "\0" in name:
        return False
    if PurePosixPath(name).is_absolute() or PureWindowsPath(name).drive:
        return False
    return ".." not in PurePosixPath(name).parts


def hash_binary(path: Path, fmt: ArchiveFormat, filename: str) -> tuple[str, str]:
    """The full in-archive path and sha256 of the one regular file named `filename`.

    Streams the member and writes nothing. Links and directories never count as a match.
    """
    if fmt is ArchiveFormat.BARE:
        raise ValueError("a bare binary has no archive to read")
    try:
        matches = _zip_matches(path, filename) if fmt is ArchiveFormat.ZIP else _tar_matches(path, fmt, filename)
    except (tarfile.TarError, zipfile.BadZipFile, lzma.LZMAError, zlib.error, EOFError, OSError) as exc:
        raise BinariesError(f"{path.name}: not a readable {fmt} archive: {exc}") from exc
    if not matches:
        raise BinariesError(f"{path.name}: no regular file named {filename}")
    if len(matches) > 1:
        raise BinariesError(
            f"{path.name}: more than one regular file named {filename}: {', '.join(m for m, _ in matches)}"
        )
    ((member, digest), ) = matches
    if not is_safe_member(member):
        raise BinariesError(f"{path.name}: unsafe member path {member!r} for {filename}")
    return member, digest


def _tar_matches(path: Path, fmt: ArchiveFormat, filename: str) -> list[tuple[str, str]]:
    matches = []
    with tarfile.open(path, TAR_MODES[fmt]) as archive:
        for info in archive:
            if info.isreg() and PurePosixPath(info.name).name == filename:
                stream = archive.extractfile(info)
                assert stream is not None
                matches.append((info.name, _sha256(stream)))
    return matches


def _zip_matches(path: Path, filename: str) -> list[tuple[str, str]]:
    matches = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            is_link = stat.S_ISLNK(info.external_attr >> 16)
            if not info.is_dir() and not is_link and PurePosixPath(info.filename).name == filename:
                with archive.open(info) as stream:
                    matches.append((info.filename, _sha256(stream)))
    return matches


def _sha256(stream: IO[bytes]) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(CHUNK):
        digest.update(chunk)
    return digest.hexdigest()
