"""Builders for archives with hostile or unusual entries, which `binaries_support.build_archive` cannot express."""

import io
import struct
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import Any, Literal

import pytest

from ctl.archive import ArchiveFormat


def write_tar(
    path: Path, entries: list[tuple[tarfile.TarInfo, bytes | None]], mode: Literal["w:xz", "w:gz"] = "w:xz"
) -> Path:
    with tarfile.open(path, mode) as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def regular(name: str, data: bytes = b"binary") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755
    return info, data


def other(name: str, kind: bytes, target: str = "elsewhere") -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
    return info, None


def write_zip(path: Path, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive, pytest.warns(UserWarning) if _has_duplicates(entries) else _nothing():
        for name, data in entries:
            archive.writestr(_verbatim(name), data)
    return path


def _verbatim(name: str | zipfile.ZipInfo) -> str | zipfile.ZipInfo:
    """On Windows `ZipInfo` rewrites a backslash to `/`; set the name afterwards so it reaches the archive as given."""
    if not isinstance(name, str) or "\\" not in name:
        return name
    info = zipfile.ZipInfo(name)
    info.filename = name
    return info


def zip_with_unicode_path(stored: str, unicode_name: str) -> tuple[zipfile.ZipInfo, bytes]:
    """An entry stored as `stored` whose Info-ZIP Unicode Path field (0x7075) names `unicode_name`, as 7-Zip reads it."""
    payload = struct.pack("<BL", 1, zlib.crc32(stored.encode())) + unicode_name.encode()
    info = zipfile.ZipInfo(stored)
    info.extra = struct.pack("<HH", 0x7075, len(payload)) + payload
    return info, b"binary"


def write_archive(path: Path, fmt: ArchiveFormat, entries: list[Any]) -> Path:
    """`entries` in the container `fmt` names: `(name, data)`, or a ready tar `(TarInfo, data)` / zip `(ZipInfo, data)`."""
    if fmt is ArchiveFormat.ZIP:
        return write_zip(path, entries)
    prepared = [e if isinstance(e[0], tarfile.TarInfo) else regular(*e) for e in entries]
    return write_tar(path, prepared, "w:gz" if fmt is ArchiveFormat.TAR_GZ else "w:xz")


def zip_link(name: str, target: str = "/etc") -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name)
    info.external_attr = 0o120777 << 16
    return info, target.encode()


def _has_duplicates(entries) -> bool:
    names = [e[0] if isinstance(e[0], str) else e[0].filename for e in entries]
    return len(names) != len(set(names))


class _nothing:

    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False
