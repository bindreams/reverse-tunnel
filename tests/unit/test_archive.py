import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from ctl.archive import ArchiveFormat, hash_binary
from ctl.errors import BinariesError


def write_tar(path: Path, entries: list[tuple[tarfile.TarInfo, bytes | None]]) -> Path:
    with tarfile.open(path, "w:xz") as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


def regular(name: str, data: bytes = b"binary") -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def other(name: str, kind: bytes, target: str = "elsewhere") -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = target if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
    return info, None


def write_zip(path: Path, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive, pytest.warns(UserWarning) if _has_duplicates(entries) else _nothing():
        for name, data in entries:
            archive.writestr(name, data)
    return path


def _has_duplicates(entries) -> bool:
    names = [e[0] if isinstance(e[0], str) else e[0].filename for e in entries]
    return len(names) != len(set(names))


class _nothing:

    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False


def test_a_single_regular_member_is_found_and_hashed(tmp_path):
    path = write_tar(tmp_path / "a.tar.xz", [regular("top/tool", b"abc"), regular("top/README.md")])
    member, digest = hash_binary(path, ArchiveFormat.TAR_XZ, "tool")
    assert member == "top/tool"
    assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@pytest.mark.parametrize(
    "second",
    [
        other("top/tool", tarfile.DIRTYPE),
        other("top/tool", tarfile.SYMTYPE, "/bin/sh"),
        other("top/tool", tarfile.LNKTYPE, "top/other"),
        regular("top/tool", b"another"),
        regular("./top/tool", b"another"),
    ],
    ids=["directory", "symlink", "hardlink", "regular", "dot-slash-regular"],
)
def test_a_tar_refuses_a_second_entry_of_any_type_at_the_matched_path(tmp_path, second):
    path = write_tar(tmp_path / "a.tar.xz", [regular("top/tool"), second])
    with pytest.raises(BinariesError, match="top/tool"):
        hash_binary(path, ArchiveFormat.TAR_XZ, "tool")


def test_a_tar_refuses_a_second_entry_listed_before_the_regular_one(tmp_path):
    path = write_tar(tmp_path / "a.tar.xz", [other("top/tool", tarfile.SYMTYPE, "/bin/sh"), regular("top/tool")])
    with pytest.raises(BinariesError, match="top/tool"):
        hash_binary(path, ArchiveFormat.TAR_XZ, "tool")


@pytest.mark.parametrize("second", ["top/tool/", "top/tool"], ids=["directory-entry", "duplicate-file"])
def test_a_zip_refuses_a_second_entry_of_any_type_at_the_matched_path(tmp_path, second):
    path = write_zip(tmp_path / "a.zip", [("top/tool", b"binary"), (second, b"")])
    with pytest.raises(BinariesError, match="top/tool"):
        hash_binary(path, ArchiveFormat.ZIP, "tool")


def test_a_zip_refuses_a_symlink_entry_sharing_the_matched_path(tmp_path):
    link = zipfile.ZipInfo("top/tool")
    link.external_attr = 0o120777 << 16
    path = write_zip(tmp_path / "a.zip", [("top/tool", b"binary"), (link, b"/bin/sh")])
    with pytest.raises(BinariesError, match="top/tool"):
        hash_binary(path, ArchiveFormat.ZIP, "tool")


def test_unrelated_entries_with_other_names_do_not_matter(tmp_path):
    path = write_tar(
        tmp_path / "a.tar.xz",
        [regular("top/tool"),
         other("top/tool-docs", tarfile.DIRTYPE),
         other("top/link", tarfile.SYMTYPE, "tool")],
    )
    assert hash_binary(path, ArchiveFormat.TAR_XZ, "tool")[0] == "top/tool"
