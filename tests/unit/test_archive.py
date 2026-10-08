import hashlib
import io
import os
import re
import tarfile
import zipfile
from pathlib import PurePosixPath

import pytest
from archive_support import other, regular, write_archive, write_tar, write_zip, zip_link

from ctl import archive
from ctl.archive import ArchiveFormat, extract_member, hash_binary
from ctl.errors import BinariesError


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
        [regular("top/tool"), other("top/tool-docs", tarfile.DIRTYPE),
         regular("top/README.md")],
    )
    assert hash_binary(path, ArchiveFormat.TAR_XZ, "tool")[0] == "top/tool"


# Hostile entries anywhere refuse the archive ==========================================================================

LINKS = [
    other("top/link", tarfile.SYMTYPE, "tool"),
    other("top/link", tarfile.SYMTYPE, "/etc"),
    other("top/link", tarfile.LNKTYPE, "top/tool"),
]
HOSTILE_TAR = [
    *LINKS,
    other("top/pipe", tarfile.FIFOTYPE),
    regular("../../evil"),
    regular("/etc/passwd"),
    regular("top\\evil"),
]


@pytest.mark.parametrize("entry", HOSTILE_TAR, ids=lambda e: f"{e[0].name}-{e[0].type!r}")
def test_a_tar_is_refused_for_a_hostile_entry_that_is_not_the_match(tmp_path, entry):
    path = write_tar(tmp_path / "a.tar.xz", [regular("top/tool"), entry])
    with pytest.raises(BinariesError, match=re.escape(repr(entry[0].name))):
        hash_binary(path, ArchiveFormat.TAR_XZ, "tool")


@pytest.mark.parametrize("name", ["../../evil", "/etc/passwd", "top\\evil"])
def test_a_zip_is_refused_for_an_unsafe_entry_that_is_not_the_match(tmp_path, name):
    path = write_zip(tmp_path / "a.zip", [("top/tool", b"binary"), (name, b"x")])
    with pytest.raises(BinariesError, match="unsafe"):
        hash_binary(path, ArchiveFormat.ZIP, "tool")


def test_a_zip_is_refused_for_a_symlink_that_is_not_the_match(tmp_path):
    path = write_zip(tmp_path / "a.zip", [("top/tool", b"binary"), zip_link("top/link")])
    with pytest.raises(BinariesError, match="top/link"):
        hash_binary(path, ArchiveFormat.ZIP, "tool")


# Names a case-insensitive or Windows extraction would merge ===========================================================

COLLIDING = [
    ("top/tool", "top/Tool"),
    ("top/tool", "TOP/TOOL"),
    ("top/tool", "top/tool."),
    ("top/tool", "top/tool "),
    ("top/tool\u00e9", "top/tool\u0065\u0301"),
    ("top/tool\u00e9", "top/TOOL\u00c9"),
]


@pytest.mark.parametrize(("first", "second"), COLLIDING)
def test_a_tar_refuses_a_second_entry_a_case_insensitive_filesystem_would_merge(tmp_path, first, second):
    path = write_tar(tmp_path / "a.tar.xz", [regular(first), regular(second, b"another")])
    with pytest.raises(BinariesError, match="more than one"):
        hash_binary(path, ArchiveFormat.TAR_XZ, PurePosixPath(first).name)


@pytest.mark.parametrize(("first", "second"), COLLIDING)
def test_a_zip_refuses_a_second_entry_a_case_insensitive_filesystem_would_merge(tmp_path, first, second):
    path = write_zip(tmp_path / "a.zip", [(first, b"binary"), (second, b"another")])
    with pytest.raises(BinariesError, match="more than one"):
        hash_binary(path, ArchiveFormat.ZIP, PurePosixPath(first).name)


def test_a_directory_entry_merging_with_the_match_is_refused(tmp_path):
    path = write_tar(tmp_path / "a.tar.xz", [regular("top/tool"), other("TOP/Tool", tarfile.DIRTYPE)])
    with pytest.raises(BinariesError, match="more than one"):
        hash_binary(path, ArchiveFormat.TAR_XZ, "tool")


# Extracting one member ================================================================================================

FORMATS = [
    (ArchiveFormat.TAR_GZ, "a.tar.gz"),
    (ArchiveFormat.TAR_XZ, "a.tar.xz"),
    (ArchiveFormat.ZIP, "a.zip"),
]


@pytest.fixture
def target(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    return scratch / "tool"


@pytest.mark.parametrize(("fmt", "name"), FORMATS)
def test_extract_member_writes_only_the_named_member_and_returns_its_digest(tmp_path, target, fmt, name):
    path = write_archive(
        tmp_path / name, fmt, [("top/tool", b"abc"), ("top/README.md", b"readme"), ("top/other", b"x")]
    )
    digest = extract_member(path, fmt, "top/tool", target)
    assert target.read_bytes() == b"abc"
    assert digest == hashlib.sha256(b"abc").hexdigest()
    assert list(target.parent.iterdir()) == [target]


@pytest.mark.parametrize(("fmt", "name"), FORMATS)
def test_extract_member_finds_a_member_under_a_top_level_directory_only_by_its_full_path(tmp_path, target, fmt, name):
    path = write_archive(tmp_path / name, fmt, [("top/tool", b"abc")])
    with pytest.raises(BinariesError, match="tool"):
        extract_member(path, fmt, "tool", target)
    assert not target.exists()


@pytest.mark.parametrize(("fmt", "name"), FORMATS)
def test_extract_member_refuses_a_second_entry_at_the_member_and_leaves_nothing(tmp_path, target, fmt, name):
    path = write_archive(tmp_path / name, fmt, [("top/tool", b"abc"), ("top/Tool", b"evil")])
    with pytest.raises(BinariesError, match="more than one"):
        extract_member(path, fmt, "top/tool", target)
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize(("fmt", "name"), FORMATS)
def test_extract_member_refuses_the_same_member_twice_and_leaves_nothing(tmp_path, target, fmt, name):
    path = write_archive(tmp_path / name, fmt, [("top/tool", b"abc"), ("top/tool", b"evil")])
    with pytest.raises(BinariesError, match="more than one"):
        extract_member(path, fmt, "top/tool", target)
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize(("fmt", "name"), FORMATS)
@pytest.mark.parametrize("member", ["../../evil", "/etc/passwd", "top\\tool", "", "top/../../tool"])
def test_extract_member_refuses_an_unsafe_member_argument(tmp_path, target, fmt, name, member):
    path = write_archive(tmp_path / name, fmt, [("top/tool", b"abc")])
    with pytest.raises(BinariesError, match="unsafe"):
        extract_member(path, fmt, member, target)
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize("fmt", [ArchiveFormat.TAR_GZ, ArchiveFormat.TAR_XZ])
def test_extract_member_never_writes_through_a_symlink_member(tmp_path, target, fmt):
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    path = write_archive(
        tmp_path / "a.tar", fmt, [other("bin", tarfile.SYMTYPE, str(sentinel)), ("bin/passwd", b"evil")]
    )
    with pytest.raises(BinariesError, match="bin"):
        extract_member(path, fmt, "bin/passwd", target)
    assert list(sentinel.iterdir()) == []
    assert list(target.parent.iterdir()) == []


def test_extract_member_never_writes_through_a_zip_symlink_member(tmp_path, target):
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    path = write_zip(tmp_path / "a.zip", [zip_link("bin", str(sentinel)), ("bin/passwd", b"evil")])
    with pytest.raises(BinariesError, match="bin"):
        extract_member(path, ArchiveFormat.ZIP, "bin/passwd", target)
    assert list(sentinel.iterdir()) == []
    assert list(target.parent.iterdir()) == []


def test_extract_member_refuses_a_target_that_exists(tmp_path, target):
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])
    target.write_bytes(b"old")
    with pytest.raises(FileExistsError):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", target)
    assert target.read_bytes() == b"old"


def test_extract_member_refuses_a_target_that_is_a_symlink(tmp_path, target):
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    target.symlink_to(victim)
    with pytest.raises(FileExistsError):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", target)
    assert victim.read_bytes() == b"precious"


def test_extract_member_refuses_a_parent_that_is_a_symlink(tmp_path):
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(BinariesError, match="directory"):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", link / "tool")
    assert list(real.iterdir()) == []


def test_extract_member_refuses_a_missing_parent(tmp_path):
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])
    with pytest.raises(BinariesError, match="directory"):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", tmp_path / "missing" / "tool")


def test_extract_member_has_nothing_to_extract_from_a_bare_binary(tmp_path, target):
    with pytest.raises(ValueError, match="bare"):
        extract_member(tmp_path / "x", ArchiveFormat.BARE, "x", target)


@pytest.mark.parametrize(("fmt", "name"), FORMATS)
def test_extract_member_reports_a_corrupt_archive_and_leaves_nothing(tmp_path, target, fmt, name):
    path = tmp_path / name
    path.write_bytes(b"not an archive at all")
    with pytest.raises(BinariesError, match=name):
        extract_member(path, fmt, "top/tool", target)
    assert list(target.parent.iterdir()) == []


@pytest.mark.parametrize("data", [b"abc", b"x" * (3 << 20)], ids=["small", "larger-than-a-chunk"])
def test_extract_member_reports_a_failed_write_as_a_write_failure_and_leaves_nothing(
    tmp_path, target, monkeypatch, data
):
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", data)])

    class Full(io.RawIOBase):

        def writable(self):
            return True

        def write(self, data):
            raise OSError(28, "No space left on device")

    def full_disk(fd, mode):
        os.close(fd)
        return io.BufferedWriter(Full())

    monkeypatch.setattr(archive.os, "fdopen", full_disk)
    with pytest.raises(BinariesError, match="cannot write") as raised:
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", target)
    assert "readable" not in str(raised.value)
    assert list(target.parent.iterdir()) == []


def test_extract_member_reports_a_failing_close_as_a_write_failure_and_leaves_nothing(tmp_path, target, monkeypatch):
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])

    class Failing(io.RawIOBase):
        closes = 0

        def writable(self):
            return True

        def write(self, data):
            return len(data)

        def close(self):
            Failing.closes += 1
            if Failing.closes == 1:
                raise OSError(5, "Input/output error")
            super().close()

    def failing(fd, mode):
        os.close(fd)
        return io.BufferedWriter(Failing())

    monkeypatch.setattr(archive.os, "fdopen", failing)
    with pytest.raises(BinariesError, match="cannot write"):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", target)
    assert list(target.parent.iterdir()) == []
