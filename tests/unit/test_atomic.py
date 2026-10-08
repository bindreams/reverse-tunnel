import errno
import io
import os
import stat
from pathlib import Path

import pytest

from ctl.atomic import replace_file
from ctl.errors import BinariesError


def put(directory: Path, name: str, data: bytes, mode: int | None = None) -> Path:
    replace_file(directory, name, io.BytesIO(data), mode)
    return directory / name


def test_a_new_file_gets_the_requested_mode_and_content(tmp_path):
    path = put(tmp_path, "tool", b"data", 0o755)
    assert path.read_bytes() == b"data"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert [p.name for p in tmp_path.iterdir()] == ["tool"]


def test_without_a_mode_a_new_file_is_0644_and_an_existing_files_mode_is_kept(tmp_path):
    fresh = put(tmp_path, "new", b"x")
    existing = tmp_path / "old"
    existing.write_bytes(b"old")
    existing.chmod(0o600)
    put(tmp_path, "old", b"new")
    if os.name == "posix":
        assert stat.S_IMODE(fresh.stat().st_mode) == 0o644
        assert stat.S_IMODE(existing.stat().st_mode) == 0o600
    assert existing.read_bytes() == b"new"


def test_a_failing_source_leaves_the_old_file_and_no_temporary_behind(tmp_path):

    class Broken(io.RawIOBase):

        def readable(self):
            return True

        def readinto(self, buffer):
            raise OSError(errno.EIO, "disk on fire")

    (tmp_path / "tool").write_bytes(b"old")
    with pytest.raises(OSError, match="disk on fire"):
        replace_file(tmp_path, "tool", io.BufferedReader(Broken()), 0o755)
    assert [p.name for p in tmp_path.iterdir()] == ["tool"]
    assert (tmp_path / "tool").read_bytes() == b"old"


def test_a_missing_directory_is_refused(tmp_path):
    with pytest.raises(BinariesError, match="directory"):
        put(tmp_path / "missing", "tool", b"data")


def test_a_file_in_place_of_the_directory_is_refused(tmp_path):
    (tmp_path / "bin").write_bytes(b"")
    with pytest.raises(BinariesError, match="directory"):
        put(tmp_path / "bin", "tool", b"data")


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b", "../escape", "nul\0byte"])
def test_a_name_that_is_not_a_single_entry_is_refused(tmp_path, name):
    (tmp_path / "sub").mkdir()
    with pytest.raises(BinariesError, match="single directory entry"):
        put(tmp_path, name, b"data")
    assert [p.name for p in tmp_path.iterdir()] == ["sub"]
    assert list((tmp_path / "sub").iterdir()) == []
