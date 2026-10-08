"""`replace_file` on Windows: the directory is held as a vetted handle and the file is created and renamed through it."""

import io
import os

import pytest

from ctl import _winfile as winfile
from ctl.atomic import replace_file
from ctl.binaries import write_atomically
from ctl.errors import BinariesError


def put(directory, name, data=b"data"):
    return replace_file(directory, name, io.BytesIO(data), None)


def test_a_new_file_is_created_and_an_existing_one_replaced_with_no_temporary_left(tmp_path):
    put(tmp_path, "tool", b"one")
    put(tmp_path, "tool", b"two")
    assert (tmp_path / "tool").read_bytes() == b"two"
    assert [p.name for p in tmp_path.iterdir()] == ["tool"]


def test_a_directory_symlink_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "bin"
    os.symlink(real, link, target_is_directory=True)
    with pytest.raises(BinariesError, match="reparse point"):
        put(link, "tool")
    assert list(real.iterdir()) == []


def test_a_junction_in_place_of_the_directory_is_refused(tmp_path):
    import _winapi

    real = tmp_path / "real"
    real.mkdir()
    junction = tmp_path / "bin"
    _winapi.CreateJunction(str(real), str(junction))
    with pytest.raises(BinariesError, match="reparse point"):
        put(junction, "tool")
    assert list(real.iterdir()) == []


def test_a_symlinked_destination_is_refused_and_its_target_untouched(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    os.symlink(victim, tmp_path / "tool")
    with pytest.raises(BinariesError, match="reparse point"):
        put(tmp_path, "tool")
    assert victim.read_bytes() == b"precious"


def test_a_destination_with_a_second_hard_link_is_refused(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"old")
    os.link(original, tmp_path / "tool")
    with pytest.raises(BinariesError, match="hard links"):
        put(tmp_path, "tool")
    assert original.read_bytes() == b"old"


def test_a_directory_at_the_destination_is_refused(tmp_path):
    (tmp_path / "tool").mkdir()
    with pytest.raises(BinariesError, match="regular file"):
        put(tmp_path, "tool")


def test_the_directory_cannot_be_renamed_away_while_the_file_is_written(tmp_path):
    """The held handle has no FILE_SHARE_DELETE, so the path cannot be pointed elsewhere mid-write."""
    directory = tmp_path / "bin"
    directory.mkdir()

    class Source(io.RawIOBase):
        tried = False

        def readable(self):
            return True

        def readinto(self, buffer):
            if not Source.tried:
                Source.tried = True
                with pytest.raises(OSError):
                    os.rename(directory, tmp_path / "moved")
            return 0

    replace_file(directory, "tool", io.BufferedReader(Source()), None)
    assert Source.tried
    assert (directory / "tool").read_bytes() == b""


def test_a_failing_source_leaves_the_old_file_and_no_temporary(tmp_path):

    class Broken(io.RawIOBase):

        def readable(self):
            return True

        def readinto(self, buffer):
            raise OSError("disk on fire")

    put(tmp_path, "tool", b"old")
    with pytest.raises(OSError, match="disk on fire"):
        replace_file(tmp_path, "tool", io.BufferedReader(Broken()), None)
    assert [p.name for p in tmp_path.iterdir()] == ["tool"]
    assert (tmp_path / "tool").read_bytes() == b"old"


def test_an_interrupt_right_after_the_temporary_is_created_leaves_nothing_behind(tmp_path, monkeypatch):
    real = winfile.create_relative

    def interrupted(*args, **kwargs):
        winfile.close_handle(real(*args, **kwargs))
        raise KeyboardInterrupt

    monkeypatch.setattr(winfile, "create_relative", interrupted)
    with pytest.raises(KeyboardInterrupt):
        put(tmp_path, "tool")
    assert list(tmp_path.iterdir()) == []


def test_write_atomically_replaces_a_file_through_the_same_path(tmp_path):
    write_atomically(tmp_path / "lock", "one")
    write_atomically(tmp_path / "lock", "two")
    assert (tmp_path / "lock").read_text() == "two"


def test_a_name_that_is_not_a_single_entry_is_refused(tmp_path):
    for name in ("a\\b", "a/b", "a:b", ""):
        with pytest.raises(BinariesError, match="single directory entry"):
            put(tmp_path, name)
    assert list(tmp_path.iterdir()) == []
