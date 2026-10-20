"""`replace_file` on Windows: the directory is held as a vetted handle and the file is created and renamed through it."""

import io
import os

import pytest

from ctl import _winfile as winfile
from ctl import perms_windows, winacl
from ctl.atomic import replace_file
from ctl.binaries import write_atomically
from ctl.errors import BinariesError
from ctl.perms import SID_LOCAL_SERVICE, Account

LOCAL_SERVICE = Account("LocalService", None, None)


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
    """The handle is left open when the interrupt lands: cleanup must delete through it and close it."""
    real = winfile.create_relative

    def interrupted(*args, **kwargs):
        real(*args, **kwargs)
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


def test_a_failed_rename_deletes_the_temporary_and_keeps_the_old_file(tmp_path, monkeypatch):
    put(tmp_path, "tool", b"old")

    def refused(*args, **kwargs):
        raise PermissionError("in use")

    monkeypatch.setattr(winfile, "rename_over", refused)
    with pytest.raises(PermissionError):
        put(tmp_path, "tool", b"new")
    assert [p.name for p in tmp_path.iterdir()] == ["tool"]
    assert (tmp_path / "tool").read_bytes() == b"old"


def test_a_successful_replace_is_never_deleted_by_the_cleanup(tmp_path, monkeypatch):
    """An interrupt after the rename must not take the new file with it."""
    real = winfile.rename_over

    def renamed_then_interrupted(*args, **kwargs):
        real(*args, **kwargs)
        raise KeyboardInterrupt

    monkeypatch.setattr(winfile, "rename_over", renamed_then_interrupted)
    with pytest.raises(KeyboardInterrupt):
        put(tmp_path, "tool", b"new")
    assert (tmp_path / "tool").read_bytes() == b"new"


def test_digests_are_read_through_the_directory_handle_and_a_link_is_refused(tmp_path):
    from ctl.download import read_digests

    real = tmp_path / "real"
    real.mkdir()
    (real / ".digests.json").write_text("{}")
    os.symlink(real, tmp_path / "bin", target_is_directory=True)
    with pytest.raises(BinariesError, match="reparse point"):
        read_digests(tmp_path / "bin")
    assert read_digests(real) == {}
    assert read_digests(tmp_path / "missing") == {}


def test_a_handle_reports_the_name_it_has_now_and_a_rename_through_it_changes_it(tmp_path):
    import ctypes

    directory = winfile.open_handle(
        tmp_path,
        access=winfile.FILE_ADD_FILE | winfile.FILE_LIST_DIRECTORY,
        disposition=winfile.OPEN_EXISTING,
        directory=True,
        error=BinariesError,
        share=winfile.FILE_SHARE_READ_WRITE,
    )
    holder = ctypes.c_void_p()
    try:
        winfile.create_relative(
            directory,
            ".temporary",
            label=tmp_path / ".temporary",
            access=winfile.GENERIC_WRITE | winfile.DELETE,
            error=BinariesError,
            into=holder
        )
        assert holder.value is not None
        assert winfile.final_name(holder.value) == ".temporary"
        winfile.rename_over(holder.value, directory, "final", label=tmp_path / "final", error=BinariesError)
        assert winfile.final_name(holder.value) == "final"
        winfile.close_handle(holder.value)
    finally:
        winfile.close_handle(directory)
    assert [p.name for p in tmp_path.iterdir()] == ["final"]


def test_a_name_longer_than_the_first_buffer_is_still_read_in_full(tmp_path):
    import ctypes

    name = "n" * 250
    directory = winfile.open_handle(
        tmp_path,
        access=winfile.FILE_ADD_FILE | winfile.FILE_LIST_DIRECTORY,
        disposition=winfile.OPEN_EXISTING,
        directory=True,
        error=BinariesError,
        share=winfile.FILE_SHARE_READ_WRITE,
    )
    holder = ctypes.c_void_p()
    try:
        winfile.create_relative(
            directory, name, label=tmp_path / name, access=winfile.GENERIC_WRITE, error=BinariesError, into=holder
        )
        assert holder.value is not None
        assert len(str(tmp_path)) + len(name) > winfile.NAME_BUFFER_SIZE // 2  # the volume-relative path overflows it
        assert winfile.final_name(holder.value) == name
        winfile.close_handle(holder.value)
    finally:
        winfile.close_handle(directory)


def service_aces(entries):
    return [(e.mask, e.flags) for e in entries if e.sid == SID_LOCAL_SERVICE]


def test_the_service_read_is_on_the_file_before_it_is_renamed_into_place(tmp_path, monkeypatch):
    """The final name must never exist without the grant: a crash between a rename and a later grant is a lockout."""
    put(tmp_path, "tool", b"old")
    seen = []
    real = winfile.rename_over

    def spy(handle, *args, **kwargs):
        seen.append(winacl.read_entries(handle)[0])
        return real(handle, *args, **kwargs)

    monkeypatch.setattr(winfile, "rename_over", spy)
    replace_file(tmp_path, "tool", io.BytesIO(b"new"), None, service=LOCAL_SERVICE)
    assert [service_aces(entries) for entries in seen] == [[(winacl.READ_EXECUTE, 0)]]
    assert (tmp_path / "tool").read_bytes() == b"new"
    with perms_windows._handle(tmp_path / "tool", directory=False, access=winfile.READ_CONTROL) as handle:
        assert service_aces(winacl.read_entries(handle)[0]) == [(winacl.READ_EXECUTE, 0)]
