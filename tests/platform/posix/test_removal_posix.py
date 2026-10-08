import os
from pathlib import Path

import pytest

from ctl import removal
from ctl.errors import InstallError
from ctl.removal import remove_directory


def test_removes_a_flat_directory(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "websocat").write_text("x")
    (tmp_path / "bin" / ".digests.json").write_text("{}")
    assert remove_directory(tmp_path, "bin") is True
    assert not (tmp_path / "bin").exists()


def test_an_absent_directory_is_not_an_error(tmp_path):
    assert remove_directory(tmp_path, "bin") is False


def test_a_second_removal_reports_nothing_to_do(tmp_path):
    (tmp_path / "bin").mkdir()
    assert (remove_directory(tmp_path, "bin"), remove_directory(tmp_path, "bin")) == (True, False)


def test_a_symlinked_directory_is_refused_and_its_target_is_untouched(tmp_path, tmp_path_factory):
    target = tmp_path_factory.mktemp("target")
    (target / "keep").write_text("x")
    (tmp_path / "bin").symlink_to(target)
    with pytest.raises(InstallError, match="symlink"):
        remove_directory(tmp_path, "bin")
    assert (target / "keep").read_text() == "x"
    assert (tmp_path / "bin").is_symlink()


def test_a_symlink_inside_is_unlinked_and_not_followed(tmp_path, tmp_path_factory):
    target = tmp_path_factory.mktemp("target")
    (target / "keep").write_text("x")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "link").symlink_to(target)
    (tmp_path / "bin" / "filelink").symlink_to(target / "keep")
    assert remove_directory(tmp_path, "bin") is True
    assert (target / "keep").read_text() == "x"
    assert not (tmp_path / "bin").exists()


def test_a_file_where_a_directory_belongs_is_refused(tmp_path):
    (tmp_path / "bin").write_text("x")
    with pytest.raises(InstallError, match="not a directory"):
        remove_directory(tmp_path, "bin")
    assert (tmp_path / "bin").read_text() == "x"


def test_an_empty_subdirectory_is_removed(tmp_path):
    (tmp_path / "bin" / "token").mkdir(parents=True)
    assert remove_directory(tmp_path, "bin") is True
    assert not (tmp_path / "bin").exists()


def test_a_subdirectory_with_contents_is_never_entered(tmp_path):
    """The directories this tree holds are flat; descending would be the way to cross a mount."""
    (tmp_path / "bin" / "sub").mkdir(parents=True)
    (tmp_path / "bin" / "sub" / "inner").write_text("x")
    (tmp_path / "bin" / "websocat").write_text("x")
    with pytest.raises(InstallError, match="remove it yourself") as raised:
        remove_directory(tmp_path, "bin")
    assert str(tmp_path / "bin" / "sub") in str(raised.value)
    assert (tmp_path / "bin" / "sub" / "inner").read_text() == "x"


def test_a_directory_that_cannot_be_removed_because_it_is_busy_is_named(tmp_path, monkeypatch):
    """A mount point answers `rmdir` with EBUSY; nothing under it may have been touched."""
    (tmp_path / "bin" / "mnt").mkdir(parents=True)
    real = os.rmdir

    def busy(path, *, dir_fd=None):
        if path == "mnt":
            raise OSError(16, "Device or resource busy")
        return real(path, dir_fd=dir_fd)

    monkeypatch.setattr(removal.os, "rmdir", busy)
    with pytest.raises(InstallError, match="Device or resource busy"):
        remove_directory(tmp_path, "bin")


def test_a_directory_swapped_for_a_symlink_after_the_check_is_not_followed(tmp_path, tmp_path_factory, monkeypatch):
    target = tmp_path_factory.mktemp("target")
    (target / "keep").write_text("x")
    (tmp_path / "bin").mkdir()
    real = os.lstat

    def lstat_then_swap(path, *, dir_fd=None):
        result = real(path, dir_fd=dir_fd)
        if path == "bin":
            (tmp_path / "bin").rmdir()
            (tmp_path / "bin").symlink_to(target)
        return result

    monkeypatch.setattr(removal.os, "lstat", lstat_then_swap)
    with pytest.raises(InstallError, match="symlink"):
        remove_directory(tmp_path, "bin")
    assert (target / "keep").read_text() == "x"


def test_the_parent_must_not_be_a_symlink(tmp_path, tmp_path_factory):
    real = tmp_path_factory.mktemp("real")
    (real / "bin").mkdir()
    (tmp_path / "linked").symlink_to(real)
    with pytest.raises(InstallError):
        remove_directory(Path(tmp_path / "linked"), "bin")
    assert (real / "bin").is_dir()
