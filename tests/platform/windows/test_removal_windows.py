"""`remove_directory` on Windows: the directory and its entries are deleted through vetted handles, never a link."""

import _winapi
import pytest

from ctl.errors import InstallError
from ctl.removal import remove_directory


def test_removes_a_flat_directory(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "websocat.exe").write_text("x")
    (tmp_path / "bin" / ".digests.json").write_text("{}")
    assert remove_directory(tmp_path, "bin") is True
    assert not (tmp_path / "bin").exists()


def test_an_absent_directory_is_not_an_error(tmp_path):
    assert remove_directory(tmp_path, "bin") is False


def test_the_name_is_matched_without_regard_to_case(tmp_path):
    (tmp_path / "Bin").mkdir()
    assert remove_directory(tmp_path, "bin") is True
    assert not (tmp_path / "Bin").exists()


def test_a_junction_in_place_of_the_directory_is_refused_and_its_target_is_untouched(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("x")
    _winapi.CreateJunction(str(target), str(tmp_path / "bin"))
    with pytest.raises(InstallError, match="reparse point"):
        remove_directory(tmp_path, "bin")
    assert (target / "keep").read_text() == "x"


def test_a_junction_inside_is_refused_and_its_target_is_untouched(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("x")
    (tmp_path / "bin").mkdir()
    _winapi.CreateJunction(str(target), str(tmp_path / "bin" / "link"))
    with pytest.raises(InstallError, match="reparse point"):
        remove_directory(tmp_path, "bin")
    assert (target / "keep").read_text() == "x"


def test_a_subdirectory_with_contents_is_never_entered(tmp_path):
    (tmp_path / "bin" / "sub").mkdir(parents=True)
    (tmp_path / "bin" / "sub" / "inner").write_text("x")
    with pytest.raises(InstallError, match="remove it yourself"):
        remove_directory(tmp_path, "bin")
    assert (tmp_path / "bin" / "sub" / "inner").read_text() == "x"
