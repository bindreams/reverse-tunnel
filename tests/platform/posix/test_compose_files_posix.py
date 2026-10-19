"""`COMPOSE_FILE` entries are regular files under the root, reached through no symbolic link."""

from pathlib import Path

from ctl.compose_files import compose_file_problems


def problems_of(root: Path, *entries: str) -> list[str]:
    values = {"COMPOSE_FILE": ":".join(entries), "COMPOSE_PATH_SEPARATOR": ":"}
    return compose_file_problems(root, values, {}).problems


def test_an_entry_that_is_a_symlink_is_refused(tmp_path):
    (tmp_path / "compose.yaml").write_text("services: {}\n", newline="\n")
    target = tmp_path / "elsewhere.yaml"
    target.write_text("services: {}\n", newline="\n")
    (tmp_path / "compose.override.yaml").symlink_to(target)
    (problem, ) = problems_of(tmp_path, "compose.yaml", "compose.override.yaml")
    assert "compose.override.yaml" in problem and "symbolic link" in problem


def test_an_entry_under_a_symlinked_directory_is_refused(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "compose.yaml").write_text("services: {}\n", newline="\n")
    (outside / "x.yaml").write_text("services: {}\n", newline="\n")
    (root / "sub").symlink_to(outside, target_is_directory=True)
    (problem, ) = problems_of(root, "compose.yaml", "sub/x.yaml")
    assert "sub/x.yaml" in problem and "symbolic link" in problem


def test_a_first_entry_that_is_a_symlink_is_refused(tmp_path):
    target = tmp_path / "real.yaml"
    target.write_text("services: {}\n", newline="\n")
    (tmp_path / "compose.yaml").symlink_to(target)
    (problem, ) = problems_of(tmp_path, "compose.yaml")
    assert "symbolic link" in problem


def test_a_regular_file_in_a_real_subdirectory_is_accepted(tmp_path):
    (tmp_path / "compose.yaml").write_text("services: {}\n", newline="\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "x.yaml").write_text("services: {}\n", newline="\n")
    assert problems_of(tmp_path, "compose.yaml", "sub/x.yaml") == []
