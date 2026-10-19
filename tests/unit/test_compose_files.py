import errno
import os
from collections.abc import Mapping
from pathlib import Path

import pytest

from ctl.compose_files import compose_file_problems


def problems_of(root: Path, values: Mapping[str, str], environ: Mapping[str, str] | None = None) -> list[str]:
    """The problems found with nothing exported unless `environ` says otherwise."""
    return compose_file_problems(root, values, {} if environ is None else environ).problems


def deployment(tmp_path, *names: str):
    for name in names:
        (tmp_path / name).write_text("services: {}\n", newline="\n")
    return tmp_path


def joined(*entries: str, separator: str = os.pathsep) -> dict[str, str]:
    return {"COMPOSE_FILE": separator.join(entries)}


def test_absent_or_empty_compose_file_is_fine(tmp_path):
    assert problems_of(tmp_path, {}) == []
    assert problems_of(tmp_path, {"COMPOSE_FILE": ""}) == []


def test_a_valid_list_is_fine(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.traefik.yaml", "compose.override.yaml")
    values = joined("compose.yaml", "compose.traefik.yaml", "compose.override.yaml")
    assert problems_of(root, values) == []


def test_compose_file_must_start_with_compose_yaml(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    problems = problems_of(root, joined("compose.override.yaml", "compose.yaml"))
    assert len(problems) == 1
    assert "COMPOSE_FILE" in problems[0] and "compose.override.yaml" in problems[0] and "compose.yaml" in problems[0]


def test_compose_file_entries_must_exist(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    problems = problems_of(root, joined("compose.yaml", "compose.override.yaml"))
    assert len(problems) == 1
    assert "COMPOSE_FILE" in problems[0] and "compose.override.yaml" in problems[0]


def test_compose_file_entries_must_be_regular_files(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    (root / "compose.override.yaml").mkdir()
    problems = problems_of(root, joined("compose.yaml", "compose.override.yaml"))
    assert len(problems) == 1 and "compose.override.yaml" in problems[0]


@pytest.mark.parametrize("entry", ["/abs.yaml", "C:/abs.yaml", "C:x.yaml", "../x.yaml", "sub/../../x.yaml"])
def test_compose_file_entries_must_be_relative_and_inside_the_root(tmp_path, entry):
    root = deployment(tmp_path, "compose.yaml")
    problems = problems_of(root, {**joined("compose.yaml", entry, separator=";"), "COMPOSE_PATH_SEPARATOR": ";"})
    assert len(problems) == 1
    assert "COMPOSE_FILE" in problems[0] and entry in problems[0]


def test_compose_path_separator_from_env_is_honoured(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    other = ";" if os.pathsep == ":" else ":"
    values = {**joined("compose.yaml", "compose.override.yaml", separator=other), "COMPOSE_PATH_SEPARATOR": other}
    assert problems_of(root, values) == []
    # Without the variable the same text is one entry that is not a file.
    problems = problems_of(root, joined("compose.yaml", "compose.override.yaml", separator=other))
    assert len(problems) >= 1


def test_every_problem_is_listed_and_nothing_else_from_the_env_is_repeated(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    values = {
        **joined("compose.yaml", "/abs.yaml", "gone.yaml", separator=";"), "COMPOSE_PATH_SEPARATOR": ";",
        "RT_TOKEN": "s3cret"
    }
    problems = problems_of(root, values)
    assert len(problems) == 2
    assert "s3cret" not in "".join(problems)


def test_an_empty_entry_is_a_problem(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    problems = problems_of(root, joined("compose.yaml", ""))
    assert len(problems) == 1 and "COMPOSE_FILE" in problems[0]


def test_an_exported_compose_file_is_judged_instead_of_the_env_file(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    check = compose_file_problems(root, joined("compose.yaml"), {"COMPOSE_FILE": "missing.yaml"})
    (problem, ) = check.problems
    assert "missing.yaml" in problem and "exported" in problem
    assert check.source == "exported"


def test_the_source_is_the_env_file_when_nothing_relevant_is_exported(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    check = compose_file_problems(root, joined("compose.yaml", "gone.yaml"), {"PATH": "/bin"})
    assert len(check.problems) == 1
    assert check.source == ".env"


def test_an_exported_empty_compose_file_is_a_problem_even_when_the_env_file_is_sound(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    check = compose_file_problems(root, joined("compose.yaml"), {"COMPOSE_FILE": ""})
    (problem, ) = check.problems
    assert "COMPOSE_FILE" in problem and "empty" in problem
    assert check.source == "exported"


def test_an_exported_empty_compose_file_is_a_problem_when_the_env_file_sets_none(tmp_path):
    assert len(problems_of(tmp_path, {}, {"COMPOSE_FILE": ""})) == 1


def test_an_exported_separator_is_honoured(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    values = joined("compose.yaml", "compose.override.yaml", separator="|")
    assert problems_of(root, values, {"COMPOSE_PATH_SEPARATOR": "|"}) == []


def test_an_exported_separator_wins_over_the_env_files(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    values = {**joined("compose.yaml", "compose.override.yaml", separator=";"), "COMPOSE_PATH_SEPARATOR": ";"}
    assert problems_of(root, values) == []
    assert len(problems_of(root, values, {"COMPOSE_PATH_SEPARATOR": "|"})) == 1


def test_an_empty_exported_separator_falls_back_to_the_os_default_and_ignores_the_env_file(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    other = ";" if os.pathsep == ":" else ":"
    # The `.env` separator would split this list; the empty export means the OS default, which does not.
    values = {**joined("compose.yaml", "compose.override.yaml", separator=other), "COMPOSE_PATH_SEPARATOR": other}
    assert problems_of(root, values) == []
    assert len(problems_of(root, values, {"COMPOSE_PATH_SEPARATOR": ""})) == 1
    values = joined("compose.yaml", "compose.override.yaml", separator=os.pathsep)
    assert problems_of(root, {**values, "COMPOSE_PATH_SEPARATOR": other}, {"COMPOSE_PATH_SEPARATOR": ""}) == []


def test_an_exported_compose_env_files_is_a_problem_because_compose_then_skips_the_env_file(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    check = compose_file_problems(root, joined("compose.yaml"), {"COMPOSE_ENV_FILES": "other.env"})
    (problem, ) = check.problems
    assert "COMPOSE_ENV_FILES" in problem and "unset" in problem
    assert check.source == "exported"


def test_an_empty_exported_compose_env_files_is_fine(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    assert problems_of(root, joined("compose.yaml"), {"COMPOSE_ENV_FILES": ""}) == []


def test_an_exported_compose_env_files_does_not_hide_a_bad_exported_compose_file(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    problems = problems_of(root, {}, {"COMPOSE_ENV_FILES": "other.env", "COMPOSE_FILE": "gone.yaml"})
    assert len(problems) == 2


def test_a_first_entry_that_is_a_directory_is_a_problem(tmp_path):
    (tmp_path / "compose.yaml").mkdir()
    (problem, ) = problems_of(tmp_path, joined("compose.yaml"))
    assert "compose.yaml" in problem


def test_a_dot_slash_first_entry_is_accepted(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    assert problems_of(root, joined("./compose.yaml")) == []


def test_a_backslash_entry_that_climbs_out_is_refused(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    values = {**joined("compose.yaml", "sub\\..\\x", separator=";"), "COMPOSE_PATH_SEPARATOR": ";"}
    (problem, ) = problems_of(root, values)
    assert "`..`" in problem


@pytest.mark.parametrize("code", [errno.ENAMETOOLONG, errno.EACCES, errno.ELOOP])
def test_an_os_error_other_than_not_found_is_a_problem_message(tmp_path, monkeypatch, code):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")

    def lstat(path, *args, **kwargs):
        if str(path).endswith("compose.override.yaml"):
            raise OSError(code, os.strerror(code))
        return real(path, *args, **kwargs)

    real = os.lstat
    monkeypatch.setattr(os, "lstat", lstat)
    (problem, ) = problems_of(root, joined("compose.yaml", "compose.override.yaml"))
    assert "compose.override.yaml" in problem and os.strerror(code) in problem
