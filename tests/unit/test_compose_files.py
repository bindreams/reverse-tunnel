import os

import pytest

from ctl.compose_files import compose_file_problems


def deployment(tmp_path, *names: str):
    for name in names:
        (tmp_path / name).write_text("services: {}\n", newline="\n")
    return tmp_path


def joined(*entries: str, separator: str = os.pathsep) -> dict[str, str]:
    return {"COMPOSE_FILE": separator.join(entries)}


def test_absent_or_empty_compose_file_is_fine(tmp_path):
    assert compose_file_problems(tmp_path, {}) == []
    assert compose_file_problems(tmp_path, {"COMPOSE_FILE": ""}) == []


def test_a_valid_list_is_fine(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.traefik.yaml", "compose.override.yaml")
    values = joined("compose.yaml", "compose.traefik.yaml", "compose.override.yaml")
    assert compose_file_problems(root, values) == []


def test_compose_file_must_start_with_compose_yaml(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    problems = compose_file_problems(root, joined("compose.override.yaml", "compose.yaml"))
    assert len(problems) == 1
    assert "COMPOSE_FILE" in problems[0] and "compose.override.yaml" in problems[0] and "compose.yaml" in problems[0]


def test_compose_file_entries_must_exist(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    problems = compose_file_problems(root, joined("compose.yaml", "compose.override.yaml"))
    assert len(problems) == 1
    assert "COMPOSE_FILE" in problems[0] and "compose.override.yaml" in problems[0]


def test_compose_file_entries_must_be_regular_files(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    (root / "compose.override.yaml").mkdir()
    problems = compose_file_problems(root, joined("compose.yaml", "compose.override.yaml"))
    assert len(problems) == 1 and "compose.override.yaml" in problems[0]


@pytest.mark.parametrize("entry", ["/abs.yaml", "C:/abs.yaml", "C:x.yaml", "../x.yaml", "sub/../../x.yaml"])
def test_compose_file_entries_must_be_relative_and_inside_the_root(tmp_path, entry):
    root = deployment(tmp_path, "compose.yaml")
    problems = compose_file_problems(
        root, {**joined("compose.yaml", entry, separator=";"), "COMPOSE_PATH_SEPARATOR": ";"}
    )
    assert len(problems) == 1
    assert "COMPOSE_FILE" in problems[0] and entry in problems[0]


def test_compose_path_separator_from_env_is_honoured(tmp_path):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    other = ";" if os.pathsep == ":" else ":"
    values = {**joined("compose.yaml", "compose.override.yaml", separator=other), "COMPOSE_PATH_SEPARATOR": other}
    assert compose_file_problems(root, values) == []
    # Without the variable the same text is one entry that is not a file.
    problems = compose_file_problems(root, joined("compose.yaml", "compose.override.yaml", separator=other))
    assert len(problems) >= 1


def test_every_problem_is_listed_and_nothing_else_from_the_env_is_repeated(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    values = {
        **joined("compose.yaml", "/abs.yaml", "gone.yaml", separator=";"), "COMPOSE_PATH_SEPARATOR": ";",
        "RT_TOKEN": "s3cret"
    }
    problems = compose_file_problems(root, values)
    assert len(problems) == 2
    assert "s3cret" not in "".join(problems)


def test_an_empty_entry_is_a_problem(tmp_path):
    root = deployment(tmp_path, "compose.yaml")
    problems = compose_file_problems(root, joined("compose.yaml", ""))
    assert len(problems) == 1 and "COMPOSE_FILE" in problems[0]


def test_an_exported_compose_file_is_judged_instead_of_the_env_file(tmp_path, monkeypatch):
    root = deployment(tmp_path, "compose.yaml")
    monkeypatch.setenv("COMPOSE_FILE", "missing.yaml")
    (problem, ) = compose_file_problems(root, joined("compose.yaml"))
    assert "missing.yaml" in problem and "exported" in problem


def test_an_exported_separator_is_honoured(tmp_path, monkeypatch):
    root = deployment(tmp_path, "compose.yaml", "compose.override.yaml")
    monkeypatch.setenv("COMPOSE_PATH_SEPARATOR", "|")
    assert compose_file_problems(root, joined("compose.yaml", "compose.override.yaml", separator="|")) == []
