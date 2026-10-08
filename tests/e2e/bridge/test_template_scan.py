"""The entrypoint's shell scan must agree with the Python gate on the shared corpus of Go template snippets."""

import json

import pytest
from bridge_support import REPO_ROOT, Entrypoint, assert_refused

CORPUS = json.loads((REPO_ROOT / "tests" / "go_template.corpus").read_text(encoding="utf-8"))
ACCEPTED = [pytest.param(case["text"], case["names"], id=case["id"]) for case in CORPUS["accepted"]]
REJECTED = [pytest.param(case["text"], case["line"], id=case["id"]) for case in CORPUS["rejected"]]


@pytest.mark.parametrize(("text", "names"), ACCEPTED)
def test_accepts_every_reference_the_python_gate_accepts(entrypoint: Entrypoint, text: str, names: list[str]):
    result = entrypoint.run(config=text, environment={name: "value" for name in names})
    assert result.returncode == 0, result.stderr
    assert "STARTED" in result.stdout


@pytest.mark.parametrize(("text", "names"), [case for case in ACCEPTED if case.values[1]])
def test_names_the_first_referenced_variable_that_is_unset(entrypoint: Entrypoint, text: str, names: list[str]):
    for missing in names:
        values = {name: ("value" if name != missing else None) for name in names}
        result = entrypoint.run(config=text, environment=values)
        assert_refused(result, f"{missing} is unset or empty")


@pytest.mark.parametrize(("text", "line"), REJECTED)
def test_rejects_every_action_the_python_gate_rejects(entrypoint: Entrypoint, text: str, line: int):
    everything = {name: "value" for name in ("X", "Y", "A", "B", "C", "RT_X")}
    result = entrypoint.run(config=text, environment=everything)
    assert_refused(result, f"frps.toml:{line}: unsupported template syntax")
    assert "{{ .Envs.NAME }}" in result.stderr
