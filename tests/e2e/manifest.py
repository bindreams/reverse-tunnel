"""The host's two daemons as `goetia.yaml` declares them, so the tests run the commands the shipped manifest runs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


@dataclass(frozen=True)
class Daemon:
    argv: list[str]  # `command`, with `${VAR}` filled in; the first element is still the manifest's `bin/<name>`
    cwd: str
    env: dict[str, str]  # the manifest's `env:`, filled in


def _fill(text: str, values: Mapping[str, str]) -> str:

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        assert name in values, f"goetia.yaml references ${{{name}}} and the test supplies no value for it"
        return values[name]

    return REFERENCE.sub(replace, text)


def daemon(name: str, values: Mapping[str, str]) -> Daemon:
    """`daemons.<name>` of `goetia.yaml`; every `${VAR}` in its command, cwd and env must have a value in `values`."""
    document = yaml.safe_load((REPO_ROOT / "goetia.yaml").read_text(encoding="utf-8"))
    entry = document["daemons"][name]
    return Daemon(
        argv=[_fill(argument, values) for argument in entry["command"]],
        cwd=_fill(entry["cwd"], values),
        env={key: _fill(value, values)
             for key, value in entry.get("env", {}).items()},
    )
