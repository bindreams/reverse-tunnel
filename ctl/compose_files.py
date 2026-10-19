# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Checks on `COMPOSE_FILE`, the variable through which `.env` chooses the bridge's compose files.

Compose reads it from `.env` for the operator's `docker compose` and for `ctl`'s alike, so every call loads the same
set. `ctl install` is the one place that insists on it being sound; `doctor` and `uninstall` must still run when it is
not, so they never call this.
"""

import os
from collections.abc import Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath

PRIMARY = "compose.yaml"


def compose_file_problems(root: Path, values: Mapping[str, str]) -> list[str]:
    """What is wrong with `COMPOSE_FILE` in `values`, one message per problem; empty when it is fine or unset.

    Each entry must be a relative path, free of `..`, naming a regular file under `root`, and the first must be
    `compose.yaml`. A message names `COMPOSE_FILE` and the entry, and quotes nothing else from the environment.
    """
    raw = values.get("COMPOSE_FILE", "")
    if not raw:
        return []
    separator = values.get("COMPOSE_PATH_SEPARATOR") or os.pathsep
    problems: list[str] = []
    for index, entry in enumerate(raw.split(separator)):
        problem = _entry_problem(root, entry, first=index == 0)
        if problem:
            problems.append(f"COMPOSE_FILE entry {entry!r}: {problem}" if entry else f"COMPOSE_FILE: {problem}")
    return problems


def _entry_problem(root: Path, entry: str, *, first: bool) -> str | None:
    if not entry:
        return "has an empty entry"
    # `.env` cannot hold a backslash, but the entry is judged under both path syntaxes, as `RT_TLS_CA_BUNDLE` is.
    for path in (PurePosixPath(entry), PureWindowsPath(entry)):
        if path.is_absolute() or path.drive or path.root:
            return "must be a relative path inside the deployment directory"
        if ".." in path.parts:
            return "must not contain `..`"
    if first and PurePosixPath(entry) != PurePosixPath(PRIMARY):
        return f"the first entry must be {PRIMARY}"
    if not (root / entry).is_file():
        return "is not a file in the deployment directory"
    return None
