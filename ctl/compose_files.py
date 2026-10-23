# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Checks on `COMPOSE_FILE`, the variable through which `.env` chooses the bridge's compose files.

Compose reads it from `.env` for the operator's `docker compose` and for `ctl`'s alike, so every call loads the same
set. Compose prefers an exported `COMPOSE_FILE` to `.env`, so that is the one judged when present. Only `ctl install`
insists on it being sound; `doctor` and `uninstall` must still run when it is not, so they never call this. An exported
`COMPOSE_ENV_FILES` (Compose then skips `.env`) and an exported empty `COMPOSE_FILE` (Compose reads the working
directory) are problems.
"""

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

from ctl.atomic import is_link

PRIMARY = "compose.yaml"

NOT_A_FILE = "is not a file in the deployment directory"
LINKED = "must not be, or go through, a symbolic link"

Source = Literal[".env", "exported"]

REMEDY: dict[Source, str] = {
    ".env": "fix COMPOSE_FILE in .env",
    "exported": "fix or unset the exported COMPOSE_FILE / COMPOSE_ENV_FILES",
}


@dataclass(frozen=True)
class ComposeFileCheck:
    """What is wrong with the file list Compose will load, and whether that list came from `.env` or the environment."""

    problems: list[str]
    source: Source


def compose_file_problems(
    root: Path, values: Mapping[str, str], environ: Mapping[str, str] | None = None
) -> ComposeFileCheck:
    """The list Compose will load, judged: one message per problem, none when it is fine or unset.

    A message names `COMPOSE_FILE` and the entry, and quotes nothing else from the environment.
    """
    environ = os.environ if environ is None else environ
    exported = "COMPOSE_FILE" in environ
    env_files = bool(environ.get("COMPOSE_ENV_FILES"))
    source: Source = "exported" if exported or env_files or environ.get("COMPOSE_PATH_SEPARATOR") else ".env"
    problems: list[str] = []
    if env_files:
        problems.append(
            "COMPOSE_ENV_FILES is exported, so Compose skips .env and ctl cannot vouch for the file list; "
            "unset it for ctl and for your own docker compose calls"
        )
        if not exported:
            return ComposeFileCheck(problems, source)
    raw = environ["COMPOSE_FILE"] if exported else values.get("COMPOSE_FILE", "")
    if exported and not raw:
        problems.append("COMPOSE_FILE is exported but empty, which Compose reads as the working directory; unset it")
    if not raw:
        return ComposeFileCheck(problems, source)
    # An exported separator wins even when empty, and then means the OS default, never `.env`'s.
    if "COMPOSE_PATH_SEPARATOR" in environ:
        separator = environ["COMPOSE_PATH_SEPARATOR"] or os.pathsep
    else:
        separator = values.get("COMPOSE_PATH_SEPARATOR") or os.pathsep
    name = "COMPOSE_FILE (exported, so it takes precedence over .env)" if exported else "COMPOSE_FILE"
    for index, entry in enumerate(raw.split(separator)):
        problem = _entry_problem(root, entry, first=index == 0)
        if problem:
            problems.append(f"{name} entry {entry!r}: {problem}" if entry else f"{name}: {problem}")
    return ComposeFileCheck(problems, source)


def _entry_problem(root: Path, entry: str, *, first: bool) -> str | None:
    if not entry:
        return "has an empty entry"
    # Judged under both path syntaxes, so a Windows-style entry is caught on POSIX too.
    for path in (PurePosixPath(entry), PureWindowsPath(entry)):
        if path.is_absolute() or path.drive or path.root:
            return "must be a relative path inside the deployment directory"
        if ".." in path.parts:
            return "must not contain `..`"
    if first and PurePosixPath(entry) != PurePosixPath(PRIMARY):
        return f"the first entry must be {PRIMARY}"
    return _file_problem(root, entry)


def _file_problem(root: Path, entry: str) -> str | None:
    """Why `entry` is not a regular file under `root` reached through no link; links are never followed."""
    directory = root
    for part in PurePosixPath(entry).parts[:-1]:
        directory = directory / part
        status = _inspect(directory)
        if not isinstance(status, os.stat_result):
            return status
        if is_link(status):
            return LINKED
    status = _inspect(os.path.join(root, entry))
    if not isinstance(status, os.stat_result):
        return status
    if is_link(status):
        return LINKED
    return None if stat.S_ISREG(status.st_mode) else NOT_A_FILE


def _inspect(path: str | Path) -> os.stat_result | str:
    """`lstat(path)`, or the problem it raised."""
    try:
        return os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return NOT_A_FILE
    except OSError as exc:
        return f"cannot be inspected: {exc.strerror or exc}"
