# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The RT-ENV dialect: the subset of `.env` syntax that docker compose, `ctl` and goetia read identically."""

import errno
import os
import re
import stat
import subprocess
from collections.abc import Collection
from pathlib import Path, PurePosixPath

KEY = re.compile(r"[A-Z][A-Z0-9_]*", re.ASCII)
BANNED_VALUE_CHARACTERS = frozenset("\"'`$\\#")
# Go `text/template` ignores whitespace and trim markers around the action, so the match must too.
GO_TEMPLATE_REFERENCE = re.compile(r"\{\{-?\s*\$?\.Envs\.([A-Z][A-Z0-9_]*)\s*-?\}\}")
COMPOSE_REFERENCE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::[?-][^}]*)?\}")
CONFIG_SUFFIXES = frozenset({".toml", ".yaml", ".yml", ".conf"})
CONFIG_NAMES = frozenset({"Caddyfile"})
# A rename of any of these must turn the template gates red rather than quietly shrink them.
KNOWN_MINIMUM = (".github/workflows/ci.yaml", "prek.toml", "pyproject.toml")

# `O_NOFOLLOW` is absent on Windows, where `read` refuses a link after opening instead. `O_NONBLOCK` keeps a FIFO at
# the path from blocking the open; `O_BINARY` stops Windows translating line endings before the dialect sees them.
OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class EnvError(Exception):
    """A `.env` file, or the set of tracked files, is outside what the dialect allows."""


# Parsing ==============================================================================================================


def parse(text: str, *, source: str) -> dict[str, str]:
    """Parse `text`, rejecting anything outside the dialect. Errors name `source` and the line, never a value."""
    if text.startswith("﻿"):
        raise EnvError(f"{source}:1: byte order mark")
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    values: dict[str, str] = {}
    first_seen: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        where = f"{source}:{number}"
        if "\r" in line:
            raise EnvError(f"{where}: carriage return; use LF line endings")
        if line == "" or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise EnvError(f"{where}: expected KEY=VALUE, a comment starting at column 0, or an empty line")
        if not KEY.fullmatch(key):
            raise EnvError(f"{where}: the key must match [A-Z][A-Z0-9_]* with no `export` and no spaces around `=`")
        if any(not "!" <= c <= "~" or c in BANNED_VALUE_CHARACTERS for c in value):
            raise EnvError(
                f"{where}: the value of {key} must be printable ASCII with no whitespace, quote, backtick, "
                "backslash, `$` or `#`"
            )
        if key in first_seen:
            raise EnvError(f"{where}: {key} is already set on line {first_seen[key]}")
        first_seen[key] = number
        values[key] = value
    return values


# Reading ==============================================================================================================


def read(path: Path) -> dict[str, str]:
    """Read and parse `path` without following a symlink, so a privileged reader cannot be aimed elsewhere."""
    try:
        fd = os.open(path, OPEN_FLAGS)
    except OSError as exc:
        raise EnvError(_open_failure(path, exc)) from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise EnvError(f"{path}: not a regular file")
        if not OPEN_FLAGS & getattr(os, "O_NOFOLLOW", 0):
            _refuse_link(path, opened)
        with os.fdopen(fd, "rb", closefd=False) as file:
            data = file.read()
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvError(f"{path}: not valid UTF-8 (byte offset {exc.start})") from exc
    return parse(text, source=str(path))


def _open_failure(path: Path, exc: OSError) -> str:
    if exc.errno in (errno.ELOOP, errno.EMLINK):
        return f"{path}: is a symlink; refusing to follow it"
    return f"{path}: {exc.strerror or exc}"


def _refuse_link(path: Path, opened: os.stat_result) -> None:
    """Fallback for platforms without `O_NOFOLLOW`: compare the opened file with what the path itself names."""
    named = os.lstat(path)
    attributes = getattr(named, "st_file_attributes", 0)
    if stat.S_ISLNK(named.st_mode) or attributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise EnvError(f"{path}: is a symlink or reparse point; refusing to follow it")
    if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
        raise EnvError(f"{path}: changed while it was being opened")


# Variable references ==================================================================================================


def referenced_variables(text: str) -> set[str]:
    """Every variable a Go template (`{{ .Envs.X }}`) or compose/goetia (`${X}`) document names."""
    return set(GO_TEMPLATE_REFERENCE.findall(text)) | set(COMPOSE_REFERENCE.findall(text))


def tracked_config_files(root: Path, *, minimum: Collection[str] = KNOWN_MINIMUM) -> list[Path]:
    """The git-tracked files that may reference variables, from `git ls-files` so a new file cannot escape."""
    try:
        listing = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError) as exc:
        detail = getattr(exc, "stderr", b"") or b""
        raise EnvError(f"{root}: cannot list tracked files: {os.fsdecode(detail).strip() or exc}") from exc
    tracked = [PurePosixPath(os.fsdecode(entry)) for entry in listing.split(b"\0") if entry]
    found = [p for p in tracked if p.suffix.lower() in CONFIG_SUFFIXES or p.name in CONFIG_NAMES]
    if not found:
        raise EnvError(f"{root}: no tracked config files; the template gates would pass vacuously")
    missing = sorted(set(minimum) - {p.as_posix() for p in found})
    if missing:
        raise EnvError(f"{root}: expected tracked config files are gone (renamed?): {', '.join(missing)}")
    return [root / p for p in found if (root / p).is_file()]
