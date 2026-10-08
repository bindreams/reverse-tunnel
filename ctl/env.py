# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The RT-ENV dialect: the subset of `.env` syntax that docker compose, `ctl` and goetia read identically."""

import errno
import os
import re
import stat
import subprocess
import sys
from collections.abc import Collection
from pathlib import Path, PurePosixPath

from ctl import _winfile as winfile

KEY = re.compile(r"[A-Z][A-Z0-9_]*", re.ASCII)
BANNED_VALUE_CHARACTERS = frozenset("\"'`$\\#")
# Go `text/template` skips ASCII space, tab, CR and LF around an action, and reads `-` as a trim marker only when
# whitespace is adjacent: `{{- ` on the left, ` -}}` on the right. Only `RT_*` names may be referenced: any other is a
# variable of the platform or the shell, not of this deployment. `bridge/entrypoint.sh` mirrors this pattern.
GO_TEMPLATE_REFERENCE = re.compile(
    r"\{\{(?:-[ \t\r\n])?[ \t\r\n]*\$?\.Envs\.(RT_[A-Z0-9_]*)(?:[ \t\r\n]+-|[ \t\r\n]*)\}\}"
)
UNSUPPORTED_TEMPLATE = "unsupported template syntax; only `{{ .Envs.RT_NAME }}` is supported"
ENVS_WORD = re.compile(r"\bEnvs\b", re.ASCII)
COMPOSE_REFERENCE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?::[?-][^}$\n]*)?\}")
# Caddy finds `{$NAME}` and `{env.NAME}` anywhere in its input, so no context may excuse one.
CADDY_PLACEHOLDER = re.compile(r"\{(?:\$[A-Za-z_]|env\.)")
OPENING_BRACES = re.compile(r"(?=\{\{)")
CONFIG_SUFFIXES = frozenset({".toml", ".yaml", ".yml", ".json", ".conf", ".ini", ".tmpl", ".service", ".plist"})
CONFIG_NAMES = frozenset({"Caddyfile"})
# Workflows are not deployment templates: their `${...}` is shell or Actions syntax, not a `.env` reference.
EXCLUDED_DIRECTORIES = frozenset({".github"})
# Everywhere but these, a `$` must be exactly a supported form. nginx and Caddy use `$name` for their own variables.
LENIENT_DOLLAR_SUFFIXES = frozenset({".conf"})
LENIENT_DOLLAR_NAMES = frozenset({"Caddyfile"})
# A rename of any of these must turn the template gates red rather than quietly shrink them.
KNOWN_MINIMUM = ("prek.toml", "pyproject.toml", "compose.yaml", "compose.traefik.yaml", "bridge/frps.toml")

# `O_NONBLOCK` keeps a FIFO at the path from blocking the open; `O_BINARY` stops Windows translating line endings
# before the dialect sees them. Windows has no `O_NOFOLLOW`; it opens through `_open_windows` instead.
OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))


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


def read_text(path: Path) -> str:
    """The UTF-8 text of `path`, opened without following a link so a privileged reader cannot be aimed elsewhere."""
    try:
        fd = _open_windows(path) if sys.platform == "win32" else os.open(path, OPEN_FLAGS)
    except OSError as exc:
        raise EnvError(_os_failure(path, exc)) from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise EnvError(f"{path}: not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as file:
            data = file.read()
    except OSError as exc:
        raise EnvError(_os_failure(path, exc)) from exc
    finally:
        os.close(fd)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvError(f"{path}: not valid UTF-8 (byte offset {exc.start})") from exc


def read(path: Path) -> dict[str, str]:
    """Read and parse `path` without following a symlink."""
    return parse(read_text(path), source=str(path))


def _os_failure(path: Path, exc: OSError) -> str:
    if exc.errno in (errno.ELOOP, errno.EMLINK):
        return f"{path}: is a symlink; refusing to follow it"
    return f"{path}: {exc.strerror or exc}"


def _open_windows(path: Path) -> int:
    """Open `path` read-only as a file descriptor, refusing any reparse point before its target is ever opened."""
    import msvcrt

    handle = winfile.open_handle(
        path, access=winfile.GENERIC_READ, disposition=winfile.OPEN_EXISTING, directory=False, error=EnvError
    )
    try:
        return msvcrt.open_osfhandle(handle, os.O_RDONLY)
    except BaseException:
        winfile.close_handle(handle)
        raise


# Variable references ==================================================================================================


def referenced_variables(text: str, *, source: str = "<text>", strict_dollar: bool = False) -> set[str]:
    """Every variable a Go template (`{{ .Envs.X }}`) or compose/goetia (`${X}`) document names.

    Fails closed, because each form below could read a variable this scan would miss:
    - a Caddy placeholder anywhere;
    - a `{{` that does not begin a `{{ .Envs.RT_NAME }}` reference, or an `Envs` outside one;
    - a `${` that is not `${NAME}`, `${NAME:?msg}` or `${NAME:-default}`.
    With `strict_dollar`, a `$` that is neither a `$$` escape nor one of those forms is an error too.
    """
    caddy = CADDY_PLACEHOLDER.search(text)
    if caddy:
        raise _unsupported(text, caddy.start(), source, "unsupported Caddy env placeholder; write the value literally")
    references = list(GO_TEMPLATE_REFERENCE.finditer(text))
    go_spans = [match.span() for match in references]
    starts = {start for start, _ in go_spans}
    for opening in OPENING_BRACES.finditer(text):
        if opening.start() not in starts:
            raise _unsupported(text, opening.start(), source, UNSUPPORTED_TEMPLATE)
    for word in ENVS_WORD.finditer(text):
        if not any(start <= word.start() and word.end() <= end for start, end in go_spans):
            raise _unsupported(text, word.start(), source, UNSUPPORTED_TEMPLATE)
    return {match.group(1) for match in references} | _dollar_references(_blank(text, go_spans), source, strict_dollar)


def referenced_in_file(path: Path) -> set[str]:
    """`referenced_variables` of one tracked file, strict about a bare `$` except in `.conf` and `Caddyfile`."""
    lenient = path.suffix.lower() in LENIENT_DOLLAR_SUFFIXES or path.name in LENIENT_DOLLAR_NAMES
    return referenced_variables(read_text(path), source=str(path), strict_dollar=not lenient)


def _dollar_references(text: str, source: str, strict: bool) -> set[str]:
    names: set[str] = set()
    position = text.find("$")
    while position != -1:
        if text.startswith("$$", position):
            position += 2
        elif match := COMPOSE_REFERENCE.match(text, position):
            names.add(match.group(1))
            position = match.end()
        elif strict or text.startswith("${", position):
            raise _unsupported(
                text, position, source, "unsupported `$`; use `$$`, `${NAME}`, `${NAME:?msg}` or `${NAME:-default}`"
            )
        else:
            position += 1
        position = text.find("$", position)
    return names


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    """`text` with each span replaced by spaces (newlines kept, so line numbers survive)."""
    pieces, last = [], 0
    for start, end in spans:
        pieces.append(text[last:start])
        pieces.append(re.sub(r"[^\n]", " ", text[start:end]))
        last = end
    pieces.append(text[last:])
    return "".join(pieces)


def _unsupported(text: str, offset: int, source: str, message: str) -> EnvError:
    return EnvError(f"{source}:{text.count(chr(10), 0, offset) + 1}: {message}")


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
    found = [
        p for p in tracked
        if (p.suffix.lower() in CONFIG_SUFFIXES or p.name in CONFIG_NAMES) and p.parts[0] not in EXCLUDED_DIRECTORIES
    ]
    if not found:
        raise EnvError(f"{root}: no tracked config files; the template gates would pass vacuously")
    missing = sorted(set(minimum) - {p.as_posix() for p in found})
    if missing:
        raise EnvError(f"{root}: expected tracked config files are gone (renamed?): {', '.join(missing)}")
    return [root / p for p in found if (root / p).is_file()]
