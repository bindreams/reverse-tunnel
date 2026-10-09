# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The only module that runs goetia, so the part of its command line this project consumes has one seam.

`list` and `status` print a JSON document whatever their exit status: goetia exits non-zero when any daemon's blob
fails to decode, though the document it printed is complete. So their stdout is parsed first and the exit status is
never read as "no document". Stderr is never parsed: on Windows the service backend writes a library message there that
the CLI cannot suppress. Every other verb has no JSON form, so its exit status is all there is, with goetia's own words
attached to a failure.

No call passes `--timeout`: goetia's default bound is the human-facing limit on an external event, the service manager
confirming a state a crash-looping daemon may never reach. It exits 4 then, and that surfaces as a named failure.
"""

import dataclasses
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from ctl.errors import InstallError

MANIFEST = "goetia.yaml"
STATES = frozenset({"running", "stopped", "failed", "unknown"})
KINDS = frozenset({
    "not-installed", "foreign", "unreadable", "undetermined", "invalid-id", "unavailable", "unsupported", "other"
})
EXIT_MEANINGS = {
    1: "error or refused",
    2: "usage error",
    3: "drift",
    4: "indeterminate: goetia stopped waiting or could not tell, and the request may still be standing",
    5: "conflict: the installed artifact was edited outside goetia",
}

# Errors and results ===================================================================================================


@dataclasses.dataclass(frozen=True)
class Problem:
    """One entry of the envelope's `errors`, or of its `undetermined` (kind `undetermined`)."""

    kind: str
    id: str | None
    message: str

    def __str__(self) -> str:
        return f"{self.kind}{f' ({self.id})' if self.id else ''}: {self.message}"


class GoetiaError(InstallError):
    """goetia failed, or said something this project cannot rely on. `problems` carries the envelope's entries."""

    def __init__(self, message: str, problems: Sequence[Problem] = ()) -> None:
        super().__init__(message)
        self.problems = tuple(problems)


@dataclasses.dataclass(frozen=True)
class DaemonState:
    id: str
    state: str  # running | stopped | failed | unknown
    enabled: bool
    pid: int | None  # null unless running


@dataclasses.dataclass(frozen=True)
class Report:
    """A parsed envelope, whole. `errors` and `undetermined` are both problems; neither is dropped."""

    daemons: tuple[DaemonState, ...]
    errors: tuple[Problem, ...]
    undetermined: tuple[Problem, ...]

    @property
    def problems(self) -> tuple[Problem, ...]:
        return self.errors + self.undetermined


# Running goetia =======================================================================================================


def executable(root: Path) -> Path:
    return root / "bin" / ("goetia.exe" if sys.platform == "win32" else "goetia")


def available(root: Path) -> bool:
    """Whether `ctl install` has put a goetia in `bin/`."""
    return executable(root).is_file()


def command(root: Path) -> list[str]:
    """The program and leading arguments that run this deployment's goetia."""
    return [str(executable(root))]


def _run(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    argv = [*command(root), "daemon", *arguments]
    try:
        return subprocess.run(
            argv,
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False
        )
    except OSError as exc:
        raise GoetiaError(f"cannot run {argv[0]}: {exc.strerror or exc}") from exc


def _failure(verb: str, subject: str, result: subprocess.CompletedProcess[str]) -> GoetiaError:
    said = " ".join((result.stderr.strip() or result.stdout.strip()).split()) or "it printed nothing"
    meaning = EXIT_MEANINGS.get(result.returncode)
    status = f"exit status {result.returncode}" + (f" ({meaning})" if meaning else "")
    return GoetiaError(f"`goetia daemon {verb}` for {subject} failed ({status}): {said}")


# The JSON verbs =======================================================================================================


def _text(value: object, where: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise GoetiaError(f"goetia's document has a non-string {where}")
    return value


def _entries(document: dict, key: str) -> list[dict]:
    entries = document.get(key)
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise GoetiaError(
            f"goetia's document has no list of objects under {key!r}; this is not the documented envelope"
        )
    return entries


def _require(entry: dict, *keys: str) -> None:
    missing = [key for key in keys if key not in entry]
    if missing:
        raise GoetiaError(f"goetia's document has an entry without {', '.join(missing)}: {entry!r}")


def _daemon(entry: dict) -> DaemonState:
    _require(entry, "id", "state", "enabled", "pid")
    identifier, state = _text(entry.get("id"), "daemon id"), _text(entry.get("state"), "daemon state")
    enabled, pid = entry.get("enabled"), entry.get("pid")
    if state not in STATES:
        raise GoetiaError(f"goetia reports {identifier} in the unknown state {state!r}")
    if not isinstance(enabled, bool):
        raise GoetiaError(f"goetia reports {identifier} with a non-boolean 'enabled'")
    if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int)):
        raise GoetiaError(f"goetia reports {identifier} with a non-integer pid")
    assert identifier is not None and state is not None
    return DaemonState(identifier, state, enabled, pid)


def _problem(entry: dict) -> Problem:
    _require(entry, "id", "kind", "message")
    kind = _text(entry.get("kind"), "error kind")
    if kind not in KINDS:
        raise GoetiaError(f"goetia reports an error of the unknown kind {kind!r}: {entry.get('message')!r}")
    assert kind is not None
    return Problem(
        kind, _text(entry.get("id"), "error id", nullable=True),
        _text(entry.get("message"), "error message") or ""
    )


def _undetermined(entry: dict) -> Problem:
    _require(entry, "name", "reason")
    return Problem(
        "undetermined", _text(entry.get("name"), "undetermined name", nullable=True),
        _text(entry.get("reason"), "undetermined reason") or ""
    )


def _not_the_envelope(verb: str, result: subprocess.CompletedProcess[str]) -> GoetiaError:
    return GoetiaError(
        f"`goetia daemon {verb} --json` printed something that is not the JSON envelope (exit status "
        f"{result.returncode}): {' '.join(result.stdout.split())[:200] or result.stderr.strip()[:200]!r}"
    )


def _parse(verb: str, result: subprocess.CompletedProcess[str]) -> Report:
    try:
        document = json.loads(result.stdout)
    except ValueError:
        raise _not_the_envelope(verb, result) from None
    if not isinstance(document, dict):
        raise _not_the_envelope(verb, result)
    return Report(
        tuple(_daemon(entry) for entry in _entries(document, "daemons")),
        tuple(_problem(entry) for entry in _entries(document, "errors")),
        tuple(_undetermined(entry) for entry in _entries(document, "undetermined")),
    )


def daemon_report(root: Path, verb: str, ids: Sequence[str] = ()) -> Report:
    """`goetia daemon list|status --json`, parsed whatever the exit status. Raises only when no envelope came back."""
    assert verb in ("list", "status")
    return _parse(verb, _run(root, verb, "--json", *ids))


def _raise_unless_clean(verb: str, report: Report, tolerated: Sequence[str] = ()) -> None:
    problems = [
        problem for problem in report.problems if not (problem.kind == "not-installed" and problem.id in tolerated)
    ]
    if problems:
        raise GoetiaError(f"`goetia daemon {verb}` reported: " + "; ".join(map(str, problems)), problems)


def daemon_list(root: Path) -> list[DaemonState]:
    """Every installed daemon. Any problem goetia reports is an error: use `daemon_report` to keep the rest."""
    report = daemon_report(root, "list")
    _raise_unless_clean("list", report)
    return list(report.daemons)


def daemon_status(root: Path, ids: Sequence[str]) -> list[DaemonState]:
    """The state of each of `ids` that is installed; one that is not is left out. Any other problem is an error."""
    report = daemon_report(root, "status", ids)
    _raise_unless_clean("status", report, tolerated=ids)
    answered = {state.id for state in report.daemons} | {problem.id for problem in report.errors}
    unanswered, unasked = sorted(set(ids) - answered), sorted({state.id for state in report.daemons} - set(ids))
    if unanswered or unasked:
        raise GoetiaError(
            "`goetia daemon status` did not answer for what was asked: " + "; ".join(
                part for part in (
                    f"no entry for {', '.join(unanswered)}" if unanswered else "",
                    f"unrequested {', '.join(unasked)}" if unasked else "",
                ) if part
            )
        )
    return list(report.daemons)


# The verbs without JSON ===============================================================================================


def _mutate(root: Path, verb: str, daemon_id: str, *flags: str) -> None:
    result = _run(root, verb, *flags, daemon_id)
    if result.returncode != 0:
        raise _failure(verb, daemon_id, result)


def daemon_install(root: Path, daemon_id: str, *, enable: bool) -> None:
    """Register `daemon_id` from the tracked manifest. It never starts the daemon, and returns when nothing changed."""
    _mutate(root, "install", daemon_id, "-f", str(root / MANIFEST), *(["--enable"] if enable else []))


def daemon_start(root: Path, daemon_id: str) -> None:
    _mutate(root, "start", daemon_id)


def daemon_restart(root: Path, daemon_id: str) -> None:
    """Stop then start, so it also starts a stopped daemon."""
    _mutate(root, "restart", daemon_id)


def daemon_stop(root: Path, daemon_id: str) -> None:
    _mutate(root, "stop", daemon_id)


def daemon_uninstall(root: Path, ids: Sequence[str]) -> None:
    """Uninstall each id. One that is not installed is success (goetia exits 0); every failure is raised, after the rest
    have been tried so that one locked unit does not leave the others behind."""
    failures: list[GoetiaError] = []
    for daemon_id in ids:
        result = _run(root, "uninstall", daemon_id)
        if result.returncode != 0:
            failures.append(_failure("uninstall", daemon_id, result))
    if failures:
        raise GoetiaError("; ".join(str(failure) for failure in failures), [p for f in failures for p in f.problems])


# Drift ================================================================================================================


def daemon_show(root: Path, daemon_id: str, *, from_manifest: bool) -> str:
    """The spec of `daemon_id` as installed, or as the tracked manifest would install it."""
    flags = ["-f", str(root / MANIFEST)] if from_manifest else []
    result = _run(root, "show", *flags, daemon_id)
    if result.returncode != 0:
        raise _failure("show", daemon_id, result)
    return result.stdout


def spec_is_current(root: Path, daemon_id: str) -> bool:
    """Whether what is installed is what the tracked manifest produces now, compared byte for byte.

    `daemon diff` cannot do this: it exits 0 for an up-to-date daemon and for one it would update.
    """
    return daemon_show(root, daemon_id, from_manifest=False) == daemon_show(root, daemon_id, from_manifest=True)
