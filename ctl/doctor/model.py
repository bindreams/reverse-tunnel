# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""What a check is, how a list of them runs, and how the result reads.

A check function returns a `Verdict`; `execute` names it. One that raises is that check's failure, reported with the
exception, so a bug in one probe cannot take the others down, and one that raises `Skip` is not applicable because
something it needs has already failed and said so.
"""

import dataclasses
import enum
from collections.abc import Callable, Iterable
from typing import NamedTuple


class Outcome(enum.StrEnum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "n/a"


@dataclasses.dataclass(frozen=True)
class Check:
    name: str
    outcome: Outcome
    detail: str


class Verdict(NamedTuple):
    outcome: Outcome
    detail: str


class Skip(Exception):
    """The check cannot be evaluated; `str(self)` says why, naming the check that holds the cause."""


def ok(detail: str) -> Verdict:
    return Verdict(Outcome.PASS, detail)


def fail(detail: str) -> Verdict:
    return Verdict(Outcome.FAIL, detail)


def not_applicable(reason: str) -> Verdict:
    return Verdict(Outcome.NOT_APPLICABLE, reason)


Probe = Callable[[], Verdict]


def execute(probes: Iterable[tuple[str, Probe]]) -> list[Check]:
    """Run each probe, in order, and name its verdict. Nothing a probe does stops the next one."""
    checks = []
    for name, probe in probes:
        try:
            outcome, detail = probe()
        except Skip as skipped:
            outcome, detail = Outcome.NOT_APPLICABLE, str(skipped)
        except Exception as exc:
            outcome, detail = Outcome.FAIL, f"the check itself failed: {type(exc).__name__}: {exc}"
        checks.append(Check(name, outcome, detail))
    return checks


# Reporting ============================================================================================================

LABELS = {Outcome.PASS: "pass", Outcome.FAIL: "FAIL", Outcome.NOT_APPLICABLE: "n/a"}


def exit_code(checks: Iterable[Check]) -> int:
    """0 unless some check failed. A check that does not apply is reported and does not count."""
    return 1 if any(check.outcome is Outcome.FAIL for check in checks) else 0


def render(checks: list[Check]) -> str:
    """One line per check, a multi-line detail indented under it, and a count."""
    width = max((len(check.name) for check in checks), default=0)
    lines = []
    for check in checks:
        first, *rest = (check.detail or "-").splitlines() or ["-"]
        lines.append(f"{LABELS[check.outcome]:<4}  {check.name:<{width}}  {first}")
        lines.extend(f"    {line}" for line in rest)
    count = {outcome: sum(check.outcome is outcome for check in checks) for outcome in Outcome}
    lines.append(
        f"{count[Outcome.PASS]} passed, {count[Outcome.FAIL]} failed, {count[Outcome.NOT_APPLICABLE]} not applicable"
    )
    return "\n".join(lines)
