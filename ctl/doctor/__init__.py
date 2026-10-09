# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""`ctl doctor`: every check of the deployment's role, each reported on its own.

One failing check never stops the rest, and one that does not apply is reported as such rather than left out. The
exit status is 0 unless some check failed.

Doctor runs as the account that owns the repository, unelevated: `.env` is `0600` and the operator's by design, and the
secrets are only ever `stat`ed (see `ctl.doctor.permissions`).
"""

import os
import sys
from pathlib import Path

from ctl.config import Config, Role
from ctl.doctor import bridge, client, host
from ctl.doctor.model import Check, Outcome, exit_code, render
from ctl.doctor.probes import Probes

__all__ = ["Check", "Config", "Outcome", "Probes", "diagnose", "exit_code", "render", "run"]

OWNER_CHECK = "runs_as_repository_owner"


def run(config: Config, probes: Probes | None = None) -> list[Check]:
    """The checks for `config.role`, in order. Probes default to the real machine."""
    probes = probes or Probes()
    runners = {Role.BRIDGE: bridge.checks, Role.HOST: host.checks, Role.CLIENT: client.checks}
    return runners[config.role](config, probes)


def _account_name(uid: int) -> str:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _not_the_owner(root: Path) -> Check | None:
    """On POSIX, a named failure if this is neither the repository's owner nor root, who can read anything."""
    if sys.platform == "win32":
        return None
    owner, me = os.stat(root).st_uid, os.geteuid()
    if me in (0, owner):
        return None
    return Check(
        OWNER_CHECK,
        Outcome.FAIL,
        f"this is {_account_name(me)}, but {root} belongs to {_account_name(owner)}, and `.env` is readable by its owner "
        f"only (mode 0600) by design. Run `uv run -m ctl doctor` as {_account_name(owner)}, without sudo",
    )


def _permission_denied(exc: BaseException | None) -> bool:
    """Whether `exc` or anything it was raised from is a permission error: `Config.load` wraps the OS error twice."""
    while exc is not None:
        if isinstance(exc, PermissionError):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


def diagnose(root: Path, probes: Probes | None = None) -> list[Check]:
    """Load `<root>/.env` and run its role's checks. A reader who is not the owner gets one named failure, not a traceback.

    Any other configuration error propagates: without a valid `.env` there is no role to check.
    """
    if (refusal := _not_the_owner(root)) is not None:
        return [refusal]
    try:
        config = Config.load(root)
    except Exception as exc:
        if not _permission_denied(exc):
            raise
        return [Check(OWNER_CHECK, Outcome.FAIL, f"{exc}. Run `uv run -m ctl doctor` as the account that owns {root}")]
    return run(config, probes)
