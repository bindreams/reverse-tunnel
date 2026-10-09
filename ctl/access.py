# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""What the service account can reach in the deployment, checked before anything is changed."""

import os
import stat
import sys
from pathlib import Path

from ctl.errors import InstallError
from ctl.perms import Account, AccountMode, account_mode

# Everything root runs, reads, or hands the daemons the means to. A service able to write `goetia.yaml` or `bin/` could
# make the next `ctl install` run its own command as root, and `.env` holds the fleet token.
GUARDED = ("", "bin", "host", "goetia.yaml", "host/frpc.toml", ".env")


def verify_traversable(root: Path, service: Account) -> None:
    """Raise unless `service` can reach the binary and config under `root` at exec time.

    The kernel checks execute permission, as the service account, on every component of the path, so a checkout under
    a `0700` home is unreachable to any account but its owner. Whether to document that as a requirement, to relocate the
    deployment, or to bind-mount it is the owner's decision and is not made yet, so a separate account fails closed. This
    is the one place that decision will land.
    """
    if account_mode(root, service) is AccountMode.SAME:
        return
    raise InstallError(
        f"RT_SERVICE_USER={service.name}: separate-account mode (the daemons run as an account that does not own {root}) "
        "needs a check that every directory above the deployment is traversable by that account, and that check is not "
        "yet available, so this install refuses rather than stage a deployment the daemons may be unable to start from. "
        f"Run the daemons as the account that owns {root} (set RT_SERVICE_USER to it) until it is"
    )


def account_groups(account: Account) -> set[int]:
    """The primary and supplementary groups of `account`."""
    assert account.gid is not None
    try:
        return set(os.getgrouplist(account.name, account.gid))
    except (OSError, OverflowError):  # macOS's `nobody` has a gid that does not fit the C call
        return {account.gid}


def service_can_write(path: Path, account: Account) -> bool:
    """Whether `path`, where it finally points, has a write bit the account holds. Mode and ownership only: POSIX ACLs,
    immutable flags and read-only mounts are not consulted."""
    try:
        status = os.stat(path)
    except FileNotFoundError:
        return False
    if account.uid == status.st_uid:
        return bool(status.st_mode & stat.S_IWUSR)
    if status.st_gid in account_groups(account):
        return bool(status.st_mode & stat.S_IWGRP)
    return bool(status.st_mode & stat.S_IWOTH)


def refuse_service_writable(root: Path, service: Account) -> None:
    """In separate-account mode, raise if the service could rewrite what root runs. Same-account mode owns it all."""
    if sys.platform == "win32" or account_mode(root, service) is AccountMode.SAME:
        return
    for name in GUARDED:
        path = root / name if name else root
        if service_can_write(path, service):
            raise InstallError(
                f"{path} is writable by {service.name}, the account the daemons run as. A compromised daemon could "
                "then rewrite what root runs or reads on the next install. Remove the write permission "
                f"(for example `chmod go-w {path}`, and make sure {service.name} does not own it)"
            )
