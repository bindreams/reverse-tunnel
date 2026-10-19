# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""What the service account can reach in the deployment, checked before anything is changed."""

import os
import shlex
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath

from ctl.errors import InstallError
from ctl.perms import Account, AccountMode, account_mode

# Everything root runs, reads, or hands the daemons the means to. A service able to write `goetia.yaml` or `bin/` could
# make the next `ctl install` run its own command as root, and `.env` holds the fleet token.
GUARDED = ("", "bin", "host", "goetia.yaml", "host/frpc.toml", ".env")
# What `sudo .venv/bin/python -m ctl` executes as root; everything beneath is checked too.
GUARDED_TREES = ("ctl", ".venv")
# What `account_can`'s shell prints after `test`, followed by its exit status.
SENTINEL = "rt-traverse:"


def first_untraversable(root: PurePosixPath, can: Callable[[str, PurePosixPath], bool]) -> PurePosixPath | None:
    """The first path the service account cannot reach, in the order the kernel walks it, or None.

    `can(flag, path)` is a `test` flag (`-x` or `-r`) and a path. Every directory from `/` down to `root` must be
    searchable, then `host/` and the config in it readable. `bin/`, `secrets/` and `logs/` are not asked about: `stage`
    gives them known modes.
    """
    for directory in (*reversed(root.parents), root, root / "host"):
        if not can("-x", directory):
            return directory
    config = root / "host" / "frpc.toml"
    return None if can("-r", config) else config


def account_can(account: Account, flag: str, path: Path) -> bool:
    """Whether `account` passes `test <flag> <path>`, asked of the kernel by running `test` as that account.

    `flag` is `-x` or `-r`. The answer is a sentinel the shell prints after `test`, so the wrapper failing (not root,
    PAM, `sudo -n` wanting a password) cannot be mistaken for `test` saying no.
    """
    posix_path = PurePosixPath(path).as_posix()
    if sys.platform == "darwin":
        as_account = ["sudo", "-n", "-u", account.name]
    else:
        as_account = ["runuser", "-u", account.name, "--"]
    command = [*as_account, "sh", "-c", f'test "$1" "$2"; echo "{SENTINEL}$?"', "sh", flag, posix_path]
    rendered = " ".join(map(shlex.quote, command))
    try:
        run = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
    except OSError as error:
        raise InstallError(
            f"could not ask whether {account.name} can `test {flag} {posix_path}`: {error} ({rendered})"
        ) from error
    lines = run.stdout.splitlines()
    answer = lines[-1] if lines else ""
    if answer in (f"{SENTINEL}0", f"{SENTINEL}1"):
        return answer.endswith("0")
    raise InstallError(
        f"could not ask whether {account.name} can `test {flag} {posix_path}`: `{rendered}` exited "
        f"{run.returncode} without a usable answer. stdout: {run.stdout.strip()!r}. stderr: {run.stderr.strip()!r}"
    )


def verify_traversable(root: Path, service: Account) -> None:
    """Raise unless `service` can reach the binary and config under `root` at exec time.

    Windows always passes: traversal is guaranteed by construction. `perms.grant_service_read` gives LocalService an
    inheritable read-and-execute ACE on the repository root, and LocalService holds SeChangeNotifyPrivilege, which
    bypasses traverse checking, so the ancestors of the root need no ACE.

    On POSIX the kernel checks execute permission, as the service account, on every component of the path, so a checkout
    under a `0700` home is unreachable to any account but its owner. The kernel is asked, as that account, rather than
    modes and ACLs being reimplemented here. The same account as the owner needs no proof.
    """
    if sys.platform == "win32" or account_mode(root, service) is AccountMode.SAME:
        return
    posix_root = PurePosixPath(root.as_posix())
    blocked = first_untraversable(posix_root, lambda flag, path: account_can(service, flag, Path(path)))
    if blocked is None:
        return
    config = posix_root / "host" / "frpc.toml"
    action = "readable" if blocked == config else "searchable"
    if blocked in (posix_root / "host", config):
        bit = "r" if blocked == config else "x"
        remedy = (
            f"Grant {service.name} access to it, for example `chmod o+{bit} {blocked}`, or give a group "
            f"{service.name} belongs to access to it"
        )
    else:
        remedy = (
            f"Move the deployment to a location whose every parent directory {service.name} can search, such as "
            "/opt/reverse-tunnel or /srv/reverse-tunnel, or set RT_SERVICE_USER to the account that owns it"
        )
    raise InstallError(
        f"{blocked} is not {action} by {service.name}, the account the daemons run as ({_describe(blocked)}), so they "
        f"could not start from {posix_root}. Nothing was changed. {remedy}"
    )


def _describe(path: PurePosixPath) -> str:
    """The mode and owner of `path`, or that it does not exist."""
    try:
        status = os.lstat(path)
    except OSError:
        return "it does not exist"
    try:
        import pwd

        owner = pwd.getpwuid(status.st_uid).pw_name
    except (ImportError, KeyError):
        owner = str(status.st_uid)
    return f"mode {stat.S_IMODE(status.st_mode):04o}, owner {owner}"


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
    for path in _guarded_paths(root):
        if service_can_write(path, service):
            raise InstallError(
                f"{path} is writable by {service.name}, the account the daemons run as. A compromised daemon could "
                "then rewrite what root runs or reads on the next install. Remove the write permission "
                f"(for example `chmod go-w {path}`, and make sure {service.name} does not own it)"
            )


def _guarded_paths(root: Path) -> Iterator[Path]:
    for name in GUARDED:
        yield root / name if name else root
    for name in GUARDED_TREES:
        top = root / name
        if not top.is_dir():
            continue
        yield top
        for directory, directories, files in os.walk(top):  # links are listed, never entered
            for entry in directories + files:
                yield Path(directory) / entry
