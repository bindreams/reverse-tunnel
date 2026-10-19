# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""What the service account can reach in the deployment, checked before anything is changed."""

import dataclasses
import os
import shlex
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import Literal

from ctl.errors import InstallError
from ctl.perms import Account, AccountMode, account_mode

try:
    import pwd
except ImportError:  # Windows has no account database
    pwd = None

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
    searchable, then `host/` and the config in it readable. `bin/`, `secrets/` and `logs/` are skipped: the installer
    sets their modes.
    """
    for directory in (*reversed(root.parents), root, root / "host"):
        if not can("-x", directory):
            return directory
    config = root / "host" / "frpc.toml"
    return None if can("-r", config) else config


def account_can(account: Account, flag: str, path: PurePosixPath) -> bool:
    """Whether `account` passes `test <flag> <path>`, asked of the kernel by running `test` as that account.

    The answer is a sentinel the shell prints after `test`, and it counts only with exit status 0, so the wrapper
    failing (not root, PAM, `sudo -n` wanting a password) cannot be mistaken for `test` saying no.
    """
    posix_path = path.as_posix()
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
    if run.returncode == 0 and answer in (f"{SENTINEL}0", f"{SENTINEL}1"):
        return answer.endswith("0")
    raise InstallError(
        f"could not ask whether {account.name} can `test {flag} {posix_path}`: `{rendered}` exited "
        f"{run.returncode} without a usable answer. stdout: {run.stdout.strip()!r}. stderr: {run.stderr.strip()!r}"
    )


@dataclasses.dataclass(frozen=True)
class Inspection:
    """What a path is, from one `lstat`. `detail` is a symlink's target (empty if unreadable) or an error's text."""
    kind: Literal["missing", "symlink", "directory", "file", "other", "error"]
    mode: int = 0
    owner: str = ""
    detail: str = ""

    def describe(self) -> str:
        match self.kind:
            case "missing":
                return "it does not exist"
            case "error":
                return f"it could not be inspected: {self.detail}"
            case "symlink":
                return f"it is a symlink to {self.detail}" if self.detail else "it is a symlink"
            case "other":
                return f"mode {self.mode:04o}, owner {self.owner}, and it is not a regular file or a directory"
            case _:
                return f"mode {self.mode:04o}, owner {self.owner}"


def inspect_path(path: PurePosixPath) -> Inspection:
    """Look at `path` once, without following a link. Only "not there" is `missing`; any other failure is `error`."""
    try:
        status = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return Inspection("missing")
    except OSError as error:
        return Inspection("error", detail=str(error))
    owner = str(status.st_uid)
    if pwd is not None:
        try:
            owner = pwd.getpwuid(status.st_uid).pw_name
        except KeyError:
            pass
    mode = stat.S_IMODE(status.st_mode)
    if stat.S_ISLNK(status.st_mode):
        try:
            return Inspection("symlink", mode, owner, str(os.readlink(path)))
        except OSError:
            return Inspection("symlink", mode, owner)
    if stat.S_ISDIR(status.st_mode):
        return Inspection("directory", mode, owner)
    return Inspection("file" if stat.S_ISREG(status.st_mode) else "other", mode, owner)


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
    blocked = first_untraversable(posix_root, lambda flag, path: account_can(service, flag, path))
    if blocked is None:
        return
    found = inspect_path(blocked)
    action = "readable" if blocked == posix_root / "host" / "frpc.toml" else "searchable"
    raise InstallError(
        f"{blocked} is not {action} by {service.name}, the account the daemons run as ({found.describe()}), so they "
        f"could not start from {posix_root}. Nothing was changed. {_remedy(blocked, found, posix_root, service)}"
    )


def _remedy(blocked: PurePosixPath, found: Inspection, root: PurePosixPath, service: Account) -> str:
    """What to do about `blocked`, by what it is: part of the repository, the deployment itself, or somewhere above."""
    expected = {root / "host": "directory", root / "host" / "frpc.toml": "file"}
    if blocked in expected and found.kind not in (expected[blocked], "error"):
        # A link there is refused later in preflight, so no chmod gets the install through.
        relative = shlex.quote(blocked.relative_to(root).as_posix())
        return (
            "It is part of the repository; restore it, for example "
            f"`git -C {shlex.quote(str(root))} checkout -- {relative}`"
        )
    if blocked == root or blocked in expected:
        bit = "r" if blocked.name == "frpc.toml" else "x"
        return (
            f"Grant {service.name} access to it, for example `chmod o+{bit} {shlex.quote(str(blocked))}`, or give a "
            f"group {service.name} belongs to access to it"
        )
    return (
        f"Move the deployment to a location whose every parent directory {service.name} can search, such as "
        "/opt/reverse-tunnel or /srv/reverse-tunnel, or set RT_SERVICE_USER to the account that owns it"
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
