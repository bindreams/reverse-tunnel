# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""`ctl install` and `ctl uninstall`, per role.

The bridge is Docker: all `install` does for it is give compose the token it mounts. A client is one binary. A host
(goetia, frpc, websocat as services) is not available yet.
"""

import dataclasses
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from ctl import binaries, client, perms
from ctl.atomic import read_file
from ctl.config import Config, Role
from ctl.download import Fetcher
from ctl.errors import InstallError
from ctl.removal import remove_directory

NO_READERS: frozenset[str] = frozenset()
SECRETS_MODE = 0o711
RECREATE = "docker compose up -d --force-recreate"

# Seams ================================================================================================================


class Runner(Protocol):

    def __call__(self, args: list[str], *, cwd: Path) -> int:
        """Run `args` in `cwd` and return its exit status; raise `FileNotFoundError` if the program does not exist."""


def run_command(args: list[str], *, cwd: Path) -> int:
    return subprocess.run(args, cwd=cwd, check=False).returncode


@dataclasses.dataclass(frozen=True)
class Services:
    """What install reaches outside the tree: the pins, the platform, the downloader, and docker."""

    lock_path: Path = binaries.LOCK_PATH
    platform: str | None = None  # None: this machine's
    fetcher: Callable[[], Fetcher] = Fetcher
    run: Runner = run_command


# Entry points =========================================================================================================


def install(config: Config, *, allow_self_disconnect: bool = False, services: Services | None = None) -> int:
    """Install this deployment's role; the exit status. `allow_self_disconnect` concerns the host role only."""
    services = services or Services()
    if config.role is Role.BRIDGE:
        return _install_bridge(config)
    if config.role is Role.CLIENT:
        client.install_client(
            config,
            lock_path=services.lock_path,
            platform=services.platform or binaries.current_platform(),
            fetcher=services.fetcher,
        )
        return 0
    raise _host_unavailable("install")


def uninstall(config: Config, *, services: Services | None = None) -> int:
    """Remove what `install` created for this role, and say so when there was nothing. Safe to repeat."""
    services = services or Services()
    if config.role is Role.BRIDGE:
        return _uninstall_bridge(config, services.run)
    if config.role is Role.CLIENT:
        client.uninstall_client(config)
        return 0
    raise _host_unavailable("uninstall")


def _host_unavailable(command: str) -> InstallError:
    return InstallError(f"ROLE=host: {command} is not available yet")


# Bridge ===============================================================================================================


def _refuse_compose_leftovers(root: Path) -> None:
    """Fail before any change if `secrets/` is not what `install` would have made.

    Docker creates a directory at a bind-mount source that does not exist, so a `docker compose up` that ran first
    leaves `secrets/` and `secrets/token` as directories, owned by root. This process is not elevated and cannot
    replace them.
    """
    secrets_dir = root / "secrets"
    try:
        status = os.lstat(secrets_dir)
    except FileNotFoundError:
        return
    if os.path.islink(secrets_dir):
        raise InstallError(f"{secrets_dir}: is a symlink; refusing to follow it. Remove the link and rerun")
    if not secrets_dir.is_dir():
        raise InstallError(f"{secrets_dir}: not a directory. Move it aside and rerun")
    problems: list[str] = []
    foreign = sys.platform != "win32" and status.st_uid != os.geteuid()
    if foreign:
        problems.append(f"secrets/ is owned by uid {status.st_uid}, not by you")
    token = secrets_dir / "token"
    if token.is_symlink():
        raise InstallError(f"{token}: is a symlink; refusing to follow it. Remove the link and rerun")
    if token.is_dir():
        foreign = foreign or (sys.platform != "win32" and token.stat().st_uid != os.geteuid())
        problems.append("secrets/token is a directory")
    if not problems:
        return
    if sys.platform == "win32":
        remove = "rmdir /s /q secrets"
    else:
        remove = ("sudo " if foreign else "") + "rm -rf ./secrets"
    raise InstallError(
        f"{'; '.join(problems)}: this is what `docker compose up` leaves when it runs before `ctl install`, "
        f"because Docker creates a directory at a bind-mount source that does not exist. "
        f"In {root}, run `{remove}`, then `uv run -m ctl install`, then `docker compose up`"
    )


def _install_bridge(config: Config) -> int:
    root = config.root
    secrets_dir, token_path = root / "secrets", root / "secrets" / "token"
    token = config.require("RT_TOKEN").encode("ascii")
    _refuse_compose_leftovers(root)
    perms.converge_dir(secrets_dir, None, SECRETS_MODE, NO_READERS, root=root)
    previous = read_file(secrets_dir, "token")
    if previous is not None and previous.strip() == token:
        # Same token; any difference is whitespace frps ignores. Rewriting would only change bytes it already read.
        perms.harden_file(token_path, None, NO_READERS, root=root)
    else:
        perms.write_secret(token_path, token + b"\n", None, NO_READERS, root=root)
    perms.harden_file(root / ".env", None, NO_READERS, root=root)
    print("bridge: secrets/token is in place")
    if previous is None or previous.strip() == token:
        return 0
    print(
        "secrets/token now holds the new RT_TOKEN, but a running frps still holds the old one: it reads the token once "
        f"at startup and cannot reload it. Recreate the container to apply the change (`{RECREATE}`). Recreating "
        "drops every connected tunnel, and a host that does not hold the new token will not reconnect.",
        file=sys.stderr,
    )
    return 1


def _uninstall_bridge(config: Config, run: Runner) -> int:
    """Take the container down while the file it mounts still exists, then remove `secrets/`."""
    try:
        status = run(["docker", "compose", "down", "--remove-orphans"], cwd=config.root)
    except FileNotFoundError:
        print("docker is not installed, so no container can be running; removing secrets/ only")
    else:
        if status != 0:
            print(f"docker compose down failed (exit {status}); secrets/ is kept", file=sys.stderr)
            return 1
    removed = remove_directory(config.root, "secrets")
    print("removed secrets/" if removed else "secrets/ is already absent")
    return 0
