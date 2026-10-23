# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""`ctl install` and `ctl uninstall`, per role.

The bridge is Docker: all `install` does for it is give compose the token it mounts. A client is one binary. A host
(goetia, frpc, websocat as services) is `ctl.host`.
"""

import os
import stat
import sys
from pathlib import Path

from ctl import binaries, client, host, perms
from ctl.atomic import read_file
from ctl.compose_files import REMEDY, compose_file_problems
from ctl.config import Config, Role
from ctl.errors import BinariesError, InstallError
from ctl.removal import remove_directory
from ctl.services import Runner, Services, run_command  # noqa: F401  re-exported: callers import them from here

NO_READERS: frozenset[str] = frozenset()
SECRETS_MODE = 0o711
RECREATE = "docker compose up -d --force-recreate"

# Entry points =========================================================================================================


def install(
    config: Config,
    *,
    allow_self_disconnect: bool = False,
    apply_staged: bool = False,
    inherit_lock: int | None = None,
    started_fd: int | None = None,
    services: Services | None = None,
) -> int:
    """Install this deployment's role; the exit status. The last three keywords before `services` are host-only."""
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
    return host.install(
        config,
        allow_self_disconnect=allow_self_disconnect,
        apply_staged=apply_staged,
        inherit_lock=inherit_lock,
        started_fd=started_fd,
        services=services,
    )


def uninstall(
    config: Config,
    *,
    force: bool = False,
    allow_self_disconnect: bool = False,
    detached: bool = False,
    inherit_lock: int | None = None,
    started_fd: int | None = None,
    services: Services | None = None,
) -> int:
    """Remove what `install` created for this role, and say so when there was nothing. Safe to repeat.

    The bridge's container is taken down first, and `secrets/` stays if that cannot be done; `force` skips the step.
    The three keywords after `force` are host-only.
    """
    services = services or Services()
    if config.role is Role.BRIDGE:
        return _uninstall_bridge(config, services.run, force)
    if config.role is Role.CLIENT:
        client.uninstall_client(config)
        return 0
    return host.uninstall(
        config,
        allow_self_disconnect=allow_self_disconnect,
        detached=detached,
        inherit_lock=inherit_lock,
        started_fd=started_fd,
        services=services,
    )


# Bridge ===============================================================================================================


def _refuse_compose_leftovers(root: Path) -> None:
    """Fail before any change if `secrets/` is not what `install` would have made.

    Docker creates a directory at a bind-mount source that does not exist, so a `docker compose up` that ran first
    leaves `secrets/` and `secrets/token` as directories, owned by root. Running `ctl` under sudo leaves root-owned
    files instead. Either way this process is not elevated and cannot replace them.
    """
    secrets_dir, token = root / "secrets", root / "secrets" / "token"
    posix = sys.platform != "win32"
    status = _lstat(secrets_dir)
    if status is None:
        return
    if stat.S_ISLNK(status.st_mode):
        raise InstallError(f"{secrets_dir}: is a symlink; refusing to follow it. Remove the link and rerun")
    if not stat.S_ISDIR(status.st_mode):
        raise InstallError(f"{secrets_dir}: not a directory. Move it aside and rerun")
    problems: list[str] = []
    needs_sudo = False
    if posix and status.st_uid != os.geteuid():
        needs_sudo = True
        problems.append(f"secrets/ is owned by uid {status.st_uid}, not by you")
    try:
        token_status = _lstat(token)
    except PermissionError:
        needs_sudo = True
        problems.append("secrets/token cannot be inspected: permission denied")
        token_status = None
    if token_status is not None:
        if stat.S_ISLNK(token_status.st_mode):
            raise InstallError(f"{token}: is a symlink; refusing to follow it. Remove the link and rerun")
        foreign = posix and token_status.st_uid != os.geteuid()
        needs_sudo = needs_sudo or foreign
        if stat.S_ISDIR(token_status.st_mode):
            problems.append(
                "secrets/token is a directory" + (f" owned by uid {token_status.st_uid}" if foreign else "")
            )
        elif foreign:
            problems.append(f"secrets/token is owned by uid {token_status.st_uid}, not by you")
    if not problems:
        return
    if not posix:
        remove = "rmdir /s /q secrets"
    else:
        remove = ("sudo " if needs_sudo else "") + "rm -rf ./secrets"
    raise InstallError(
        f"{'; '.join(problems)}. That is what `docker compose up` leaves when it runs before `ctl install` (Docker "
        "creates a directory at a bind-mount source that does not exist), or what running `ctl` under sudo leaves. "
        f"In {root}, run `{remove}`, then `uv run -m ctl install` (without sudo), then `docker compose up`"
    )


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except PermissionError:
        raise
    except OSError as exc:
        raise InstallError(f"{path}: {exc.strerror or exc}") from exc


def _token_landed(secrets_dir: Path, token: bytes) -> bool | None:
    """Whether `secrets/token` now holds `token`; None when it cannot be read."""
    try:
        return (read_file(secrets_dir, "token") or b"").strip() == token
    except (OSError, BinariesError):
        return None


def _install_bridge(config: Config) -> int:
    root = config.root
    secrets_dir, token_path = root / "secrets", root / "secrets" / "token"
    token = config.require("RT_TOKEN").encode("ascii")
    check = compose_file_problems(root, config.values)
    if check.problems:
        raise InstallError("; ".join(check.problems) + f". Nothing was changed; {REMEDY[check.source]} and rerun")
    _refuse_compose_leftovers(root)
    perms.converge_dir(secrets_dir, None, SECRETS_MODE, NO_READERS, root=root)
    previous = read_file(secrets_dir, "token")
    changed = previous is not None and previous.strip() != token
    try:
        if previous is not None and not changed:
            # Same token; any difference is whitespace frps ignores. Rewriting would only change bytes it already read.
            perms.harden_file(token_path, None, NO_READERS, root=root)
        else:
            perms.write_secret(token_path, token + b"\n", None, NO_READERS, root=root)
        perms.harden_file(root / ".env", None, NO_READERS, root=root)
    finally:
        # Whatever failed after the token changed, the running frps still holds the old one and the operator must hear it.
        landed = _token_landed(secrets_dir, token) if changed else False
        if landed is not False:
            holds = "now holds" if landed else "may now hold"
            unread = "" if landed else " (could not re-read it)"
            print(
                f"secrets/token {holds} the new RT_TOKEN{unread}, but a running frps still holds the old one: it reads "
                f"the token once at startup and cannot reload it. Recreate the container to apply the change (`{RECREATE}`). "
                "Recreating drops every connected tunnel, and a host that does not hold the new token will not reconnect.",
                file=sys.stderr,
            )
    print("bridge: secrets/token is in place")
    return 1 if changed else 0


def _uninstall_bridge(config: Config, run: Runner, force: bool) -> int:
    """Take the container down while the file it mounts still exists, then remove `secrets/`."""
    if force:
        print("--force: not checking whether the container is running; skipping `docker compose down`")
    else:
        try:
            status = run(["docker", "compose", "down", "--remove-orphans"], cwd=config.root)
        except FileNotFoundError:
            print(
                "docker was not found on PATH, so whether the frps container is running could not be checked; "
                "secrets/ is kept. Install docker and rerun, or pass --force to remove secrets/ without checking",
                file=sys.stderr,
            )
            return 1
        if status != 0:
            check = compose_file_problems(config.root, config.values)
            reasons = "; ".join(check.problems)
            hint = f" COMPOSE_FILE has problems ({reasons}); {REMEDY[check.source]}, or pass --force." if reasons else ""
            print(f"docker compose down failed (exit {status}); secrets/ is kept.{hint}", file=sys.stderr)
            return 1
    removed = remove_directory(config.root, "secrets")
    print("removed secrets/" if removed else "secrets/ is already absent")
    return 0
