# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Command-line entrypoint: `uv run -m ctl <command>`."""

import argparse
import os
import sys
from collections.abc import Sequence

from pathlib import Path

from ctl import binaries
from ctl.client import render_ssh_config
from ctl.config import Config, ConfigError, Role
from ctl.env import EnvError
from ctl.errors import BinariesError, InstallError
from ctl.install import install, uninstall
from ctl.perms import PermsError

ROOT = Path(__file__).resolve().parent.parent
INHERIT_LOCK = "--inherit-lock"

COMMANDS = {
    "install": "Install or update this deployment.",
    "uninstall": "Remove what `install` created.",
    "doctor": "Diagnose this deployment.",
    "client-config": "Print the ssh_config block for a host.",
    "pin": "Show or update the pinned binaries.",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctl", description="Install and diagnose a reverse-tunnel deployment.", allow_abbrev=False
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, summary in COMMANDS.items():
        subparser = commands.add_parser(name, help=summary, description=summary, allow_abbrev=False)
        if name == "install":
            subparser.add_argument(
                "--allow-self-disconnect",
                action="store_true",
                help="host role: restart websocat even though this session may be running over the tunnel",
            )
            # The detached child of --allow-self-disconnect: the apply phase only, for what the parent staged.
            subparser.add_argument("--apply-staged", action="store_true", help=argparse.SUPPRESS)
            subparser.add_argument("--inherit-lock", type=int, help=argparse.SUPPRESS)
            subparser.add_argument("--started-fd", type=int, help=argparse.SUPPRESS)
        if name == "uninstall":
            subparser.add_argument(
                "--allow-self-disconnect",
                action="store_true",
                help="host role: stop the daemons even though this session may be running over the tunnel",
            )
            subparser.add_argument("--detached", action="store_true", help=argparse.SUPPRESS)
            subparser.add_argument("--inherit-lock", type=int, help=argparse.SUPPRESS)
            subparser.add_argument("--started-fd", type=int, help=argparse.SUPPRESS)
            subparser.add_argument(
                "--force",
                action="store_true",
                help="bridge role: remove secrets/ without checking that the container is down, "
                "for when docker is not available",
            )
        if name == "client-config":
            subparser.add_argument("label", help="the host to reach: its RT_LABEL")
        if name == "pin":
            subparser.add_argument("--update", action="store_true", help="re-pin from the published releases")
            subparser.add_argument("tools", nargs="*", metavar="TOOL", help="with --update: only these tools")
    return parser


def github_token() -> str | None:
    """A token for GitHub's API from the environment, if any; unauthenticated reads are rate limited."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def pin_command(args: argparse.Namespace) -> int:
    if args.tools and not args.update:
        build_parser().error("naming tools requires --update")
    if args.update:
        binaries.refresh(binaries.LOCK_PATH, args.tools or None, token=github_token())
    lock = binaries.load_lock(binaries.LOCK_PATH)
    for tool, by_platform in lock.items():
        for platform, pins in by_platform.items():
            first = pins[0]
            names = ",".join(pin.install_name for pin in pins)
            print(f"{tool} {first.version} {platform} {names} {first.archive_format} sha256:{first.asset_sha256[:12]}")
    return 0


def is_elevated() -> bool:
    """Whether this process is root, or on Windows runs with an elevated (Administrator) token."""
    if sys.platform == "win32":
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def refuse_root(command: str, config: Config) -> None:
    """The bridge and the client run as the operator: what root creates in this directory the operator cannot replace."""
    if config.role in (Role.BRIDGE, Role.CLIENT) and is_elevated():
        raise InstallError(
            f"ROLE={config.role} must not run `{command}` as root (sudo) or from an elevated Administrator prompt: the "
            "files an elevated process creates in this directory (secrets/, bin/) are ones you can no longer replace. "
            "Rerun as yourself"
        )


def require_elevation(command: str, config: Config) -> None:
    """The host role installs system services, which goetia can do only as root or an elevated Administrator."""
    if config.role is Role.HOST and not is_elevated():
        raise InstallError(
            f"ROLE=host: `{command}` needs root. Run `uv sync` as yourself, then `sudo .venv/bin/python -m ctl "
            f"{command}` (on Windows, the same from an elevated Administrator prompt), so that uv and its cache are "
            "not left owned by root"
        )


def check_inherited(args: argparse.Namespace, *, child: bool, flag: str) -> None:
    """The descriptors a detached child is told about mean nothing, and could close the wrong one, anywhere else."""
    if (args.inherit_lock is not None or args.started_fd is not None) and not child:
        build_parser().error(f"--inherit-lock and --started-fd are internal to the detached child ({flag})")
    if args.started_fd is not None and args.inherit_lock is None:
        build_parser().error("--started-fd is valid only with --inherit-lock")


def run_command(args: argparse.Namespace) -> int:
    if args.command == "pin":
        return pin_command(args)
    if args.command in {"install", "uninstall", "client-config"}:
        config = Config.load(args.root)
        if args.command == "install":
            if args.allow_self_disconnect and config.role is not Role.HOST:
                build_parser().error(
                    "--allow-self-disconnect applies to ROLE=host only; this deployment has no websocat to restart"
                )
            if args.apply_staged and not args.allow_self_disconnect:
                build_parser().error("--apply-staged is for the detached child of --allow-self-disconnect")
            check_inherited(args, child=args.apply_staged, flag="--apply-staged")
            refuse_root("install", config)
            require_elevation("install", config)
            return install(
                config,
                allow_self_disconnect=args.allow_self_disconnect,
                apply_staged=args.apply_staged,
                inherit_lock=args.inherit_lock,
                started_fd=args.started_fd,
            )
        if args.command == "uninstall":
            if args.force and config.role is not Role.BRIDGE:
                build_parser().error("--force applies to ROLE=bridge only; no other role checks a container")
            if args.allow_self_disconnect and config.role is not Role.HOST:
                build_parser(
                ).error("--allow-self-disconnect applies to ROLE=host only; this deployment has no daemons to stop")
            if args.detached and not args.allow_self_disconnect:
                build_parser().error("--detached is for the detached child of --allow-self-disconnect")
            check_inherited(args, child=args.detached, flag="--detached")
            refuse_root("uninstall", config)
            require_elevation("uninstall", config)
            if config.role is not Role.HOST:
                return uninstall(config, force=args.force)
            return uninstall(
                config,
                allow_self_disconnect=args.allow_self_disconnect,
                detached=args.detached,
                inherit_lock=args.inherit_lock,
                started_fd=args.started_fd,
            )
        print(render_ssh_config(config, args.label), end="")
        return 0
    print(f"ctl {args.command}: not implemented yet", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """Run a command against the deployment in `root`, which is this checkout unless a test says otherwise.

    The detached child of an install or uninstall (the one given `--inherit-lock`) has nobody watching it, so every way
    it can end, a usage error and a lock it cannot take over included, ends its log with an `apply finished:` line.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    child = any(token == INHERIT_LOCK or token.startswith(INHERIT_LOCK + "=") for token in arguments)
    try:
        args = build_parser().parse_args(arguments)
        args.root = root
        child = getattr(args, "inherit_lock", None) is not None
        code = run_command(args)
    except SystemExit as exc:
        if child and exc.code not in (0, None):
            print(f"apply finished: failed: usage error (exit status {exc.code})", flush=True)
        raise
    except (ConfigError, EnvError, BinariesError, InstallError, PermsError, OSError) as exc:
        print(f"ctl {args.command}: {exc}", file=sys.stderr)
        if child:
            print(f"apply finished: failed: {exc}", flush=True)
        return 1
    except BaseException as exc:
        if child:
            print(f"apply finished: failed: {type(exc).__name__}: {exc}".rstrip(": "), flush=True)
        raise
    if child:
        print("apply finished: ok" if code == 0 else f"apply finished: failed: exit status {code}", flush=True)
    return code
