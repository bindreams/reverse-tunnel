# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Command-line entrypoint: `uv run -m ctl <command>`."""

import argparse
import os
import sys
from collections.abc import Sequence

from pathlib import Path

from ctl import binaries
from ctl.client import render_ssh_config
from ctl.config import Config, ConfigError
from ctl.env import EnvError
from ctl.errors import BinariesError, InstallError
from ctl.install import install, uninstall
from ctl.perms import PermsError

ROOT = Path(__file__).resolve().parent.parent

COMMANDS = {
    "install": "Install or update this deployment.",
    "uninstall": "Remove what `install` created.",
    "doctor": "Diagnose this deployment.",
    "client-config": "Print the ssh_config block for a host.",
    "pin": "Show or update the pinned binaries.",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctl", description="Install and diagnose a reverse-tunnel deployment.")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, summary in COMMANDS.items():
        subparser = commands.add_parser(name, help=summary, description=summary)
        if name == "install":
            subparser.add_argument(
                "--allow-self-disconnect",
                action="store_true",
                help="host role: restart websocat even though this session may be running over the tunnel",
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


def run_command(args: argparse.Namespace) -> int:
    if args.command == "pin":
        return pin_command(args)
    if args.command in {"install", "uninstall", "client-config"}:
        config = Config.load(args.root)
        if args.command == "install":
            return install(config, allow_self_disconnect=args.allow_self_disconnect)
        if args.command == "uninstall":
            return uninstall(config)
        print(render_ssh_config(config, args.label), end="")
        return 0
    print(f"ctl {args.command}: not implemented yet", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None, *, root: Path = ROOT) -> int:
    """Run a command against the deployment in `root`, which is this checkout unless a test says otherwise."""
    args = build_parser().parse_args(argv)
    args.root = root
    try:
        return run_command(args)
    except (ConfigError, EnvError, BinariesError, InstallError, PermsError) as exc:
        print(f"ctl {args.command}: {exc}", file=sys.stderr)
        return 1
