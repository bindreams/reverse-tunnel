# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Command-line entrypoint: `uv run -m ctl <command>`."""

import argparse
import sys
from collections.abc import Sequence

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
        commands.add_parser(name, help=summary, description=summary)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"ctl {args.command}: not implemented yet", file=sys.stderr)
    return 1
