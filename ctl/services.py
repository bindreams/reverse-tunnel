# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""What an install reaches outside the tree: the pins, the platform, the downloader, docker, and detaching."""

import dataclasses
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import IO, Protocol

from ctl import binaries, detach
from ctl.download import Fetcher


class Runner(Protocol):

    def __call__(self, args: list[str], *, cwd: Path) -> int:
        """Run `args` in `cwd` and return its exit status; raise `FileNotFoundError` if the program does not exist."""


def run_command(args: list[str], *, cwd: Path) -> int:
    return subprocess.run(args, cwd=cwd, check=False).returncode


class Spawner(Protocol):

    def __call__(self, argv: list[str], *, cwd: Path, log: IO[bytes]) -> int:
        """Start `argv` detached from this session, its output appended to `log`; return its pid."""


@dataclasses.dataclass(frozen=True)
class Services:
    """What install reaches outside the tree: the pins, the platform, the downloader, docker, and detaching."""

    lock_path: Path = binaries.LOCK_PATH
    platform: str | None = None  # None: this machine's
    fetcher: Callable[[], Fetcher] = Fetcher
    run: Runner = run_command
    spawn: Spawner = detach.spawn_detached
