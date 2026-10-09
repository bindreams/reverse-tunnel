# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Starting a process that outlives the session that started it.

A host install can restart the websocat that this very ssh session rides on. The apply phase then runs in a process
that the dying session cannot take with it.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import IO


def spawn_detached(argv: list[str], *, cwd: Path, log: IO[bytes]) -> int:
    """Start `argv` in `cwd` with its output appended to `log` and no input, outside this session; return its pid.

    The start is reported back: a program that cannot be started raises `OSError` here rather than in a log nobody is
    reading. Windows has no sessions to leave, so the process is detached from the console and given its own group.
    """
    if sys.platform == "win32":
        return _spawn_windows(argv, cwd, log)
    return _spawn_posix(argv, cwd, log)


def _spawn_windows(argv: list[str], cwd: Path, log: IO[bytes]) -> int:
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=flags,
        close_fds=True
    )
    return process.pid


# Runs in a session of its own (the parent starts it with `setsid`), starts the real program, reports its pid or why it
# could not start on stdout, and exits. The program is then a child of nothing, and not a session leader.
LAUNCHER = """
import json, subprocess, sys
argv, cwd, log = json.loads(sys.argv[1]), sys.argv[2], int(sys.argv[3])
try:
    process = subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, close_fds=True
    )
    print(json.dumps({"pid": process.pid}))
except OSError as exc:
    print(json.dumps({"errno": exc.errno or 0, "message": exc.strerror or str(exc), "file": str(exc.filename)}))
"""


def _spawn_posix(argv: list[str], cwd: Path, log: IO[bytes]) -> int:
    """Two processes and a `setsid` between them, without forking this one (which may hold threads)."""
    fd = log.fileno()
    result = subprocess.run(
        [sys.executable, "-c", LAUNCHER, json.dumps(argv),
         str(cwd), str(fd)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        pass_fds=(fd, ),
        check=False,
    )
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise OSError(f"the process that detaches the install died before reporting (exit status {result.returncode})")
    if "pid" not in report:
        raise OSError(report["errno"], report["message"], report["file"])
    return report["pid"]
