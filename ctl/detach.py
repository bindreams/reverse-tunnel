# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Starting a process that outlives the session that started it.

A host install can restart the websocat and frpc that this very ssh session rides on. The apply phase then runs in a
process that the dying session cannot take with it.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import IO

# Windows creation flags, written out so that this module reads the same on every platform.
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
SYSTEMD_RUNTIME = "/run/systemd/system"


def spawn_detached(argv: list[str], *, cwd: Path, log: IO[bytes], inherit: Sequence[int] = ()) -> int:
    """Start `argv` in `cwd` with its output appended to `log` and no input, outside this session; return its pid.

    `inherit` lists descriptors (POSIX) or handles (Windows) the child keeps. The start is reported back: a program that
    cannot be started raises `OSError` here rather than in a log nobody is reading.
    """
    if sys.platform == "win32":
        return _spawn_windows(argv, cwd, log, inherit)
    return _spawn_posix(argv, cwd, log, inherit)


# Windows ==============================================================================================================


def _spawn_windows(argv: list[str], cwd: Path, log: IO[bytes], inherit: Sequence[int]) -> int:
    """Detached from the console, in a group of its own, and outside the job the session runs in.

    A job that kills its processes when the session ends would take the apply phase with it. If the job forbids
    breakaway the start fails with access denied, and that is refused rather than gambled on: nothing has been applied.
    """
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
    startupinfo = None
    if inherit:
        for handle in inherit:
            os.set_handle_inheritable(handle, True)
        startupinfo = subprocess.STARTUPINFO(lpAttributeList={"handle_list": list(inherit)})
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
            close_fds=True,
            startupinfo=startupinfo,
        )
    except PermissionError as exc:
        raise OSError(
            "cannot detach the apply phase: the job this session runs in does not allow a process to break away from "
            f"it, so the apply phase could be killed part-way ({exc}). Nothing has been applied. Run the install from "
            "the console or from a session that is not in such a job"
        ) from exc
    finally:
        for handle in inherit:
            os.set_handle_inheritable(handle, False)
    return process.pid


# POSIX ================================================================================================================


def systemd_run() -> str | None:
    """`systemd-run`, when systemd is what runs this machine."""
    if not sys.platform.startswith("linux") or not os.path.isdir(SYSTEMD_RUNTIME):
        return None
    return shutil.which("systemd-run")


def launch_argv(argv: list[str]) -> list[str]:
    """`argv`, wrapped to run in a systemd scope of its own where there is systemd.

    A login session's processes live in the session's cgroup, and logind can kill that cgroup when the session ends,
    `setsid` or not. A scope unit is outside it. `--scope` makes `systemd-run` register the unit and then run the program
    itself, so the descriptors passed down, the lock among them, are kept.
    """
    runner = systemd_run()
    if runner is None:
        return argv
    unit = f"reverse-tunnel-apply-{secrets.token_hex(4)}"
    return [
        runner, "--scope", "--collect", "--quiet", f"--unit={unit}", "--description=reverse-tunnel apply", "--", *argv
    ]


# Runs in a session of its own (the parent starts it with `setsid`), starts the real program, reports its pid or why it
# could not start on stdout, and exits. The program is then a child of nothing, and not a session leader.
LAUNCHER = """
import json, subprocess, sys
argv, cwd, log, keep = json.loads(sys.argv[1]), sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4])
try:
    process = subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, close_fds=True,
        pass_fds=keep,
    )
    print(json.dumps({"pid": process.pid}))
except OSError as exc:
    print(json.dumps({"errno": exc.errno or 0, "message": exc.strerror or str(exc), "file": str(exc.filename)}))
"""


def _spawn_posix(argv: list[str], cwd: Path, log: IO[bytes], inherit: Sequence[int]) -> int:
    """Two processes and a `setsid` between them, without forking this one (which may hold threads)."""
    fd = log.fileno()
    keep = list(inherit)
    result = subprocess.run(
        [sys.executable, "-c", LAUNCHER,
         json.dumps(launch_argv(argv)),
         str(cwd), str(fd),
         json.dumps(keep)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        pass_fds=(fd, *keep),
        check=False,
    )
    try:
        report = json.loads(result.stdout)
    except ValueError:
        raise OSError(f"the process that detaches the install died before reporting (exit status {result.returncode})")
    if "pid" not in report:
        raise OSError(report["errno"], report["message"], report["file"])
    return report["pid"]
