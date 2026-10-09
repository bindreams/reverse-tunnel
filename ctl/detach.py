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

from ctl.errors import InstallError

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

JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
NO_BREAKAWAY = (
    "the job this session runs in does not allow a process to break away from it, so a detached apply phase could be "
    "killed part-way. Nothing has been applied. Run the install from the console or from a session that is not in such "
    "a job"
)


def _kernel32():
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)
    ]
    return kernel32


def process_in_job() -> bool:
    """Whether this process belongs to any job object, however deeply nested."""
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    in_job = wintypes.BOOL()
    if not kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(in_job)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(in_job.value)


STILL_IN_A_JOB = "still inside a job object; cannot guarantee surviving the session"


def survival_problem() -> str | None:
    """Why this process, just started detached, could not outlive its session; None if nothing says it could not.

    `job_allows_breakaway` sees only the innermost job. With nested jobs a child that broke out of that one can still be
    inside an outer job that kills its processes when the session ends, so the child checks for itself, once started,
    whether it is in any job at all.
    """
    if sys.platform == "win32" and process_in_job():
        return STILL_IN_A_JOB
    return None


def job_allows_breakaway() -> bool:
    """Whether this process may start one that leaves its job: it is in no job, or the job permits breakaway."""
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount",
            "WriteTransferCount", "OtherTransferCount"
        )]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimits),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = _kernel32()
    if not process_in_job():
        return True
    limits = ExtendedLimits()
    # A null job handle asks about the job the calling process belongs to.
    if not kernel32.QueryInformationJobObject(
        None, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS, ctypes.byref(limits), ctypes.sizeof(limits), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    flags = limits.BasicLimitInformation.LimitFlags
    return bool(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))


# Adds the directories named in argv[1] the way `site` does, `.pth` files included (pywin32 depends on one), which
# `PYTHONPATH` would not.
PRELUDE = """
import os, site, sys
for path in sys.argv[1].split(os.pathsep):
    site.addsitedir(path)
"""
BOOTSTRAP = PRELUDE + """
import runpy
sys.argv = ["ctl", *sys.argv[2:]]
runpy.run_module("ctl", run_name="__main__", alter_sys=True)
"""


def python_command(arguments: list[str]) -> list[str]:
    """The command that runs `python -m ctl <arguments>` as a detached child.

    On Windows a venv's `python.exe` can be a redirector that starts the real interpreter inside a job that kills it
    with the redirector, which would take a detached child down with the session. So the child is started from the real
    interpreter, given the venv's packages and the repository, and runs `ctl` the way `-m` does.
    """
    if sys.platform != "win32":
        return [sys.executable, "-m", "ctl", *arguments]
    import sysconfig

    root = Path(__file__).resolve().parent.parent
    paths = {sysconfig.get_path("purelib"), sysconfig.get_path("platlib")}
    interpreter = getattr(sys, "_base_executable", sys.executable)
    return [interpreter, "-c", BOOTSTRAP, os.pathsep.join([*sorted(paths), str(root)]), *arguments]


def check_can_detach() -> None:
    """Raise `InstallError` if a detached process could not leave this session's job. Nothing else to check elsewhere."""
    if sys.platform == "win32" and not job_allows_breakaway():
        raise InstallError(f"cannot detach the apply phase: {NO_BREAKAWAY}")


def _spawn_windows(argv: list[str], cwd: Path, log: IO[bytes], inherit: Sequence[int]) -> int:
    """Detached from the console, in a group of its own, and outside the job the session runs in.

    The job is asked first, because `CreateProcess` answers a refused breakaway with the same access denied as a program
    that may not be run, and the two need different words. An access denied after the job allowed breakaway is the program.
    """
    if not job_allows_breakaway():
        raise OSError(f"cannot detach the apply phase: {NO_BREAKAWAY}")
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
    finally:
        for handle in inherit:
            os.set_handle_inheritable(handle, False)
    return process.pid


# POSIX ================================================================================================================


def systemd_run() -> str | None:
    """`systemd-run`, when systemd is what runs this machine and this is root.

    Only root: for anyone else `systemd-run --scope` asks polkit for authority, which an unattended run cannot answer.
    A host install is always root, so nothing real is lost.
    """
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or not os.path.isdir(SYSTEMD_RUNTIME):
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
