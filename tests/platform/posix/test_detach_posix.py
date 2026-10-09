"""The detached child: its own session, not a session leader, still running when the parent's call has returned."""

import os
import sys

import pytest

from ctl.detach import spawn_detached

REPORT = """
import os, sys
print("hello from the child", flush=True)
with open(sys.argv[1], "w") as report:
    report.write(f"{os.getsid(0)} {os.getpid()} {os.getcwd()}")
"""


def test_the_child_leaves_the_parent_s_session_and_is_not_a_session_leader(tmp_path):
    """Two forks and a `setsid` between them: the child cannot reacquire a controlling terminal, and a hangup on the
    parent's does not reach it."""
    report = tmp_path / "report"
    os.mkfifo(report)
    with open(tmp_path / "install.log", "ab") as log:
        pid = spawn_detached([sys.executable, "-c", REPORT, str(report)], cwd=tmp_path, log=log)
    # Opening a FIFO for reading waits for the child to open it for writing: the child's own report is the signal.
    with open(report) as stream:
        session, child, cwd = stream.read().split()
    assert int(child) == pid
    assert int(session) not in (os.getsid(0), pid)
    assert os.path.realpath(cwd) == os.path.realpath(tmp_path)


def test_the_child_writes_to_the_log_and_reads_nothing(tmp_path):
    report = tmp_path / "report"
    os.mkfifo(report)
    with open(tmp_path / "install.log", "ab") as log:
        spawn_detached([sys.executable, "-c", REPORT, str(report)], cwd=tmp_path, log=log)
    with open(report) as stream:
        stream.read()
    assert (tmp_path / "install.log").read_text() == "hello from the child\n"


def test_a_program_that_cannot_start_is_reported_by_the_parent(tmp_path):
    with open(tmp_path / "install.log", "ab") as log, pytest.raises(OSError):
        spawn_detached([str(tmp_path / "no-such-program")], cwd=tmp_path, log=log)
