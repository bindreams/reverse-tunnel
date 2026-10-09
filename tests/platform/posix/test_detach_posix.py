"""The detached child: its own session, not a session leader, still running when the parent's call has returned."""

import os
import re
import sys

import pytest

from ctl import detach
from ctl.detach import spawn_detached


@pytest.fixture(autouse=True)
def no_systemd(monkeypatch):
    """What starts the child is tested below with the detection stubbed; the rest must not depend on the machine."""
    monkeypatch.setattr(detach, "systemd_run", lambda: None)


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


# What starts the process ==============================================================================================


def test_under_systemd_the_program_is_started_in_a_scope_of_its_own(monkeypatch):
    """A logind session's cgroup is killed when the session ends; a scope unit is outside it."""
    monkeypatch.setattr(detach, "systemd_run", lambda: "/usr/bin/systemd-run")
    argv = detach.launch_argv(["/venv/bin/python", "-m", "ctl", "install"])
    assert argv[:3] == ["/usr/bin/systemd-run", "--scope", "--collect"]
    assert any(re.fullmatch(r"--unit=reverse-tunnel-apply-[0-9a-f]{8}", part) for part in argv)
    assert argv[argv.index("--") + 1:] == ["/venv/bin/python", "-m", "ctl", "install"]


def test_two_launches_get_different_unit_names(monkeypatch):
    monkeypatch.setattr(detach, "systemd_run", lambda: "/usr/bin/systemd-run")
    units = {next(part for part in detach.launch_argv(["x"]) if part.startswith("--unit=")) for _ in range(5)}
    assert len(units) == 5


def test_without_systemd_the_program_is_started_as_it_is(monkeypatch):
    monkeypatch.setattr(detach, "systemd_run", lambda: None)
    assert detach.launch_argv(["a", "b"]) == ["a", "b"]


def test_systemd_run_is_not_used_where_systemd_is_not_running(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(os.path, "isdir", lambda path: False)
    assert detach.systemd_run() is None


def test_spawn_starts_what_launch_argv_returns(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(detach, "launch_argv", lambda argv: seen.append(argv) or argv)
    report = tmp_path / "report"
    os.mkfifo(report)
    with open(tmp_path / "install.log", "ab") as log:
        spawn_detached([sys.executable, "-c", REPORT, str(report)], cwd=tmp_path, log=log)
    with open(report) as stream:
        stream.read()
    assert seen == [[sys.executable, "-c", REPORT, str(report)]]
