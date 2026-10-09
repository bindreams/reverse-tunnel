"""The start handshake: the detached child says it has taken over, or the parent learns that it never will.

Nothing here waits on a clock. The parent blocks reading a pipe whose write end only the child (and, for an instant, the
parent) holds, so the read ends with a byte or with end of file, and never otherwise.
"""

import os
import stat
import sys
import textwrap

import pytest

from ctl import detach, handshake
from ctl.detach import spawn_detached

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SIGNAL = f"import sys; sys.path.insert(0, {REPO!r}); from ctl import handshake; handshake.signal(int(sys.argv[1]))"


@pytest.fixture(autouse=True)
def no_systemd(monkeypatch):
    """These tests are about the handshake, not about which launcher starts the child."""
    monkeypatch.setattr(detach, "systemd_run", lambda: None)


def start(tmp_path, program: list[str], pipe: handshake.Pipe) -> None:
    with open(tmp_path / "install.log", "ab") as log:
        spawn_detached(program, cwd=tmp_path, log=log, inherit=[pipe.token])


def test_a_child_that_signals_is_reported_as_started(tmp_path):
    pipe = handshake.Pipe()
    start(tmp_path, [sys.executable, "-c", SIGNAL, str(pipe.token)], pipe)
    assert pipe.wait() is True


def test_a_child_that_exits_without_signalling_is_reported_as_not_started(tmp_path):
    pipe = handshake.Pipe()
    start(tmp_path, [sys.executable, "-c", "raise SystemExit(3)"], pipe)
    assert pipe.wait() is False


def test_a_program_that_cannot_be_started_is_reported_by_spawn_and_the_wait_still_ends(tmp_path):
    pipe = handshake.Pipe()
    with pytest.raises(OSError):
        start(tmp_path, [str(tmp_path / "no-such-program")], pipe)
    assert pipe.wait() is False


FAKE_DENIED = """
import sys
sys.stderr.write("Failed to start transient scope unit: Access denied\\n")
sys.exit(1)
"""

FAKE_SCOPE = """
import os, sys
os.execv(sys.argv[1], sys.argv[1:])
"""


def fake_systemd_run(tmp_path, monkeypatch, body: str) -> None:
    script = tmp_path / "fake-systemd-run.py"
    script.write_text(textwrap.dedent(body))
    monkeypatch.setattr(detach, "launch_argv", lambda argv: [sys.executable, str(script), *argv])


def test_systemd_run_being_denied_is_reported_and_its_message_reaches_the_log(tmp_path, monkeypatch):
    """The pid the parent gets back is systemd-run's, so the handshake is the only way to learn that nothing ran."""
    fake_systemd_run(tmp_path, monkeypatch, FAKE_DENIED)
    pipe = handshake.Pipe()
    start(tmp_path, [sys.executable, "-c", SIGNAL, str(pipe.token)], pipe)
    assert pipe.wait() is False
    assert "Access denied" in (tmp_path / "install.log").read_text()


def test_systemd_run_that_runs_the_program_in_place_is_reported_as_started(tmp_path, monkeypatch):
    fake_systemd_run(tmp_path, monkeypatch, FAKE_SCOPE)
    pipe = handshake.Pipe()
    start(tmp_path, [sys.executable, "-c", SIGNAL, str(pipe.token)], pipe)
    assert pipe.wait() is True


def test_the_parent_s_own_copy_is_closed_first_so_an_absent_child_cannot_hang_it(tmp_path):
    pipe = handshake.Pipe()
    token = pipe.token
    assert pipe.wait() is False  # nothing holds the write end but the parent's copy, which wait() closes before reading
    with pytest.raises(OSError):
        os.fstat(token)


def test_signalling_writes_one_byte_and_closes_the_descriptor():
    pipe = handshake.Pipe()
    child = os.dup(pipe.token)
    handshake.signal(child)
    with pytest.raises(OSError):
        os.fstat(child)
    assert pipe.wait() is True


def test_the_descriptor_handed_to_the_child_is_not_inheritable_until_spawn_passes_it():
    pipe = handshake.Pipe()
    try:
        assert not os.get_inheritable(pipe.token)
        assert stat.S_ISFIFO(os.fstat(pipe.token).st_mode)
    finally:
        pipe.close()


def test_systemd_run_is_only_considered_for_root(monkeypatch):
    """`systemd-run --scope` as an ordinary user asks polkit for a password, which would hang an unattended run."""
    monkeypatch.undo()  # the real detection, not the stub every other test here installs
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os.path, "isdir", lambda path: True)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/systemd-run")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert detach.systemd_run() is None
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert detach.systemd_run() == "/usr/bin/systemd-run"
