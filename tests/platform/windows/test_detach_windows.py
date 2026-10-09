"""Detaching on Windows: a process of its own, outside the job the session may run in."""

import subprocess

import pytest

from ctl import detach
from ctl.errors import InstallError

BREAKAWAY = 0x01000000


@pytest.fixture
def breakaway_allowed(monkeypatch):
    monkeypatch.setattr(detach, "job_allows_breakaway", lambda: True)


def test_the_real_job_query_answers_without_raising():
    assert detach.job_allows_breakaway() in (True, False)


def test_the_child_is_detached_in_its_own_group_and_breaks_away_from_the_job(tmp_path, monkeypatch, breakaway_allowed):
    seen = {}

    class Fake:
        pid = 77

        def __init__(self, argv, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(subprocess, "Popen", Fake)
    with open(tmp_path / "install.log", "ab") as log:
        assert detach.spawn_detached(["x.exe"], cwd=tmp_path, log=log) == 77
    flags = seen["creationflags"]
    assert flags & BREAKAWAY and flags & subprocess.DETACHED_PROCESS and flags & subprocess.CREATE_NEW_PROCESS_GROUP


def test_a_job_that_forbids_breakaway_is_a_refusal_before_anything_is_started(tmp_path, monkeypatch):
    monkeypatch.setattr(detach, "job_allows_breakaway", lambda: False)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("nothing may be started"))
    with open(tmp_path / "install.log", "ab") as log, pytest.raises(OSError, match="job"):
        detach.spawn_detached(["x.exe"], cwd=tmp_path, log=log)


def test_an_access_denied_on_the_program_itself_is_not_blamed_on_the_job(tmp_path, monkeypatch, breakaway_allowed):

    def refuse(argv, **kwargs):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    with open(tmp_path / "install.log", "ab") as log, pytest.raises(PermissionError) as raised:
        detach.spawn_detached(["x.exe"], cwd=tmp_path, log=log)
    assert "job" not in str(raised.value)


def test_check_can_detach_refuses_in_a_job_that_forbids_breakaway(monkeypatch):
    monkeypatch.setattr(detach, "job_allows_breakaway", lambda: False)
    with pytest.raises(InstallError, match="job"):
        detach.check_can_detach()
    monkeypatch.setattr(detach, "job_allows_breakaway", lambda: True)
    detach.check_can_detach()


def test_the_real_membership_query_answers_without_raising():
    assert detach.process_in_job() in (True, False)


def test_a_child_still_inside_any_job_does_not_claim_it_can_survive(monkeypatch):
    """With nested jobs the breakaway query sees only the innermost; an outer kill-on-close job would still end the child."""
    monkeypatch.setattr(detach, "process_in_job", lambda: True)
    assert detach.survival_problem() == detach.STILL_IN_A_JOB
    monkeypatch.setattr(detach, "process_in_job", lambda: False)
    assert detach.survival_problem() is None


def test_the_child_command_uses_the_real_interpreter_isolated_and_with_each_path_its_own_argument():
    """A venv's python.exe may be a launcher that puts the real interpreter in a kill-on-close job."""
    import sys

    argv = detach.python_command(["install", "--apply-staged"])
    assert argv[0] == getattr(sys, "_base_executable", sys.executable)
    assert argv[1:4] == ["-I", "-S", "-c"]
    assert argv[-2:] == ["install", "--apply-staged"]
    site_packages, root = argv[5], argv[6]
    assert site_packages.lower().endswith("site-packages") and ";" not in site_packages + root


def test_a_child_started_from_the_venv_is_in_no_job_and_says_so(tmp_path):
    from ctl import handshake

    body = "from ctl import detach, handshake\nhandshake.signal(int(sys.argv[3]), refusal=detach.survival_problem())\n"
    pipe = handshake.Pipe()
    prefix = detach.python_command([])
    argv = [prefix[0], "-I", "-S", "-c", detach.ISOLATED_SETUP + body, prefix[5], prefix[6], str(pipe.token)]
    with open(tmp_path / "install.log", "ab") as log:
        detach.spawn_detached(argv, cwd=tmp_path, log=log, inherit=[pipe.token])
    assert pipe.wait() is True, pipe.refusal
