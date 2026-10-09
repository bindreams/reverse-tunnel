"""Detaching on Windows: a process of its own, outside the job the session may run in."""

import subprocess

import pytest

from ctl import detach

BREAKAWAY = 0x01000000


class Recorded(Exception):
    pass


def test_the_child_is_detached_in_its_own_group_and_breaks_away_from_the_job(tmp_path, monkeypatch):
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


def test_a_job_that_forbids_breakaway_is_a_refusal_not_a_child_that_may_die_mid_apply(tmp_path, monkeypatch):

    def refuse(argv, **kwargs):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    with open(tmp_path / "install.log", "ab") as log, pytest.raises(OSError, match="job"):
        detach.spawn_detached(["x.exe"], cwd=tmp_path, log=log)
