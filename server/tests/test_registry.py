import os
import stat
import threading

import pytest

from ctl import registry
from ctl.registry import (
    RegistryError,
    locked,
    read_aliases,
    read_hosts,
    write_aliases,
    write_hosts,
)

T = "t.test"
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


def test_hosts_tolerates_hand_edits(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(f"# comment\r\n\r\nzeta {H1}\r\n  alpha\t{H2}  \n   # indented\nmid {H1}".encode())
    assert read_hosts(path) == {"zeta": H1, "alpha": H2, "mid": H1}


def test_hosts_bad_line_reports_line_number(tmp_path):
    path = tmp_path / "hosts"
    path.write_text(f"a {H1}\n\n# c\nb\n")
    with pytest.raises(RegistryError) as err:
        read_hosts(path)
    assert err.value.line_no == 4


@pytest.mark.parametrize(
    "line",
    [
        f"Bad {H1}",
        f"a_b {H1}",
        "a sha256:" + "1" * 63,
        "a sha256:" + "A" * 64,
        "a " + "1" * 64,
        f"a {H1} extra",
        f"dup {H2}",
        "a b�c",
    ],
)
def test_registry_rejects_bad_hosts(tmp_path, line):
    path = tmp_path / "hosts"
    path.write_text(f"ok {H1}\ndup {H1}\n{line}\n", encoding="utf-8")
    with pytest.raises(RegistryError) as err:
        read_hosts(path)
    assert err.value.line_no == 3


@pytest.mark.parametrize(
    "line",
    [
        "movies.example.test jellyfin.other.example",  # backend not under T
        "movies.example.test a.b.c.t.test",  # backend deeper than s.h.T
        "movies.example.test t.test",  # backend is T itself
        "movies.example.test Jellyfin.mothership.t.test",
        "bad`name.example.test jellyfin.mothership.t.test",
        "Movies.example.test jellyfin.mothership.t.test",
        "movies.t.test jellyfin.mothership.t.test",  # public name under T
        "t.test jellyfin.mothership.t.test",
        "movies..example.test jellyfin.mothership.t.test",
        "dup.example.test jellyfin.mothership.t.test",
        "movies.example.test",
    ],
)
def test_registry_rejects_bad_aliases(tmp_path, line):
    path = tmp_path / "aliases"
    path.write_text(f"dup.example.test jellyfin.mothership.t.test\n{line}\n")
    with pytest.raises(RegistryError) as err:
        read_aliases(path, T)
    assert err.value.line_no == 2


def test_registries_round_trip_sorted_with_lf(tmp_path):
    hosts = tmp_path / "hosts"
    write_hosts(hosts, {"b": H2, "a": H1})
    assert hosts.read_bytes() == f"a {H1}\nb {H2}\n".encode()
    assert read_hosts(hosts) == {"a": H1, "b": H2}

    aliases = tmp_path / "aliases"
    write_aliases(aliases, {"z.example.test": "h.t.test", "a.example.test": "s.h.t.test"})
    assert aliases.read_text() == "a.example.test s.h.t.test\nz.example.test h.t.test\n"
    assert read_aliases(aliases, T) == {"z.example.test": "h.t.test", "a.example.test": "s.h.t.test"}


def test_written_mode_0644(tmp_path):
    old = os.umask(0o077)
    try:
        write_hosts(tmp_path / "hosts", {})
        write_aliases(tmp_path / "aliases", {})
    finally:
        os.umask(old)
    for name in ["hosts", "aliases"]:
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o644


def test_atomic_write_fsyncs(tmp_path, monkeypatch):
    synced = []
    real_fsync = os.fsync

    def recording_fsync(fd):
        synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    registry.atomic_write(tmp_path / "f", b"data", 0o600)
    assert synced == [False, True]  # the file, then the directory
    assert (tmp_path / "f").read_bytes() == b"data"
    assert list(tmp_path.iterdir()) == [tmp_path / "f"]


def _blocked_flocks():
    with open("/proc/locks") as f:
        return [line for line in f if "->" in line and f" {os.getpid()} " in line]


def test_locked_excludes(tmp_path):
    acquired = threading.Event()

    def waiter():
        with locked(tmp_path):
            acquired.set()

    thread = threading.Thread(target=waiter)
    with locked(tmp_path):
        thread.start()
        # Spin until the kernel lists a blocked flock, or the waiter got the lock anyway.
        while not _blocked_flocks() and not acquired.is_set():
            os.sched_yield()
        assert not acquired.is_set()
    thread.join()
    assert acquired.is_set()
