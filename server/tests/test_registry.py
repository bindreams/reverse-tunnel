import os
import stat
import threading

import pytest

from ctl import registry
from ctl.registry import (
    RegistryError,
    locked,
    put,
    read_aliases,
    read_hosts,
    write_aliases,
    write_hosts,
)

T = "t.test"
MOVIES = "movies.binarydreams.me"
DUP = "dup.binarydreams.me"
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


def test_hosts_tolerates_hand_edits(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_bytes(f"# comment\r\n\r\nzeta: {H1}\r\n  # indented\r\nalpha: {H2}  # mine \nmid: {H1}".encode())
    assert read_hosts(path) == {"zeta": H1, "alpha": H2, "mid": H1}


@pytest.mark.parametrize(
    "text, line_no",
    [
        ("a: x\n\nb: [1, 2}\n", 3),
        ("a: x\nb\n", 2),
        ("a: x\nb\x00: y\n", 2),
        ("a: x\n- y\n", 2),
        ("- y\n", 1),
        ("a: " + "[" * 100_000 + "]" * 100_000 + "\n", 1),
        ("a: " + "9" * 5000 + "\n", 1),
        ("&r\na: *r\n", 2),
        ("a: x\n<<: {Bad_: y}\n", 2),
    ],
    ids=[
        "bad-flow",
        "missing-colon",
        "control-character",
        "list-in-mapping",
        "list",
        "too-deeply-nested",
        "huge-integer",
        "self-referential",
        "merge-key",
    ],
)
def test_unparseable_registry_names_a_line(tmp_path, text, line_no):
    path = tmp_path / "hosts.yaml"
    path.write_text(text)
    with pytest.raises(RegistryError) as err:
        read_hosts(path)
    assert err.value.line_no == line_no


@pytest.mark.parametrize(
    "line",
    [
        f"Bad: {H1}",
        "a: sha256:" + "1" * 63,
        "a: sha256:" + "A" * 64,
        "a: " + "1" * 64,
        f"dup: {H2}",
    ],
)
def test_registry_rejects_bad_hosts(tmp_path, line):
    path = tmp_path / "hosts.yaml"
    path.write_text(f"ok: {H1}\ndup: {H1}\n{line}\n", encoding="utf-8")
    with pytest.raises(RegistryError) as err:
        read_hosts(path)
    assert err.value.line_no == 3


def test_non_string_key_is_rejected_with_line(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_text(f"a: {H1}\nnull: {H1}\n")
    with pytest.raises(RegistryError, match="quote") as err:
        read_hosts(path)
    assert err.value.line_no == 2


def test_hosts_undecodable_bytes_name_their_line(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_bytes(f"a: {H1}\nb".encode() + b"\xff\xfe: " + H1.encode() + b"\n")
    with pytest.raises(RegistryError) as err:
        read_hosts(path)
    assert err.value.line_no == 2


@pytest.mark.parametrize(
    "line",
    [
        "Movies.binarydreams.me: jellyfin.mothership.t.test",
        f"{MOVIES}: jellyfin.other.example",
        f"{DUP}: jellyfin.mothership.t.test",
        f"{MOVIES}:",
    ],
)
def test_registry_rejects_bad_aliases(tmp_path, line):
    path = tmp_path / "aliases.yaml"
    path.write_text(f"{DUP}: jellyfin.mothership.t.test\n{line}\n")
    with pytest.raises(RegistryError) as err:
        read_aliases(path, T)
    assert err.value.line_no == 2


@pytest.mark.parametrize("public", ["movies.tunnel.binarydreams.me", "tunnel.binarydreams.me"])
def test_alias_public_name_under_the_tunnel_domain_is_rejected(tmp_path, public):
    path = tmp_path / "aliases.yaml"
    path.write_text(f"{public}: jellyfin.mothership.tunnel.binarydreams.me\n")
    with pytest.raises(RegistryError, match="under the tunnel domain") as err:
        read_aliases(path, "tunnel.binarydreams.me")
    assert err.value.line_no == 1


def test_hosts_tolerates_a_utf8_bom(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_bytes(b"\xef\xbb\xbf" + f"a: {H1}\n".encode())
    assert read_hosts(path) == {"a": H1}


def test_empty_registry_reads_as_empty(tmp_path):
    path = tmp_path / "registry.yaml"
    path.write_bytes(b"")
    assert read_hosts(path) == {}
    assert read_aliases(path, T) == {}


def test_missing_registry_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_hosts(tmp_path / "hosts.yaml")
    with pytest.raises(FileNotFoundError):
        read_aliases(tmp_path / "aliases.yaml", T)


def test_write_hosts_refuses_what_the_reader_rejects(tmp_path):
    path = tmp_path / "hosts.yaml"
    write_hosts(path, {"keep": H1})
    for bad, culprit in [({"ok": H1, "Bad": H1}, "Bad"), ({"ok": "sha256:1"}, "ok")]:
        with pytest.raises(RegistryError, match=f"^{culprit}:"):
            write_hosts(path, bad)
    assert read_hosts(path) == {"keep": H1}


@pytest.mark.parametrize(
    "bad",
    [
        {"movies.test": "jellyfin.mothership.t.test"},
        {MOVIES: "other.example"},
        {"movies.t.test": "jellyfin.mothership.t.test"},
    ],
)
def test_write_aliases_refuses_what_the_reader_rejects(tmp_path, bad):
    path = tmp_path / "aliases.yaml"
    write_aliases(path, {DUP: "s.h.t.test"}, T)
    with pytest.raises(RegistryError):
        write_aliases(path, bad, T)
    assert read_aliases(path, T) == {DUP: "s.h.t.test"}


def test_put_inserts_in_sorted_position_and_the_file_is_written_with_lf(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_bytes(f"b: {H1}  # b\r\nd: {H1}\r\n".encode())
    hosts = read_hosts(path)
    for name in ["e", "c", "a"]:
        put(hosts, name, H2)
    write_hosts(path, hosts)
    assert path.read_bytes() == f"a: {H2}\nb: {H1}  # b\nc: {H2}\nd: {H1}\ne: {H2}\n".encode()


def test_rewrite_refuses_to_replace_undecodable_bytes_in_a_comment(tmp_path):
    path = tmp_path / "hosts.yaml"
    original = f"a: {H1}  # caf".encode() + b"\xe9\n"
    path.write_bytes(original)
    hosts = read_hosts(path)
    put(hosts, "b", H2)
    with pytest.raises(RegistryError, match="line 1:"):
        write_hosts(path, hosts)
    assert path.read_bytes() == original


def test_comments_survive_when_an_empty_registry_gains_its_first_entry(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_text("# my hosts\n")
    hosts = read_hosts(path)
    put(hosts, "a", H1)
    write_hosts(path, hosts)
    assert path.read_text() == f"# my hosts\n\na: {H1}\n"


def test_written_mode_0644(tmp_path):
    old = os.umask(0o077)
    try:
        write_hosts(tmp_path / "hosts.yaml", {})
        write_aliases(tmp_path / "aliases.yaml", {}, T)
    finally:
        os.umask(old)
    for name in ["hosts.yaml", "aliases.yaml"]:
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


def test_atomic_write_cleanup_failure_keeps_the_original_error(tmp_path, monkeypatch):
    def failing_replace(src, dst):
        raise OSError("replace failed")

    def failing_unlink(path):
        raise PermissionError("unlink refused")

    monkeypatch.setattr(os, "replace", failing_replace)
    monkeypatch.setattr(os, "unlink", failing_unlink)
    with pytest.raises(OSError, match="replace failed"):
        registry.atomic_write(tmp_path / "f", b"data", 0o600)


def test_atomic_write_over_an_existing_file_gives_new_content_and_mode(tmp_path):
    target = tmp_path / "f"
    target.write_bytes(b"old")
    target.chmod(0o600)
    registry.atomic_write(target, b"new", 0o644)
    assert target.read_bytes() == b"new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert list(tmp_path.iterdir()) == [target]


def test_atomic_write_failed_replace_keeps_the_old_file(tmp_path, monkeypatch):
    target = tmp_path / "f"
    target.write_bytes(b"old")
    target.chmod(0o600)

    def failing_replace(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError, match="replace failed"):
        registry.atomic_write(target, b"new", 0o644)
    assert target.read_bytes() == b"old"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(tmp_path.iterdir()) == [target]


def test_lock_file_mode_0644(tmp_path):
    old = os.umask(0o077)
    try:
        with locked(tmp_path):
            pass
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "lock").stat().st_mode) == 0o644


def test_locked_works_on_a_read_only_lock_file(tmp_path):
    lock = tmp_path / "lock"
    lock.touch(mode=0o444)
    with locked(tmp_path):
        pass
    assert stat.S_IMODE(lock.stat().st_mode) == 0o444


def test_locked_acquires_after_losing_the_creation_race(tmp_path, monkeypatch):
    real_link = os.link

    def link_after_another_operator_created_it(src, dst):
        (tmp_path / "lock").touch(mode=0o600)
        real_link(src, dst)

    monkeypatch.setattr(os, "link", link_after_another_operator_created_it)
    with locked(tmp_path):
        pass
    assert stat.S_IMODE((tmp_path / "lock").stat().st_mode) == 0o600


def _blocked_flocks():
    with open("/proc/locks") as f:
        return [line for line in f if "->" in line and f" {os.getpid()} " in line]


def test_locked_excludes(tmp_path):
    acquired = threading.Event()
    failures = []

    def waiter():
        try:
            with locked(tmp_path):
                acquired.set()
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=waiter)
    with locked(tmp_path):
        thread.start()
        # Wait for the waiter to block on the flock (or end).
        while thread.is_alive() and not _blocked_flocks():
            os.sched_yield()
        if failures:
            raise failures[0]
        assert not acquired.is_set()
    thread.join()
    assert acquired.is_set()
