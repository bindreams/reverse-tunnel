import errno
import os

import pytest

from ctl import perms
from ctl.config import ConfigError
from ctl.perms import Account, PermsError, converge_tree, harden_file, resolve_service_account, write_secret

NO_READERS: frozenset[str] = frozenset()


def test_resolve_service_account_rejects_a_missing_account():
    with pytest.raises(ConfigError) as raised:
        resolve_service_account("rt-no-such-account")
    assert "rt-no-such-account" in str(raised.value)


def test_resolve_service_account_rejects_uid_zero(monkeypatch):
    monkeypatch.setattr(perms, "_lookup_account", lambda name: Account(name, 0, 0))
    with pytest.raises(ConfigError) as raised:
        resolve_service_account("anyone")
    assert "anyone" in str(raised.value)
    assert "root" in str(raised.value)


def test_write_secret_writes_the_exact_bytes(tmp_path):
    path = tmp_path / "token"
    data = bytes(range(256)) + b"\r\n\n"
    write_secret(path, data, None, NO_READERS)
    assert path.read_bytes() == data


def test_write_secret_replaces_the_previous_contents(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"a-much-longer-previous-value", None, NO_READERS)
    write_secret(path, b"short", None, NO_READERS)
    assert path.read_bytes() == b"short"


def test_write_secret_refuses_a_symlink_at_the_destination(tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"untouched")
    link = tmp_path / "token"
    link.symlink_to(sentinel)
    with pytest.raises(PermsError) as raised:
        write_secret(link, b"the-secret", None, NO_READERS)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)
    assert sentinel.read_bytes() == b"untouched"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["sentinel", "token"]


def test_write_secret_refuses_a_dangling_symlink(tmp_path):
    target = tmp_path / "absent"
    link = tmp_path / "token"
    link.symlink_to(target)
    with pytest.raises(PermsError):
        write_secret(link, b"the-secret", None, NO_READERS)
    assert not target.exists()


def test_harden_file_refuses_a_symlink(tmp_path):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)
    with pytest.raises(PermsError) as raised:
        harden_file(link, None, NO_READERS)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)


def names(directory) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def test_write_secret_leaves_only_the_destination(tmp_path):
    write_secret(tmp_path / "token", b"secret", None, NO_READERS)
    assert names(tmp_path) == ["token"]


def test_write_secret_keeps_the_previous_secret_when_the_write_fails(tmp_path, monkeypatch):
    path = tmp_path / "token"
    write_secret(path, b"old", None, NO_READERS)

    def full_disk(fd, data):
        raise OSError(errno.ENOSPC, "no space left on device")

    monkeypatch.setattr(os, "write", full_disk)
    with pytest.raises(OSError):
        write_secret(path, b"new", None, NO_READERS)
    monkeypatch.undo()
    assert path.read_bytes() == b"old"
    assert names(tmp_path) == ["token"]


def test_write_secret_keeps_the_previous_secret_when_it_cannot_replace_it(tmp_path):
    path = tmp_path / "token"
    path.mkdir()
    with pytest.raises(PermsError) as raised:
        write_secret(path, b"new", None, NO_READERS)
    assert str(path) in str(raised.value)
    assert names(tmp_path) == ["token"]
    assert path.is_dir()


def test_harden_file_refuses_a_hard_linked_file(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"A=1\n")
    env = tmp_path / ".env"
    os.link(other, env)
    with pytest.raises(PermsError) as raised:
        harden_file(env, None, NO_READERS)
    assert str(env) in str(raised.value)
    assert "hard link" in str(raised.value)


def test_write_secret_refuses_a_hard_linked_destination(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"the-old-secret")
    token = tmp_path / "token"
    os.link(other, token)
    with pytest.raises(PermsError) as raised:
        write_secret(token, b"new", None, NO_READERS)
    assert "hard link" in str(raised.value)
    assert other.read_bytes() == b"the-old-secret"


def test_converge_tree_refuses_a_subdirectory(tmp_path):
    logs = tmp_path / "logs"
    (logs / "old").mkdir(parents=True)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, None, 0o750)
    assert str(logs / "old") in str(raised.value)
    assert "remove it" in str(raised.value)


def test_converge_tree_accepts_a_flat_directory_of_regular_files(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "frpc.log").write_bytes(b"")
    (logs / "websocat.log").write_bytes(b"")
    converge_tree(logs, None, 0o750)
