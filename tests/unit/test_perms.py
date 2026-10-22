import errno
import os

import pytest

from ctl import perms
from ctl.config import ConfigError
from ctl.perms import Account, PermsError, harden_file, resolve_service_account, write_secret

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
    write_secret(path, data, None, NO_READERS, root=tmp_path)
    assert path.read_bytes() == data


def test_write_secret_replaces_the_previous_contents(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"a-much-longer-previous-value", None, NO_READERS, root=tmp_path)
    write_secret(path, b"short", None, NO_READERS, root=tmp_path)
    assert path.read_bytes() == b"short"


def test_write_secret_refuses_a_symlink_at_the_destination(tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"untouched")
    link = tmp_path / "token"
    link.symlink_to(sentinel)
    with pytest.raises(PermsError) as raised:
        write_secret(link, b"the-secret", None, NO_READERS, root=tmp_path)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)
    assert sentinel.read_bytes() == b"untouched"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["sentinel", "token"]


def test_write_secret_refuses_a_dangling_symlink(tmp_path):
    target = tmp_path / "absent"
    link = tmp_path / "token"
    link.symlink_to(target)
    with pytest.raises(PermsError):
        write_secret(link, b"the-secret", None, NO_READERS, root=tmp_path)
    assert not target.exists()


def test_harden_file_refuses_a_symlink(tmp_path):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)
    with pytest.raises(PermsError) as raised:
        harden_file(link, None, NO_READERS, root=tmp_path)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)


def names(directory) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def test_write_secret_leaves_only_the_destination(tmp_path):
    write_secret(tmp_path / "token", b"secret", None, NO_READERS, root=tmp_path)
    assert names(tmp_path) == ["token"]


def test_write_secret_keeps_the_previous_secret_when_the_write_fails(tmp_path, monkeypatch):
    path = tmp_path / "token"
    write_secret(path, b"old", None, NO_READERS, root=tmp_path)

    def full_disk(fd, data):
        raise OSError(errno.ENOSPC, "no space left on device")

    monkeypatch.setattr(os, "write", full_disk)
    with pytest.raises(OSError):
        write_secret(path, b"new", None, NO_READERS, root=tmp_path)
    monkeypatch.undo()
    assert path.read_bytes() == b"old"
    assert names(tmp_path) == ["token"]


def test_write_secret_keeps_the_previous_secret_when_it_cannot_replace_it(tmp_path):
    path = tmp_path / "token"
    path.mkdir()
    with pytest.raises(PermsError) as raised:
        write_secret(path, b"new", None, NO_READERS, root=tmp_path)
    assert str(path) in str(raised.value)
    assert names(tmp_path) == ["token"]
    assert path.is_dir()


def test_harden_file_refuses_a_hard_linked_file(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"A=1\n")
    env = tmp_path / ".env"
    os.link(other, env)
    with pytest.raises(PermsError) as raised:
        harden_file(env, None, NO_READERS, root=tmp_path)
    assert str(env) in str(raised.value)
    assert "hard link" in str(raised.value)


def test_write_secret_refuses_a_hard_linked_destination(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"the-old-secret")
    token = tmp_path / "token"
    os.link(other, token)
    with pytest.raises(PermsError) as raised:
        write_secret(token, b"new", None, NO_READERS, root=tmp_path)
    assert "hard link" in str(raised.value)
    assert other.read_bytes() == b"the-old-secret"


# Removing a temporary file while an error is in flight ================================================================


def test_discarding_a_temporary_file_removes_it(tmp_path):
    temporary = tmp_path / ".token.tmp"
    temporary.write_bytes(b"partial")
    perms.discard_temporary(str(temporary), RuntimeError("write failed"))
    assert not temporary.exists()


def test_discarding_a_temporary_file_that_is_gone_is_no_failure_and_adds_no_note(tmp_path):
    error = RuntimeError("write failed")
    perms.discard_temporary(str(tmp_path / "gone"), error)
    assert not hasattr(error, "__notes__")


def test_a_temporary_file_that_cannot_be_removed_is_noted_on_the_error_in_flight_and_raises_nothing(
    tmp_path, monkeypatch
):

    def refuse(*args, **kwargs):
        raise PermissionError(errno.EACCES, "Access is denied")

    monkeypatch.setattr(os, "unlink", refuse)
    error = RuntimeError("write failed")
    perms.discard_temporary(str(tmp_path / "held"), error)
    assert len(error.__notes__) == 1 and "held" in error.__notes__[0] and "Access is denied" in error.__notes__[0]
