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
