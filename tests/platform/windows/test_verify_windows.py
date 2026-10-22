"""`ctl` reads back what it wrote and fails unless the whole ACL is what it meant: every ACE (type, flags, mask, SID) and
the inheritance state, not just which SIDs are named.

The tampering stands for NTFS or a filter driver storing something other than what was asked for.
"""

import pytest

from ctl import winacl
from ctl.perms import SID_LOCAL_SERVICE, Account, PermsError, converge_dir, harden_file, write_secret

LOCAL_SERVICE = Account("LocalService", None, None)
READERS = frozenset({SID_LOCAL_SERVICE})
FILE_WRITE_DATA = 0x2


def widen(entries, protected):
    """The service's right widened to full control: the same SIDs."""
    return [e._replace(mask=winacl.FULL) if e.sid == SID_LOCAL_SERVICE else e for e in entries], protected


def deny(entries, protected):
    """A deny for a SID the ACL already names: the same SIDs."""
    return [winacl.Entry(winacl.ACCESS_DENIED_ACE_TYPE, 0, FILE_WRITE_DATA, SID_LOCAL_SERVICE), *entries], protected


def uninheritable(entries, protected):
    """Inheritance flags lost: the same SIDs and masks."""
    return [
        e._replace(flags=e.flags & ~(winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE)) for e in entries
    ], protected


def flip_protected(entries, protected):
    return entries, not protected


FILE_TAMPERING = [widen, deny, flip_protected]
DIRECTORY_TAMPERING = [widen, deny, uninheritable, flip_protected]


def tamper(monkeypatch, change) -> None:
    """Every DACL written afterwards is stored as `change` made it."""
    real = winacl.set_dacl

    def writing(handle, entries, *, protected):
        entries, protected = change(list(entries), protected)
        real(handle, entries, protected=protected)

    monkeypatch.setattr(winacl, "set_dacl", writing)


@pytest.mark.parametrize("change", FILE_TAMPERING)
def test_hardening_a_file_fails_unless_the_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    path = tmp_path / ".env"
    path.write_bytes(b"")
    tamper(monkeypatch, change)
    with pytest.raises(PermsError) as raised:
        harden_file(path, None, READERS, root=tmp_path)
    assert str(path) in str(raised.value)


@pytest.mark.parametrize("change", FILE_TAMPERING)
def test_writing_a_secret_fails_unless_the_acl_of_its_temporary_file_reads_back_as_written(
    tmp_path, monkeypatch, change
):
    tamper(monkeypatch, change)
    with pytest.raises(PermsError):
        write_secret(tmp_path / "token", b"secret", LOCAL_SERVICE, READERS, root=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", DIRECTORY_TAMPERING)
def test_converging_an_isolated_directory_fails_unless_the_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    tamper(monkeypatch, change)
    with pytest.raises(PermsError) as raised:
        converge_dir(tmp_path / "secrets", LOCAL_SERVICE, 0o711, READERS, root=tmp_path)
    assert str(tmp_path / "secrets") in str(raised.value)


@pytest.mark.parametrize("change", DIRECTORY_TAMPERING)
def test_converging_a_directory_that_inherits_fails_unless_the_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    tamper(monkeypatch, change)
    with pytest.raises(PermsError) as raised:
        converge_dir(tmp_path / "staging", LOCAL_SERVICE, 0o700, READERS, isolate=False, root=tmp_path)
    assert str(tmp_path / "staging") in str(raised.value)
