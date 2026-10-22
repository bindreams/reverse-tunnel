"""`ctl` reads back what it wrote and fails unless the whole ACL is what it meant: every ACE (type, flags, mask, SID) and
the inheritance state, not just which SIDs are named.

The tampering stands for NTFS or a filter driver storing something other than what was asked for.
"""

import errno
import os

import pytest
from tests.platform.windows.acl_support import icacls

from ctl import perms_windows, winacl
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


def widen_all(entries, protected):
    """Every right widened to full control: the same SIDs."""
    return [e._replace(mask=winacl.FULL) for e in entries], protected


def tamper(monkeypatch, change, *, skip: int = 0) -> None:
    """Every DACL written afterwards, but the first `skip`, is stored as `change` made it."""
    real = winacl.set_dacl
    written = []

    def writing(handle, entries, *, protected):
        written.append(handle)
        if len(written) > skip:
            entries, protected = change(list(entries), protected)
        real(handle, entries, protected=protected)

    monkeypatch.setattr(winacl, "set_dacl", writing)


def flip_protected(monkeypatch) -> None:
    """Every ACL read afterwards says its inheritance is in the other state than it is."""
    real = winacl.read_entries

    def reading(handle):
        entries, protected = real(handle)
        return entries, not protected

    monkeypatch.setattr(winacl, "read_entries", reading)


def writes_as(change, *, skip: int = 0):
    return lambda monkeypatch: tamper(monkeypatch, change, skip=skip)


FILE_TAMPERING = [writes_as(widen), writes_as(deny), flip_protected]
DIRECTORY_TAMPERING = [writes_as(widen), writes_as(deny), writes_as(uninheritable), flip_protected]


@pytest.mark.parametrize("change", FILE_TAMPERING)
def test_hardening_a_file_fails_unless_the_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    path = tmp_path / ".env"
    path.write_bytes(b"")
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        harden_file(path, None, READERS, root=tmp_path)
    assert str(path) in str(raised.value)


@pytest.mark.parametrize("change", FILE_TAMPERING)
def test_writing_a_secret_fails_unless_the_acl_of_its_temporary_file_reads_back_as_written(
    tmp_path, monkeypatch, change
):
    change(monkeypatch)
    with pytest.raises(PermsError):
        write_secret(tmp_path / "token", b"secret", LOCAL_SERVICE, READERS, root=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("change", DIRECTORY_TAMPERING)
def test_converging_an_isolated_directory_fails_unless_the_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        converge_dir(tmp_path / "secrets", LOCAL_SERVICE, 0o711, READERS, root=tmp_path)
    assert str(tmp_path / "secrets") in str(raised.value)


@pytest.mark.parametrize("change", DIRECTORY_TAMPERING)
def test_converging_a_directory_that_inherits_fails_unless_the_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        converge_dir(tmp_path / "staging", LOCAL_SERVICE, 0o700, READERS, isolate=False, root=tmp_path)
    assert str(tmp_path / "staging") in str(raised.value)


# `converge_owned`, the entries of `converge_dir`, and `revoke_root` ===================================================


def owned_with_a_file(tmp_path):
    """`bin` holding one file, and the file's path."""
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "tool.exe").write_bytes(b"")
    return tmp_path / "bin", tmp_path / "bin" / "tool.exe"


@pytest.mark.parametrize("change", DIRECTORY_TAMPERING)
def test_converging_an_owned_directory_fails_unless_its_acl_reads_back_as_written(tmp_path, monkeypatch, change):
    directory, _ = owned_with_a_file(tmp_path)
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        perms_windows.converge_owned(directory, LOCAL_SERVICE, write=False, root=tmp_path)
    assert str(directory) in str(raised.value)


@pytest.mark.parametrize("change", [writes_as(widen, skip=1), writes_as(deny, skip=1)])
def test_converging_an_owned_directory_fails_unless_the_acl_of_a_file_in_it_reads_back_as_written(
    tmp_path, monkeypatch, change
):
    directory, file = owned_with_a_file(tmp_path)
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        perms_windows.converge_owned(directory, LOCAL_SERVICE, write=False, root=tmp_path)
    assert str(file) in str(raised.value)


@pytest.mark.parametrize("change", [writes_as(widen, skip=1), writes_as(deny, skip=1)])
def test_converging_a_directory_fails_unless_the_acl_of_a_file_in_it_reads_back_as_written(
    tmp_path, monkeypatch, change
):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "token").write_bytes(b"")
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        converge_dir(secrets, LOCAL_SERVICE, 0o711, READERS, root=tmp_path)
    assert str(secrets / "token") in str(raised.value)


REVOKING = [writes_as(widen_all), writes_as(deny), writes_as(uninheritable), flip_protected]


@pytest.mark.parametrize("change", REVOKING)
def test_revoking_the_service_from_the_root_fails_unless_the_whole_acl_reads_back_as_written(
    tmp_path, monkeypatch, change
):
    """The root holds an ACE for the service to take away and others it must keep exactly."""
    icacls(str(tmp_path), "/grant", f"*{SID_LOCAL_SERVICE}:(RX)", f"*{winacl.SID_USERS}:(OI)(CI)(R)")
    change(monkeypatch)
    with pytest.raises(PermsError) as raised:
        perms_windows.revoke_root(tmp_path, LOCAL_SERVICE)
    assert str(tmp_path) in str(raised.value)


def test_a_failure_to_remove_the_temporary_file_does_not_replace_the_error_that_caused_it(tmp_path, monkeypatch):
    """Cleanup runs while the original error is in flight; its own failure is attached to it as a note."""
    tamper(monkeypatch, widen)

    def refuse(*args, **kwargs):
        raise PermissionError(errno.EACCES, "Access is denied")

    monkeypatch.setattr(os, "unlink", refuse)
    with pytest.raises(PermsError) as raised:
        write_secret(tmp_path / "token", b"secret", LOCAL_SERVICE, READERS, root=tmp_path)
    assert any("Access is denied" in note for note in getattr(raised.value, "__notes__", []))
