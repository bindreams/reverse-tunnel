import os
import subprocess
from pathlib import Path

import pytest

from ctl import perms_windows, winacl
from ctl.perms import (
    SID_ADMINISTRATORS,
    SID_AUTHENTICATED_USERS,
    SID_EVERYONE,
    SID_LOCAL_SERVICE,
    SID_USERS,
    Account,
    PermsError,
    converge_dir,
    converge_tree,
    describe,
    grant_traverse,
    harden_file,
    principals,
    write_secret,
)

LOCAL_SERVICE = Account("LocalService", None, None)
NO_READERS: frozenset[str] = frozenset()
BROAD_SIDS = {SID_EVERYONE, SID_USERS, SID_AUTHENTICATED_USERS}

FILE_READ_DATA = 0x1
FILE_WRITE_DATA = 0x2
FILE_APPEND_DATA = 0x4
FILE_EXECUTE = 0x20
DELETE = 0x10000
OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
INHERITED_ACE = 0x10
WRITING = FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE


def operator() -> str:
    return winacl.current_user_sid()


def ace_for(path: Path, sid: str) -> winacl.Ace:
    (ace, ) = [ace for ace in winacl.read_acl(path).aces if ace.sid == sid]
    return ace


def env_file(tmp_path: Path) -> Path:
    path = tmp_path / ".env"
    path.write_bytes(b"RT_TOKEN=x\n")
    return path


# Files ================================================================================================================


def test_hardened_file_grants_no_access_to_users_everyone_or_authenticated_users(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    assert not BROAD_SIDS & principals(path)


def test_env_grants_no_access_to_localservice(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    assert principals(path) == {operator(), SID_ADMINISTRATORS}
    assert SID_LOCAL_SERVICE not in principals(path)


def test_token_grants_localservice_read_but_not_write(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    ace = ace_for(path, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_READ_DATA
    assert not ace.mask & WRITING
    assert principals(path) == {SID_ADMINISTRATORS, SID_LOCAL_SERVICE}
    assert path.read_bytes() == b"secret"


def test_repo_owner_keeps_read_access_where_inheritance_is_broken(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    assert winacl.read_acl(path).protected
    assert path.read_bytes() == b"RT_TOKEN=x\n"
    with open(path, "ab") as file:
        file.write(b"")


def test_a_plain_0600_file_is_reported_as_not_owner_only(tmp_path):
    path = env_file(tmp_path)
    os.chmod(path, 0o600)
    assert principals(path) != {operator(), SID_ADMINISTRATORS}


def test_principals_reports_an_unexpected_sid(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    subprocess.run(["icacls", str(path), "/grant", f"*{SID_LOCAL_SERVICE}:(R)"], check=True, capture_output=True)
    assert SID_LOCAL_SERVICE in principals(path)


def test_harden_file_removes_a_stale_explicit_grant(tmp_path):
    path = env_file(tmp_path)
    subprocess.run(["icacls", str(path), "/grant", f"*{SID_USERS}:(R)"], check=True, capture_output=True)
    harden_file(path, None, NO_READERS)
    assert principals(path) == {operator(), SID_ADMINISTRATORS}


def test_harden_file_is_idempotent(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    first = winacl.read_acl(path)
    harden_file(path, None, NO_READERS)
    assert winacl.read_acl(path) == first


def test_harden_file_refuses_a_reparse_point_naming_the_path(tmp_path):
    target = env_file(tmp_path)
    link = tmp_path / "link.env"
    link.symlink_to(target)
    with pytest.raises(PermsError) as raised:
        harden_file(link, None, NO_READERS)
    assert str(link) in str(raised.value)


def test_a_secret_is_never_written_under_the_permissive_inherited_acl(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, operator()}))
    path = folder / "token"
    write_secret(path, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    assert winacl.read_acl(path).protected
    assert SID_LOCAL_SERVICE in principals(path)
    assert operator() not in principals(path)


def test_harden_file_refuses_a_directory_junction(tmp_path):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    before = winacl.read_acl(target)
    with pytest.raises(PermsError) as raised:
        harden_file(junction, None, NO_READERS)
    assert "reparse point" in str(raised.value)
    assert winacl.read_acl(target) == before


def test_write_secret_sets_the_acl_before_the_first_byte_is_written(tmp_path, monkeypatch):
    seen: list[frozenset[str]] = []
    real = perms_windows.write_all

    def spy(fd, data):
        (temporary, ) = [entry for entry in tmp_path.iterdir() if entry.name.endswith(".tmp")]
        seen.append(principals(temporary))
        real(fd, data)

    monkeypatch.setattr(perms_windows, "write_all", spy)
    write_secret(tmp_path / "token", b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    assert seen == [frozenset({SID_ADMINISTRATORS, SID_LOCAL_SERVICE})]


def test_write_secret_replaces_a_hardened_secret_and_keeps_the_acl(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"old", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    write_secret(path, b"new", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    assert path.read_bytes() == b"new"
    assert principals(path) == {SID_ADMINISTRATORS, SID_LOCAL_SERVICE}
    assert [entry.name for entry in tmp_path.iterdir()] == ["token"]


# Directories ==========================================================================================================


def test_directory_grants_carry_object_and_container_inherit(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, operator()}))
    for sid in (SID_LOCAL_SERVICE, operator(), SID_ADMINISTRATORS):
        flags = ace_for(folder, sid).flags
        assert flags & OBJECT_INHERIT_ACE and flags & CONTAINER_INHERIT_ACE, sid
    child = folder / "child"
    child.write_bytes(b"")
    assert ace_for(child, SID_LOCAL_SERVICE).flags & INHERITED_ACE


def test_secrets_directory_grants_localservice_read_and_execute_but_not_write(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, operator()}))
    ace = ace_for(folder, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_EXECUTE
    assert not ace.mask & WRITING
    assert principals(folder) == {SID_LOCAL_SERVICE, operator(), SID_ADMINISTRATORS}


def test_logs_directory_grants_localservice_modify(tmp_path):
    logs = tmp_path / "logs"
    converge_dir(logs, LOCAL_SERVICE, 0o750, NO_READERS, writers=frozenset({SID_LOCAL_SERVICE}), isolate=False)
    ace = ace_for(logs, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_WRITE_DATA
    assert ace.flags & OBJECT_INHERIT_ACE and ace.flags & CONTAINER_INHERIT_ACE
    assert not winacl.read_acl(logs).protected


def test_converge_dir_removes_a_stale_explicit_grant(tmp_path):
    folder = tmp_path / "secrets"
    folder.mkdir()
    subprocess.run(["icacls", str(folder), "/grant", f"*{SID_USERS}:(OI)(CI)(R)"], check=True, capture_output=True)
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, operator()}))
    assert SID_USERS not in principals(folder)


def test_converge_dir_refuses_a_reparse_point_and_leaves_its_target_untouched(tmp_path):
    target = tmp_path / "sentinel"
    target.mkdir()
    before = winacl.read_acl(target)
    link = tmp_path / "secrets"
    os.symlink(target, link, target_is_directory=True)
    with pytest.raises(PermsError) as raised:
        converge_dir(link, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE}))
    assert str(link) in str(raised.value)
    assert winacl.read_acl(target) == before


def test_converge_tree_refuses_a_reparse_point_entry(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "sentinel"
    target.write_bytes(b"")
    (logs / "frpc.log").symlink_to(target)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert str(logs / "frpc.log") in str(raised.value)


def test_converge_tree_restores_inheritance_on_an_existing_entry(tmp_path):
    logs = tmp_path / "logs"
    converge_dir(logs, LOCAL_SERVICE, 0o750, NO_READERS, writers=frozenset({SID_LOCAL_SERVICE}), isolate=False)
    entry = logs / "frpc.log"
    entry.write_bytes(b"")
    harden_file(entry, None, NO_READERS)
    converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert SID_LOCAL_SERVICE in principals(entry)
    assert not winacl.read_acl(entry).protected


# Traversal ============================================================================================================


def test_grant_traverse_makes_a_profile_directory_reachable_by_localservice(tmp_path):
    folder = tmp_path / "profile"
    folder.mkdir()
    before = winacl.read_acl(folder)
    grant_traverse(folder, LOCAL_SERVICE)
    ace = ace_for(folder, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_EXECUTE and ace.mask & FILE_READ_DATA
    assert not ace.mask & WRITING
    assert ace.flags & OBJECT_INHERIT_ACE and ace.flags & CONTAINER_INHERIT_ACE
    assert winacl.read_acl(folder).protected == before.protected
    (folder / "bin").mkdir()
    assert SID_LOCAL_SERVICE in principals(folder / "bin")


# Inspection ===========================================================================================================


def test_describe_lists_the_sids_and_the_inheritance_state(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    text = describe(path)
    assert SID_ADMINISTRATORS in text
    assert "inheritance broken" in text


def test_current_user_sid_is_a_sid():
    assert winacl.current_user_sid().startswith("S-1-5-")
