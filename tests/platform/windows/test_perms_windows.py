import os
import secrets
import subprocess
from dataclasses import dataclass
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
    grant_service_read,
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


@dataclass
class StandardUser:
    name: str
    sid: str
    token: object


def owner_of(path: Path) -> str:
    """The operator for files under `path`: the SID that owns it."""
    return perms_windows.operator_sid(path)


def enable_privilege(name: str) -> None:
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
    )
    # pywin32 takes None for the local machine and a list of pairs; its stubs say otherwise.
    luid = win32security.LookupPrivilegeValue(None, name)  # ty: ignore[invalid-argument-type]
    privileges = [(luid, win32con.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(token, False, privileges)  # ty: ignore[invalid-argument-type]


def make_owner(path: Path, user: StandardUser) -> None:
    import win32security

    enable_privilege("SeRestorePrivilege")
    enable_privilege("SeTakeOwnershipPrivilege")
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION,
        win32security.ConvertStringSidToSid(user.sid), None, None, None
    )


@pytest.fixture
def standard_user():
    """A throwaway local non-administrator with a random password, logged on and removed afterwards."""
    import win32con
    import win32net
    import win32netcon
    import win32security

    name = f"rt{secrets.token_hex(4)}"
    password = "Aa1-" + secrets.token_urlsafe(24)
    win32net.NetUserAdd(
        None,  # ty: ignore[invalid-argument-type]
        1,
        {
            "name": name,
            "password": password,
            "priv": win32netcon.USER_PRIV_USER,
            "home_dir": None,
            "comment": None,
            "flags": win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD,
            "script_path": None,
        }
    )
    try:
        sid, _, _ = win32security.LookupAccountName(None, name)
        token = win32security.LogonUser(
            name, ".", password, win32con.LOGON32_LOGON_NETWORK, win32con.LOGON32_PROVIDER_DEFAULT
        )
        yield StandardUser(name, win32security.ConvertSidToStringSid(sid), token)
    finally:
        win32net.NetUserDel(None, name)  # ty: ignore[invalid-argument-type]


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
    assert principals(path) == {owner_of(tmp_path), SID_ADMINISTRATORS}
    assert SID_LOCAL_SERVICE not in principals(path)


def test_token_grants_localservice_read_but_not_write(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    ace = ace_for(path, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_READ_DATA
    assert not ace.mask & WRITING
    assert principals(path) == {SID_ADMINISTRATORS, SID_LOCAL_SERVICE}
    assert path.read_bytes() == b"secret"


def test_repo_owner_keeps_read_access_where_inheritance_is_broken(tmp_path, standard_user):
    import win32security

    root = tmp_path / "repo"
    root.mkdir()
    make_owner(root, standard_user)
    path = env_file(root)
    harden_file(path, None, NO_READERS)
    assert winacl.read_acl(path).protected
    assert principals(path) == {standard_user.sid, SID_ADMINISTRATORS}
    win32security.ImpersonateLoggedOnUser(standard_user.token)
    try:
        data = path.read_bytes()
    finally:
        win32security.RevertToSelf()
    assert data == b"RT_TOKEN=x\n"


def test_the_operator_is_the_owner_of_the_repository_root_not_the_process_user(tmp_path, standard_user):
    root = tmp_path / "repo"
    root.mkdir()
    make_owner(root, standard_user)
    assert perms_windows.operator_sid(root) == standard_user.sid


def test_harden_file_refuses_a_hard_linked_file(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"")
    os.link(other, tmp_path / ".env")
    before = winacl.read_acl(other)
    with pytest.raises(PermsError) as raised:
        harden_file(tmp_path / ".env", None, NO_READERS)
    assert "hard link" in str(raised.value)
    assert winacl.read_acl(other) == before


def test_a_plain_0600_file_is_reported_as_not_owner_only(tmp_path):
    path = env_file(tmp_path)
    os.chmod(path, 0o600)
    assert principals(path) != {owner_of(tmp_path), SID_ADMINISTRATORS}


def test_principals_reports_an_unexpected_sid(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    subprocess.run(["icacls", str(path), "/grant", f"*{SID_LOCAL_SERVICE}:(R)"], check=True, capture_output=True)
    assert SID_LOCAL_SERVICE in principals(path)


def test_harden_file_removes_a_stale_explicit_grant(tmp_path):
    path = env_file(tmp_path)
    subprocess.run(["icacls", str(path), "/grant", f"*{SID_USERS}:(R)"], check=True, capture_output=True)
    harden_file(path, None, NO_READERS)
    assert principals(path) == {owner_of(tmp_path), SID_ADMINISTRATORS}


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
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}))
    path = folder / "token"
    write_secret(path, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}))
    assert winacl.read_acl(path).protected
    assert SID_LOCAL_SERVICE in principals(path)
    assert owner_of(tmp_path) not in principals(path)


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
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}))
    for sid in (SID_LOCAL_SERVICE, owner_of(tmp_path), SID_ADMINISTRATORS):
        flags = ace_for(folder, sid).flags
        assert flags & OBJECT_INHERIT_ACE and flags & CONTAINER_INHERIT_ACE, sid
    child = folder / "child"
    child.write_bytes(b"")
    assert ace_for(child, SID_LOCAL_SERVICE).flags & INHERITED_ACE


def test_secrets_directory_grants_localservice_read_and_execute_but_not_write(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}))
    ace = ace_for(folder, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_EXECUTE
    assert not ace.mask & WRITING
    assert principals(folder) == {SID_LOCAL_SERVICE, owner_of(tmp_path), SID_ADMINISTRATORS}


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
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}))
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
    before = winacl.read_acl(target)
    (logs / "frpc.log").symlink_to(target)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert str(logs / "frpc.log") in str(raised.value)
    assert "remove it" in str(raised.value)
    assert winacl.read_acl(target) == before


def test_converge_tree_refuses_a_subdirectory_and_does_not_enter_it(tmp_path):
    logs = tmp_path / "logs"
    (logs / "old").mkdir(parents=True)
    inner = logs / "old" / "frpc.log.1"
    inner.write_bytes(b"")
    harden_file(inner, None, NO_READERS)
    before = winacl.read_acl(inner)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert str(logs / "old") in str(raised.value)
    assert "remove it" in str(raised.value)
    assert winacl.read_acl(inner) == before


def test_converge_tree_refuses_a_junction_entry(tmp_path):
    import _winapi

    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    _winapi.CreateJunction(str(target), str(logs / "junction"))
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert "reparse point" in str(raised.value)


def test_converge_tree_refuses_a_hard_linked_entry(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    other = tmp_path / "other"
    other.write_bytes(b"")
    os.link(other, logs / "frpc.log")
    before = winacl.read_acl(other)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert "hard link" in str(raised.value)
    assert winacl.read_acl(other) == before


def test_converge_tree_converges_the_directory_itself(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    converge_tree(logs, LOCAL_SERVICE, 0o750)
    ace = ace_for(logs, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_WRITE_DATA
    assert ace.flags & OBJECT_INHERIT_ACE and ace.flags & CONTAINER_INHERIT_ACE
    assert SID_ADMINISTRATORS in principals(logs)
    assert not winacl.read_acl(logs).protected


def test_converge_tree_restores_inheritance_on_an_existing_entry(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    entry = logs / "frpc.log"
    entry.write_bytes(b"")
    harden_file(entry, None, NO_READERS)
    assert SID_LOCAL_SERVICE not in principals(entry)
    converge_tree(logs, LOCAL_SERVICE, 0o750)
    assert SID_LOCAL_SERVICE in principals(entry)
    assert not winacl.read_acl(entry).protected


# Service access =======================================================================================================


def test_grant_service_read_reaches_the_repository_and_leaves_its_ancestors_alone(tmp_path):
    profile = tmp_path / "profile"
    repo = profile / "repo"
    (repo / "bin").mkdir(parents=True)
    (repo / "host").mkdir()
    (repo / "host" / "frpc.toml").write_bytes(b"")
    env = env_file(repo)
    harden_file(env, None, NO_READERS)
    secrets_dir = repo / "secrets"
    converge_dir(secrets_dir, LOCAL_SERVICE, 0o711, NO_READERS)
    before = {path: winacl.read_acl(path) for path in (profile, tmp_path, env, secrets_dir)}
    grant_service_read(repo, LOCAL_SERVICE)
    for path, acl in before.items():
        assert winacl.read_acl(path) == acl, path
    ace = ace_for(repo, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_EXECUTE and ace.mask & FILE_READ_DATA
    assert not ace.mask & WRITING
    assert ace.flags & OBJECT_INHERIT_ACE and ace.flags & CONTAINER_INHERIT_ACE
    for path in (repo / "bin", repo / "host", repo / "host" / "frpc.toml"):
        assert SID_LOCAL_SERVICE in principals(path), path
        assert not winacl.read_acl(path).protected, path
    assert SID_LOCAL_SERVICE not in principals(env)


# Inspection ===========================================================================================================


def test_describe_lists_the_sids_and_the_inheritance_state(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS)
    text = describe(path)
    assert SID_ADMINISTRATORS in text
    assert "inheritance broken" in text
