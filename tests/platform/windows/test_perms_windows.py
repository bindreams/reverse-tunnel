import os
import secrets
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
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
    token: Any


def owner_of(path: Path) -> str:
    """The operator for files under `path`: the SID that owns it."""
    return perms_windows.operator_sid(path)


@contextmanager
def privilege(name: str):
    """Enable a privilege of this process for the block and put its previous state back afterwards."""
    import win32api
    import win32con
    import win32security
    import winerror

    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
    )
    try:
        # pywin32 takes None for the local machine and a list of pairs; its stubs say otherwise.
        luid = win32security.LookupPrivilegeValue(None, name)  # ty: ignore[invalid-argument-type]
        enable = [(luid, win32con.SE_PRIVILEGE_ENABLED)]
        win32api.SetLastError(0)
        previous = win32security.AdjustTokenPrivileges(token, False, enable)  # ty: ignore[invalid-argument-type]
        # AdjustTokenPrivileges succeeds even when the privilege is not held; only the last error says so.
        if win32api.GetLastError() == winerror.ERROR_NOT_ALL_ASSIGNED:
            raise AssertionError(f"this process does not hold {name}; run the Windows tests elevated")
        try:
            yield
        finally:
            win32security.AdjustTokenPrivileges(token, False, previous)
    finally:
        win32api.CloseHandle(token)


def make_owner(path: Path, user: StandardUser) -> None:
    import win32security

    with privilege("SeRestorePrivilege"), privilege("SeTakeOwnershipPrivilege"):
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
        try:
            yield StandardUser(name, win32security.ConvertSidToStringSid(sid), token)
        finally:
            token.Close()
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
    harden_file(path, None, NO_READERS, root=tmp_path)
    assert not BROAD_SIDS & principals(path)


def test_env_grants_no_access_to_localservice(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    assert principals(path) == {owner_of(tmp_path), SID_ADMINISTRATORS}
    assert SID_LOCAL_SERVICE not in principals(path)


def test_token_grants_localservice_read_but_not_write(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}), root=tmp_path)
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
    harden_file(path, None, NO_READERS, root=root)
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
        harden_file(tmp_path / ".env", None, NO_READERS, root=tmp_path)
    assert "hard link" in str(raised.value)
    assert winacl.read_acl(other) == before


def test_a_plain_0600_file_is_reported_as_not_owner_only(tmp_path):
    path = env_file(tmp_path)
    os.chmod(path, 0o600)
    assert principals(path) != {owner_of(tmp_path), SID_ADMINISTRATORS}


def test_principals_reports_an_unexpected_sid(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    subprocess.run(["icacls", str(path), "/grant", f"*{SID_LOCAL_SERVICE}:(R)"], check=True, capture_output=True)
    assert SID_LOCAL_SERVICE in principals(path)


def test_harden_file_removes_a_stale_explicit_grant(tmp_path):
    path = env_file(tmp_path)
    subprocess.run(["icacls", str(path), "/grant", f"*{SID_USERS}:(R)"], check=True, capture_output=True)
    harden_file(path, None, NO_READERS, root=tmp_path)
    assert principals(path) == {owner_of(tmp_path), SID_ADMINISTRATORS}


def test_harden_file_is_idempotent(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    first = winacl.read_acl(path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    assert winacl.read_acl(path) == first


def test_harden_file_refuses_a_reparse_point_naming_the_path(tmp_path):
    target = env_file(tmp_path)
    link = tmp_path / "link.env"
    link.symlink_to(target)
    with pytest.raises(PermsError) as raised:
        harden_file(link, None, NO_READERS, root=tmp_path)
    assert str(link) in str(raised.value)


def test_a_secret_is_never_written_under_the_permissive_inherited_acl(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}), root=tmp_path)
    path = folder / "token"
    write_secret(path, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}), root=tmp_path)
    assert winacl.read_acl(path).protected
    # Administrators are always granted, and are the operator on an elevated run; nothing else is, the operator included.
    assert principals(path) == {SID_LOCAL_SERVICE, SID_ADMINISTRATORS}


def test_harden_file_refuses_a_directory_junction(tmp_path):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    before = winacl.read_acl(target)
    with pytest.raises(PermsError) as raised:
        harden_file(junction, None, NO_READERS, root=tmp_path)
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
    write_secret(tmp_path / "token", b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}), root=tmp_path)
    assert seen == [frozenset({SID_ADMINISTRATORS, SID_LOCAL_SERVICE})]


def test_write_secret_replaces_a_hardened_secret_and_keeps_the_acl(tmp_path):
    path = tmp_path / "token"
    write_secret(path, b"old", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}), root=tmp_path)
    write_secret(path, b"new", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}), root=tmp_path)
    assert path.read_bytes() == b"new"
    assert principals(path) == {SID_ADMINISTRATORS, SID_LOCAL_SERVICE}
    assert [entry.name for entry in tmp_path.iterdir()] == ["token"]


def test_a_non_elevated_operator_replaces_the_token(tmp_path, standard_user):
    """Replacing deletes the old token. Elevated, Administrators' full access allows it; the operator's ACE must."""
    import win32security

    root = tmp_path / "repo"
    root.mkdir()
    make_owner(root, standard_user)
    # Ownership alone grants no FILE_READ_ATTRIBUTES. Not inheritable and without DELETE, so the only DELETE below is
    # ctl's.
    subprocess.run(["icacls", str(root), "/grant", f"*{standard_user.sid}:(RX)"], check=True, capture_output=True)
    folder = root / "secrets"
    converge_dir(folder, None, 0o711, frozenset({SID_LOCAL_SERVICE}), root=root)
    path = folder / "token"
    write_secret(path, b"old", None, frozenset({SID_LOCAL_SERVICE}), root=root)
    assert standard_user.sid in principals(path)
    win32security.ImpersonateLoggedOnUser(standard_user.token)
    try:
        write_secret(path, b"new", None, frozenset({SID_LOCAL_SERVICE}), root=root)
    finally:
        win32security.RevertToSelf()
    assert path.read_bytes() == b"new"
    assert [entry.name for entry in folder.iterdir()] == ["token"]


# Directories ==========================================================================================================


def test_directory_grants_carry_object_and_container_inherit(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}), root=tmp_path)
    for sid in (SID_LOCAL_SERVICE, owner_of(tmp_path), SID_ADMINISTRATORS):
        flags = ace_for(folder, sid).flags
        assert flags & OBJECT_INHERIT_ACE and flags & CONTAINER_INHERIT_ACE, sid
    child = folder / "child"
    child.write_bytes(b"")
    assert ace_for(child, SID_LOCAL_SERVICE).flags & INHERITED_ACE


def test_secrets_directory_grants_localservice_read_and_execute_but_not_write(tmp_path):
    folder = tmp_path / "secrets"
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}), root=tmp_path)
    ace = ace_for(folder, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_EXECUTE
    assert not ace.mask & WRITING
    assert principals(folder) == {SID_LOCAL_SERVICE, owner_of(tmp_path), SID_ADMINISTRATORS}


def test_logs_directory_grants_localservice_modify(tmp_path):
    logs = tmp_path / "logs"
    converge_dir(
        logs, LOCAL_SERVICE, 0o750, NO_READERS, writers=frozenset({SID_LOCAL_SERVICE}), isolate=False, root=tmp_path
    )
    ace = ace_for(logs, SID_LOCAL_SERVICE)
    assert ace.mask & FILE_WRITE_DATA
    assert ace.flags & OBJECT_INHERIT_ACE and ace.flags & CONTAINER_INHERIT_ACE
    assert not winacl.read_acl(logs).protected


def test_converge_dir_removes_a_stale_explicit_grant(tmp_path):
    folder = tmp_path / "secrets"
    folder.mkdir()
    subprocess.run(["icacls", str(folder), "/grant", f"*{SID_USERS}:(OI)(CI)(R)"], check=True, capture_output=True)
    converge_dir(folder, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE, owner_of(tmp_path)}), root=tmp_path)
    assert SID_USERS not in principals(folder)


def test_converge_dir_refuses_a_reparse_point_and_leaves_its_target_untouched(tmp_path):
    target = tmp_path / "sentinel"
    target.mkdir()
    before = winacl.read_acl(target)
    link = tmp_path / "secrets"
    os.symlink(target, link, target_is_directory=True)
    with pytest.raises(PermsError) as raised:
        converge_dir(link, LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE}), root=tmp_path)
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
        converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
    assert str(logs / "frpc.log") in str(raised.value)
    assert "remove it" in str(raised.value)
    assert winacl.read_acl(target) == before


def test_converge_tree_refuses_a_subdirectory_and_does_not_enter_it(tmp_path):
    logs = tmp_path / "logs"
    (logs / "old").mkdir(parents=True)
    inner = logs / "old" / "frpc.log.1"
    inner.write_bytes(b"")
    harden_file(inner, None, NO_READERS, root=tmp_path)
    before = {path: winacl.read_acl(path) for path in (logs, logs / "old", inner)}
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
    assert str(logs / "old") in str(raised.value)
    assert "remove it" in str(raised.value)
    for path, acl in before.items():
        assert winacl.read_acl(path) == acl, path


def test_converge_tree_refuses_a_junction_entry(tmp_path):
    import _winapi

    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    _winapi.CreateJunction(str(target), str(logs / "junction"))
    (target / "inside").write_bytes(b"")
    before = {path: winacl.read_acl(path) for path in (logs, target, target / "inside")}
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
    assert "reparse point" in str(raised.value)
    for path, acl in before.items():
        assert winacl.read_acl(path) == acl, path


def test_converge_tree_refuses_a_hard_linked_entry(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    other = tmp_path / "other"
    other.write_bytes(b"")
    os.link(other, logs / "frpc.log")
    before = {path: winacl.read_acl(path) for path in (logs, other)}
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
    assert "hard link" in str(raised.value)
    for path, acl in before.items():
        assert winacl.read_acl(path) == acl, path


def test_converge_tree_converges_the_directory_itself(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
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
    harden_file(entry, None, NO_READERS, root=tmp_path)
    assert SID_LOCAL_SERVICE not in principals(entry)
    converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
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
    harden_file(env, None, NO_READERS, root=repo)
    secrets_dir = repo / "secrets"
    converge_dir(secrets_dir, LOCAL_SERVICE, 0o711, NO_READERS, root=repo)
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


def repo_with(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    (repo / "host").mkdir()
    (repo / "bin" / "frpc.exe").write_bytes(b"")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    return repo


def acls_under(repo: Path) -> dict[Path, winacl.Acl]:
    return {path: winacl.read_acl(path) for path in [repo, *repo.rglob("*")]}


def test_grant_service_read_refuses_a_subdirectory_in_bin_and_changes_nothing(tmp_path):
    repo = repo_with(tmp_path)
    (repo / "bin" / "old").mkdir()
    (repo / "bin" / "old" / "x").write_bytes(b"")
    before = acls_under(repo)
    with pytest.raises(PermsError) as raised:
        grant_service_read(repo, LOCAL_SERVICE)
    assert str(repo / "bin" / "old") in str(raised.value)
    assert acls_under(repo) == before


def test_grant_service_read_refuses_a_hard_linked_file_and_leaves_the_foreign_file_alone(tmp_path):
    repo = repo_with(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"")
    os.link(foreign, repo / "host" / "extra.toml")
    before = {**acls_under(repo), foreign: winacl.read_acl(foreign)}
    with pytest.raises(PermsError) as raised:
        grant_service_read(repo, LOCAL_SERVICE)
    assert "hard link" in str(raised.value)
    assert {**acls_under(repo), foreign: winacl.read_acl(foreign)} == before


def test_grant_service_read_refuses_a_reparse_point_in_host_and_leaves_its_target_alone(tmp_path):
    repo = repo_with(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (repo / "host" / "link").symlink_to(target, target_is_directory=True)
    before = {**acls_under(repo), target: winacl.read_acl(target)}
    with pytest.raises(PermsError) as raised:
        grant_service_read(repo, LOCAL_SERVICE)
    assert "reparse point" in str(raised.value)
    assert {**acls_under(repo), target: winacl.read_acl(target)} == before


def test_grant_service_read_does_not_reach_other_directories(tmp_path):
    repo = repo_with(tmp_path)
    (repo / "ctl").mkdir()
    before = winacl.read_acl(repo / "ctl")
    grant_service_read(repo, LOCAL_SERVICE)
    assert winacl.read_acl(repo / "ctl") == before


def test_grant_service_read_does_not_reach_a_file_beside_bin_and_host(tmp_path):
    repo = repo_with(tmp_path)
    (repo / "goetia.yaml").write_bytes(b"")
    before = winacl.read_acl(repo / "goetia.yaml")
    grant_service_read(repo, LOCAL_SERVICE)
    assert winacl.read_acl(repo / "goetia.yaml") == before


def test_grant_service_read_is_idempotent(tmp_path):
    repo = repo_with(tmp_path)
    grant_service_read(repo, LOCAL_SERVICE)
    first = acls_under(repo)
    grant_service_read(repo, LOCAL_SERVICE)
    assert acls_under(repo) == first


def entries_of(path: Path, *, directory: bool = True) -> list[winacl.Entry]:
    with perms_windows._handle(path, directory=directory, access=perms_windows.winfile.READ_CONTROL) as handle:
        return winacl.read_entries(handle)[0]


def test_grant_service_read_keeps_an_explicit_deny_for_the_service(tmp_path):
    repo = repo_with(tmp_path)
    subprocess.run(["icacls", str(repo), "/deny", f"*{SID_LOCAL_SERVICE}:(W)"], check=True, capture_output=True)
    grant_service_read(repo, LOCAL_SERVICE)
    kept = [e for e in entries_of(repo) if e.sid == SID_LOCAL_SERVICE]
    assert {e.ace_type for e in kept} == {winacl.ACCESS_ALLOWED_ACE_TYPE, winacl.ACCESS_DENIED_ACE_TYPE}


# Names outside the BMP ================================================================================================

NON_BMP = "\U0001d4b3"


def test_converge_tree_opens_an_entry_whose_name_is_outside_the_bmp(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    entry = logs / f"frpc-{NON_BMP}.log"
    entry.write_bytes(b"")
    harden_file(entry, None, NO_READERS, root=tmp_path)
    converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
    assert SID_LOCAL_SERVICE in principals(entry)


def test_converge_tree_refuses_a_non_bmp_junction_by_name_instead_of_skipping_it(tmp_path):
    import _winapi

    logs = tmp_path / "logs"
    logs.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    before = {path: winacl.read_acl(path) for path in (logs, target)}
    _winapi.CreateJunction(str(target), str(logs / NON_BMP))
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, LOCAL_SERVICE, 0o750, root=tmp_path)
    assert NON_BMP in str(raised.value)
    assert "reparse point" in str(raised.value)
    assert {path: winacl.read_acl(path) for path in before} == before


def test_grant_service_read_opens_a_non_bmp_file_name_in_bin(tmp_path):
    repo = repo_with(tmp_path)
    (repo / "bin" / f"tool-{NON_BMP}.exe").write_bytes(b"")
    grant_service_read(repo, LOCAL_SERVICE)
    assert SID_LOCAL_SERVICE in principals(repo / "bin" / f"tool-{NON_BMP}.exe")


# Differential against NTFS ============================================================================================


def icacls(*arguments: str) -> None:
    subprocess.run(["icacls", *arguments], check=True, capture_output=True)


def differential_parent(tmp_path: Path) -> Path:
    """A directory whose ACL has every inheritance case: an inherited deny from above, then explicit ACEs of each kind."""
    grandparent = tmp_path / "grandparent"
    grandparent.mkdir()
    icacls(str(grandparent), "/inheritance:r", "/grant:r", f"*{SID_ADMINISTRATORS}:(OI)(CI)(F)")
    icacls(str(grandparent), "/deny", "*S-1-5-32-546:(OI)(CI)(W)")
    parent = grandparent / "parent"
    parent.mkdir()
    icacls(
        str(parent), "/grant:r", "*S-1-3-0:(OI)(CI)(IO)(F)", "*S-1-3-1:(OI)(CI)(IO)(R)",
        f"*{SID_USERS}:(OI)(CI)(GR,GE)", "*S-1-5-32-547:(OI)(CI)(NP)(R)", "*S-1-5-32-551:(OI)(RX)",
        "*S-1-3-4:(OI)(CI)(RC)"
    )
    return parent


def test_inherited_for_reproduces_the_ordered_acl_ntfs_computes(tmp_path):
    parent = differential_parent(tmp_path)
    child_file = parent / "f"
    child_file.write_bytes(b"")
    child_dir = parent / "d"
    child_dir.mkdir()
    parent_entries = entries_of(parent)
    assert any(e.flags & winacl.INHERITED_ACE and e.ace_type == winacl.ACCESS_DENIED_ACE_TYPE for e in parent_entries)

    def ordered(entries):
        return [(e.ace_type, e.sid, e.mask, e.flags) for e in entries]

    for path, directory in ((child_file, False), (child_dir, True)):
        with perms_windows._handle(path, directory=directory) as handle:
            by_ntfs = ordered(winacl.read_entries(handle)[0])
            owner, group = winacl.owner_and_group(handle)
            winacl.set_dacl(handle, [], protected=False)
            assert winacl.read_entries(handle)[0] == []
            computed = winacl.inherited_for(parent_entries, directory=directory, owner=owner, group=group)
            winacl.set_dacl(handle, computed, protected=False)
            assert ordered(winacl.read_entries(handle)[0]) == by_ntfs, path


def snapshot(root: Path) -> dict[Path, tuple[list[winacl.Entry], bool]]:
    """Every ACE, in stored order, and the inheritance state of `root` and everything under it."""
    result = {}
    for path in [root, *root.rglob("*")]:
        with perms_windows._handle(path, directory=path.is_dir(), access=perms_windows.winfile.READ_CONTROL) as handle:
            result[path] = winacl.read_entries(handle)
    return result


def test_a_creator_owner_server_ace_on_the_parent_is_refused_and_nothing_is_created_or_changed(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    icacls(str(parent), "/grant:r", "*S-1-3-2:(OI)(CI)(F)")
    before = snapshot(parent)
    with pytest.raises(PermsError) as raised:
        converge_tree(parent / "logs", LOCAL_SERVICE, 0o750, root=parent)
    assert "S-1-3-2" in str(raised.value)
    assert str(parent) in str(raised.value)
    assert not (parent / "logs").exists()
    assert snapshot(parent) == before


def test_converge_dir_refused_for_an_unsupported_parent_ace_creates_nothing(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    icacls(str(parent), "/grant:r", "*S-1-3-3:(OI)(CI)(F)")
    with pytest.raises(PermsError) as raised:
        converge_dir(parent / "logs", LOCAL_SERVICE, 0o750, NO_READERS, isolate=False, root=parent)
    assert "S-1-3-3" in str(raised.value)
    assert not (parent / "logs").exists()


def test_grant_service_read_refuses_an_unsupported_ace_on_the_root_and_writes_nothing(tmp_path):
    repo = repo_with(tmp_path)
    icacls(str(repo), "/grant:r", "*S-1-3-2:(OI)(CI)(F)")
    before = snapshot(repo)
    with pytest.raises(PermsError) as raised:
        grant_service_read(repo, LOCAL_SERVICE)
    assert "S-1-3-2" in str(raised.value)
    assert snapshot(repo) == before


def test_grant_service_read_refuses_an_unsupported_ace_on_bin_and_writes_nothing(tmp_path):
    repo = repo_with(tmp_path)
    icacls(str(repo / "bin"), "/grant:r", "*S-1-3-2:(OI)(R)")
    before = snapshot(repo)
    with pytest.raises(PermsError) as raised:
        grant_service_read(repo, LOCAL_SERVICE)
    assert "S-1-3-2" in str(raised.value)
    assert snapshot(repo) == before


def case_sensitive_repo(tmp_path: Path) -> Path:
    """An empty directory whose names are matched case-sensitively, so `bin` and `Bin` are different entries."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["fsutil", "file", "setCaseSensitiveInfo", str(repo), "enable"], check=True, capture_output=True)
    return repo


def test_grant_service_read_opens_a_directory_by_the_name_the_listing_gives(tmp_path):
    repo = case_sensitive_repo(tmp_path)
    (repo / "Bin").mkdir()
    (repo / "Bin" / "frpc.exe").write_bytes(b"")
    grant_service_read(repo, LOCAL_SERVICE)
    assert SID_LOCAL_SERVICE in principals(repo / "Bin" / "frpc.exe")


def test_grant_service_read_refuses_bin_and_Bin_together_as_ambiguous(tmp_path):
    repo = case_sensitive_repo(tmp_path)
    (repo / "bin").mkdir()
    (repo / "Bin").mkdir()
    before = snapshot(repo)
    with pytest.raises(PermsError) as raised:
        grant_service_read(repo, LOCAL_SERVICE)
    assert "ambiguous" in str(raised.value)
    assert snapshot(repo) == before


# Inspection ===========================================================================================================


def test_describe_lists_the_sids_and_the_inheritance_state(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    text = describe(path)
    assert SID_ADMINISTRATORS in text
    assert "inheritance broken" in text
