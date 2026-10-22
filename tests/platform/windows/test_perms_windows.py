import os
import secrets
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.platform.windows.acl_support import (
    after_each_write,
    entries_of,
    icacls,
    owned_shape,
    shape_of,
    snapshot,
    whole_entries,
)

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
    converge_owned,
    describe,
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
    # Administrators are always granted, and are the operator on an elevated run; nothing else is, not the operator.
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


# What NTFS rewrites when a directory gains inheritable ACEs ===========================================================


def repo_with(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "secrets").mkdir(parents=True)
    return repo


def acls_under(repo: Path) -> dict[Path, tuple[list[winacl.Entry], bool]]:
    return snapshot(repo)


def whole_acl(path: Path) -> tuple[list[winacl.Entry], bool]:
    return whole_entries(path)


def converge_secrets(repo: Path) -> None:
    converge_dir(repo / "secrets", LOCAL_SERVICE, 0o711, frozenset({SID_LOCAL_SERVICE}), root=repo)


@pytest.fixture
def converged_directory(tmp_path):
    """A repository whose `secrets` is about to be converged, and a file in it whose ACL `ctl` did not set."""
    repo = repo_with(tmp_path)
    extra = repo / "secrets" / "extra.txt"
    extra.write_bytes(b"")
    return repo, "secrets", extra


def test_converging_a_directory_again_changes_neither_it_nor_a_file_in_it(converged_directory):
    """The first converge writes the file (it was opened and vetted); one where the ACEs exist rewrites nothing."""
    repo, directory, extra = converged_directory
    converge_secrets(repo)
    first = (whole_acl(extra), entries_of(repo / directory))
    converge_secrets(repo)
    assert (whole_acl(extra), entries_of(repo / directory)) == first


def test_a_file_in_a_converged_directory_ends_up_inheriting_from_it(converged_directory):
    """Vetted and written through its own handle, the file holds what NTFS inheritance from the new ACL gives it."""
    repo, directory, extra = converged_directory
    converge_secrets(repo)
    with perms_windows._handle(extra, directory=False, access=perms_windows.winfile.READ_CONTROL) as handle:
        owner, group = winacl.owner_and_group(handle)
    expected = winacl.inherited_for(entries_of(repo / directory), directory=False, owner=owner, group=group)
    assert whole_acl(extra) == (expected, False)


def inherited_by(path: Path, parent: Path) -> tuple[list[winacl.Entry], bool]:
    """What `path`, a new entry of `parent`, inherits: its ACL when nothing explicit is on it, and not protected."""
    with perms_windows._handle(path, directory=path.is_dir(), access=perms_windows.winfile.READ_CONTROL) as handle:
        owner, group = winacl.owner_and_group(handle)
    return winacl.inherited_for(entries_of(parent), directory=path.is_dir(), owner=owner, group=group), False


def add_nested(repo: Path) -> list[Path]:
    """Two levels of subdirectory in `secrets`, each holding a file; parents first."""
    top, deeper = repo / "secrets" / "old", repo / "secrets" / "old" / "deeper"
    deeper.mkdir(parents=True)
    (top / "x").write_bytes(b"")
    (deeper / "y").write_bytes(b"")
    return [top, top / "x", deeper, deeper / "y"]


def test_converging_secrets_rewrites_a_subdirectory_and_what_is_in_it_to_inherit(tmp_path):
    repo = repo_with(tmp_path)
    nested = add_nested(repo)
    converge_secrets(repo)
    parents = {nested[0]: repo / "secrets", nested[1]: nested[0], nested[2]: nested[0], nested[3]: nested[2]}
    for path in nested:
        assert whole_acl(path) == inherited_by(path, parents[path]), path


def test_converging_secrets_again_writes_nothing_with_subdirectories_present(tmp_path, monkeypatch):
    repo = repo_with(tmp_path)
    add_nested(repo)
    converge_secrets(repo)
    first = acls_under(repo)
    writes = after_each_write(monkeypatch, lambda: None)
    converge_secrets(repo)
    assert len(writes) == 1 and acls_under(repo) == first  # the directory itself is always written, nothing in it


def test_converging_secrets_refuses_a_hard_link_deep_in_a_subdirectory_and_changes_nothing(tmp_path):
    repo = repo_with(tmp_path)
    nested = add_nested(repo)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"")
    os.link(foreign, nested[2] / "linked")
    before = acls_under(repo) | acls_under(foreign)
    with pytest.raises(PermsError) as raised:
        converge_secrets(repo)
    assert "hard link" in str(raised.value) and str(nested[2] / "linked") in str(raised.value)
    assert acls_under(repo) | acls_under(foreign) == before


def test_converging_secrets_refuses_a_reparse_point_deep_in_a_subdirectory_and_leaves_its_target_alone(tmp_path):
    repo = repo_with(tmp_path)
    nested = add_nested(repo)
    target = tmp_path / "target"
    target.mkdir()
    (nested[2] / "link").symlink_to(target, target_is_directory=True)
    before = acls_under(repo) | acls_under(target)
    with pytest.raises(PermsError) as raised:
        converge_secrets(repo)
    assert "reparse point" in str(raised.value) and str(nested[2] / "link") in str(raised.value)
    assert acls_under(repo) | acls_under(target) == before


def test_converging_secrets_skips_an_entry_deleted_between_listing_and_opening(tmp_path, monkeypatch):
    repo = repo_with(tmp_path)
    victim = repo / "secrets" / "rotated"
    victim.write_bytes(b"")
    kept = repo / "secrets" / "kept"
    kept.write_bytes(b"")
    real = perms_windows.winfile.list_names

    def listing(directory):
        names = real(directory)
        if victim.exists():
            victim.unlink()
        return names

    monkeypatch.setattr(perms_windows.winfile, "list_names", listing)
    converge_secrets(repo)
    assert not victim.exists() and whole_acl(kept) == inherited_by(kept, repo / "secrets")


def test_converging_secrets_leaves_a_file_with_broken_inheritance_as_it_was(tmp_path):
    repo = repo_with(tmp_path)
    token = repo / "secrets" / "token"
    converge_secrets(repo)
    write_secret(token, b"secret", LOCAL_SERVICE, frozenset({SID_LOCAL_SERVICE}), root=repo)
    before = whole_acl(token)
    converge_secrets(repo)
    assert whole_acl(token) == before and before[1]


# The operator =========================================================================================================


@pytest.mark.parametrize("name,mask", [("bin", winacl.READ_EXECUTE), ("host", winacl.READ_EXECUTE)])
def test_an_operator_who_is_not_an_administrator_holds_full_control_of_an_owned_directory(
    tmp_path, standard_user, name, mask
):
    repo = tmp_path / "repo"
    repo.mkdir()
    make_owner(repo, standard_user)
    converge_owned(repo / name, LOCAL_SERVICE, root=repo)
    expected = owned_shape(repo, mask, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
    assert (standard_user.sid, winacl.FULL, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) in expected
    assert shape_of(repo / name) == (expected, True)


# Differential against NTFS ============================================================================================


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


def test_converge_dir_refused_for_an_unsupported_parent_ace_creates_nothing(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    icacls(str(parent), "/grant:r", "*S-1-3-3:(OI)(CI)(F)")
    with pytest.raises(PermsError) as raised:
        converge_dir(parent / "logs", LOCAL_SERVICE, 0o750, NO_READERS, isolate=False, root=parent)
    assert "S-1-3-3" in str(raised.value)
    assert not (parent / "logs").exists()


# Inspection ===========================================================================================================


def test_reading_the_acl_of_a_missing_path_is_a_file_not_found_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        winacl.read_acl(tmp_path / "absent")


def test_describe_lists_the_sids_and_the_inheritance_state(tmp_path):
    path = env_file(tmp_path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    text = describe(path)
    assert SID_ADMINISTRATORS in text
    assert "inheritance broken" in text


def test_the_doctor_check_of_the_services_access_runs_for_an_operator_who_is_not_elevated(tmp_path, standard_user):
    import win32security
    from tests.unit.deployment_support import write_env

    from ctl.config import Role
    from ctl.doctor import Outcome
    from ctl.doctor.permissions import Permissions
    from ctl.doctor.probes import Probes

    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    (repo / "host").mkdir()
    make_owner(repo, standard_user)
    config = write_env(repo, Role.HOST)
    for name in ("frpc.exe", "websocat.exe", "goetia-shim.exe"):
        (repo / "bin" / name).write_bytes(b"")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    converge_owned(repo / "bin", LOCAL_SERVICE, root=repo)
    converge_owned(repo / "host", LOCAL_SERVICE, root=repo)
    converge_owned(repo / "logs", LOCAL_SERVICE, write=True, root=repo)
    readers = frozenset({SID_LOCAL_SERVICE, standard_user.sid})
    converge_dir(repo / "secrets", LOCAL_SERVICE, 0o711, readers, root=repo)
    write_secret(repo / "secrets" / "token", b"x", LOCAL_SERVICE, readers, root=repo)
    win32security.ImpersonateLoggedOnUser(standard_user.token)
    try:
        outcome, detail = Permissions(config, Probes()).service_read()
    finally:
        win32security.RevertToSelf()
    assert outcome is Outcome.PASS, detail
