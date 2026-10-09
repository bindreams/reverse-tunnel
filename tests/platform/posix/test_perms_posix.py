import errno
import os
import pwd
import socket
import stat
from pathlib import Path

import pytest

from ctl.config import Config, ConfigError, Role
from ctl import perms
from ctl.perms import (
    Account,
    AccountMode,
    PermsError,
    account_mode,
    converge_dir,
    converge_tree,
    describe,
    grant_service_read,
    harden_file,
    principals,
    resolve_service_account,
    service_account,
    write_secret,
)

NO_READERS: frozenset[str] = frozenset()
# Provisioned by the container recipe and the CI leg; root tests fail loudly when it is missing.
TEST_ACCOUNT = "rt-test-svc"
OPERATOR_UID = 4242


def me() -> Account:
    return Account(pwd.getpwuid(os.getuid()).pw_name, os.getuid(), os.getgid())


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.fixture
def umask0():
    previous = os.umask(0)
    yield
    os.umask(previous)


# Accounts =============================================================================================================


def test_resolve_service_account_resolves_an_unprivileged_account():
    entry = pwd.getpwnam("nobody")
    assert resolve_service_account("nobody") == Account("nobody", entry.pw_uid, entry.pw_gid)


def test_resolve_service_account_rejects_root_by_name():
    with pytest.raises(ConfigError) as raised:
        resolve_service_account("root")
    assert "root" in str(raised.value)


def test_service_account_reads_rt_service_user_from_the_config(tmp_path):
    config = Config(root=tmp_path, role=Role.HOST, values={"RT_SERVICE_USER": "nobody"})
    assert service_account(config) == resolve_service_account("nobody")


def test_service_account_names_the_missing_variable(tmp_path):
    config = Config(root=tmp_path, role=Role.HOST, values={})
    with pytest.raises(ConfigError) as raised:
        service_account(config)
    assert "RT_SERVICE_USER" in str(raised.value)


@pytest.mark.parametrize(("service_uid_offset", "expected"), [(0, AccountMode.SAME), (1, AccountMode.SEPARATE)])
def test_account_mode_detects_same_and_separate(tmp_path, service_uid_offset, expected):
    service = Account("svc", os.getuid() + service_uid_offset, os.getgid())
    assert account_mode(tmp_path, service) == expected


# Secrets ==============================================================================================================


def test_secret_is_created_0600_under_a_permissive_umask(tmp_path, umask0):
    path = tmp_path / "token"
    write_secret(path, b"x", me(), NO_READERS, root=tmp_path)
    assert mode_of(path) == 0o600


def test_secret_stays_0600_when_overwritten_over_a_world_readable_file(tmp_path, umask0):
    path = tmp_path / "token"
    path.write_bytes(b"old")
    path.chmod(0o644)
    write_secret(path, b"new", me(), NO_READERS, root=tmp_path)
    assert mode_of(path) == 0o600
    assert path.read_bytes() == b"new"


def test_secret_is_never_briefly_world_readable(tmp_path, umask0, monkeypatch):
    path = tmp_path / "token"
    seen: list[tuple[str, int]] = []
    real = {name: getattr(os, name) for name in ("open", "fchown", "fchmod", "write")}

    def observe(label: str, fd: int) -> None:
        seen.append((label, stat.S_IMODE(os.fstat(fd).st_mode)))

    def spy_open(*args, **kwargs):
        fd = real["open"](*args, **kwargs)
        if args[1] & os.O_CREAT:
            observe("open", fd)
        return fd

    def spy(name: str):

        def wrapper(fd, *args, **kwargs):
            observe(name, fd)
            return real[name](fd, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(os, "open", spy_open)
    for name in ("fchown", "fchmod", "write"):
        monkeypatch.setattr(os, name, spy(name))
    write_secret(path, b"secret", me(), NO_READERS, root=tmp_path)
    monkeypatch.undo()
    assert {label for label, _ in seen} == {"open", "fchown", "fchmod", "write"}
    assert {mode for _, mode in seen} == {0o600}


def test_secret_is_replaced_atomically_not_rewritten(tmp_path):
    path = tmp_path / "token"
    path.write_bytes(b"old-secret")
    with open(path, "rb") as reader:
        write_secret(path, b"new", me(), NO_READERS, root=tmp_path)
        assert reader.read() == b"old-secret"
    assert path.read_bytes() == b"new"


def test_secret_is_fsynced_and_then_its_directory_after_the_rename(tmp_path, monkeypatch):
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("fsync-directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync-file")
        return real_fsync(fd)

    def replace(*args, **kwargs):
        events.append("replace")
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    write_secret(tmp_path / "token", b"secret", me(), NO_READERS, root=tmp_path)
    assert events == ["fsync-file", "replace", "fsync-directory"]


def test_write_secret_removes_its_temporary_file_when_the_chown_fails(tmp_path):
    with pytest.raises(ValueError):
        write_secret(tmp_path / "token", b"secret", Account("windows-only", None, None), NO_READERS, root=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_write_secret_refuses_a_symlinked_directory(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "secrets").symlink_to(tmp_path / "real")
    with pytest.raises(PermsError) as raised:
        write_secret(tmp_path / "secrets" / "token", b"secret", me(), NO_READERS, root=tmp_path)
    assert str(tmp_path / "secrets") in str(raised.value)
    assert list((tmp_path / "real").iterdir()) == []


def test_harden_file_tightens_the_mode_and_keeps_the_owner(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\n")
    path.chmod(0o644)
    before = os.stat(path)
    harden_file(path, None, NO_READERS, root=tmp_path)
    after = os.stat(path)
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)


def test_harden_file_refuses_a_hard_linked_file_and_leaves_the_other_link_untouched(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"")
    other.chmod(0o644)
    env = tmp_path / ".env"
    os.link(other, env)
    with pytest.raises(PermsError) as raised:
        harden_file(env, None, NO_READERS, root=tmp_path)
    assert "hard link" in str(raised.value)
    assert mode_of(other) == 0o644


def test_write_secret_refuses_a_hard_linked_destination(tmp_path):
    other = tmp_path / "other"
    other.write_bytes(b"the-old-secret")
    token = tmp_path / "token"
    os.link(other, token)
    with pytest.raises(PermsError) as raised:
        write_secret(token, b"new", me(), NO_READERS, root=tmp_path)
    assert "hard link" in str(raised.value)
    assert other.read_bytes() == b"the-old-secret"
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["other", "token"]


def test_harden_file_refuses_a_directory(tmp_path):
    with pytest.raises(PermsError) as raised:
        harden_file(tmp_path, None, NO_READERS, root=tmp_path)
    assert str(tmp_path) in str(raised.value)


# Directories ==========================================================================================================


def test_converge_dir_creates_a_missing_directory_with_the_exact_mode(tmp_path, umask0):
    path = tmp_path / "secrets"
    converge_dir(path, me(), 0o711, NO_READERS, root=tmp_path)
    assert mode_of(path) == 0o711


def test_converge_dir_reasserts_the_mode_on_an_existing_directory(tmp_path):
    path = tmp_path / "secrets"
    path.mkdir()
    path.chmod(0o755)
    converge_dir(path, me(), 0o711, NO_READERS, root=tmp_path)
    assert mode_of(path) == 0o711


def test_converge_dir_refuses_a_regular_file(tmp_path):
    path = tmp_path / "secrets"
    path.write_bytes(b"")
    with pytest.raises(PermsError) as raised:
        converge_dir(path, me(), 0o711, NO_READERS, root=tmp_path)
    assert str(path) in str(raised.value)


def test_converge_dir_refuses_a_symlink_and_leaves_its_target_untouched(tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    sentinel.chmod(0o775)
    before = os.stat(sentinel)
    link = tmp_path / "secrets"
    link.symlink_to(sentinel)
    with pytest.raises(PermsError) as raised:
        converge_dir(link, me(), 0o700, NO_READERS, root=tmp_path)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)
    after = os.stat(sentinel)
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)


def test_converge_dir_refuses_a_dangling_symlink(tmp_path):
    link = tmp_path / "secrets"
    link.symlink_to(tmp_path / "absent")
    with pytest.raises(PermsError) as raised:
        converge_dir(link, me(), 0o700, NO_READERS, root=tmp_path)
    assert str(link) in str(raised.value)
    assert not (tmp_path / "absent").exists()


def forbid_path_based_calls(monkeypatch):

    def forbidden(name: str):

        def refuse(*args, **kwargs):
            raise AssertionError(f"os.{name} follows a path; use the descriptor form")

        return refuse

    for name in ("chmod", "chown", "lchown", "lchmod"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden(name))


def test_converge_dir_does_not_use_a_path_based_chmod_or_chown(tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "frpc.log").write_bytes(b"")
    calls: list[str] = []
    for name in ("fchmod", "fchown"):
        real = getattr(os, name)
        monkeypatch.setattr(os, name, lambda *a, _n=name, _r=real, **k: (calls.append(_n), _r(*a, **k))[1])
    forbid_path_based_calls(monkeypatch)
    converge_dir(tmp_path / "secrets", me(), 0o711, NO_READERS, root=tmp_path)
    converge_dir(logs, me(), 0o750, NO_READERS, root=tmp_path)
    converge_tree(logs, me(), 0o750, root=tmp_path)
    (tmp_path / ".env").write_bytes(b"")
    harden_file(tmp_path / ".env", me(), NO_READERS, root=tmp_path)
    write_secret(tmp_path / "token", b"x", me(), NO_READERS, root=tmp_path)
    assert {"fchmod", "fchown"} <= set(calls)


# Trees ================================================================================================================


def test_converge_tree_sets_the_directory_mode_and_keeps_entry_modes(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    log = logs / "frpc.log"
    log.write_bytes(b"")
    log.chmod(0o640)
    converge_tree(logs, me(), 0o750, root=tmp_path)
    assert mode_of(logs) == 0o750
    assert mode_of(log) == 0o640


def test_converge_tree_refuses_a_symlinked_entry_and_leaves_its_target_untouched(tmp_path):
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"")
    sentinel.chmod(0o664)
    before = os.stat(sentinel)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "frpc.log").symlink_to(sentinel)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, me(), 0o750, root=tmp_path)
    assert str(logs / "frpc.log") in str(raised.value)
    after = os.stat(sentinel)
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)


def test_converge_tree_refuses_a_symlink_where_logs_should_be(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "logs").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(PermsError) as raised:
        converge_tree(tmp_path / "logs", me(), 0o750, root=tmp_path)
    assert str(tmp_path / "logs") in str(raised.value)


def test_converge_tree_refuses_a_fifo_without_opening_it(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    os.mkfifo(logs / "pipe")
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, me(), 0o750, root=tmp_path)
    assert str(logs / "pipe") in str(raised.value)
    assert "remove it" in str(raised.value)


def test_converge_tree_refuses_a_socket(tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.chdir(logs)  # a socket path must fit in sun_path, which a temporary directory's may not
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind("frpc.sock")
        with pytest.raises(PermsError) as raised:
            converge_tree(logs, me(), 0o750, root=tmp_path)
    assert str(logs / "frpc.sock") in str(raised.value)


def test_converge_tree_refuses_a_subdirectory_and_does_not_enter_it(tmp_path):
    logs = tmp_path / "logs"
    (logs / "old").mkdir(parents=True)
    inner = logs / "old" / "frpc.log.1"
    inner.write_bytes(b"")
    inner.chmod(0o664)
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, me(), 0o750, root=tmp_path)
    assert str(logs / "old") in str(raised.value)
    assert "remove it" in str(raised.value)
    assert mode_of(inner) == 0o664


def test_converge_tree_refuses_a_hard_linked_file_and_leaves_the_other_link_untouched(tmp_path):
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"")
    foreign.chmod(0o640)
    before = os.stat(foreign)
    logs = tmp_path / "logs"
    logs.mkdir()
    os.link(foreign, logs / "frpc.log")
    with pytest.raises(PermsError) as raised:
        converge_tree(logs, me(), 0o750, root=tmp_path)
    assert str(logs / "frpc.log") in str(raised.value)
    assert "hard link" in str(raised.value)
    after = os.stat(foreign)
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)


def entry_status(*, mode=stat.S_IFREG | 0o644, device=7, links=1) -> os.stat_result:
    return os.stat_result((mode, 1, device, links, 0, 0, 0, 0, 0, 0))


def test_an_entry_on_another_device_is_refused():
    with pytest.raises(PermsError) as raised:
        perms._refuse_entry(Path("logs/frpc.log"), entry_status(device=8), directory_device=7)
    assert "another filesystem" in str(raised.value)


def test_a_single_link_regular_file_on_the_same_device_is_accepted():
    perms._refuse_entry(Path("logs/frpc.log"), entry_status(), directory_device=7)


# Inspection ===========================================================================================================


def test_principals_matches_the_mode_and_owner_on_posix(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"")
    path.chmod(0o600)
    assert principals(path) == frozenset({f"owner={me().name}", "mode=0600"})


def test_principals_reports_a_symlink_as_its_own_entry(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    assert "mode=0600" not in principals(link)


def test_describe_names_the_owner_and_mode(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"")
    path.chmod(0o600)
    assert describe(path) == f"owner {me().name}, mode 0600"


def test_grant_service_read_is_a_no_op(tmp_path):
    before = os.stat(tmp_path)
    grant_service_read(tmp_path, me())
    assert os.stat(tmp_path).st_mode == before.st_mode


# Root =================================================================================================================


def previous_owner(path: Path) -> None:
    os.chown(path, OPERATOR_UID, OPERATOR_UID)


@pytest.mark.root
def test_converge_dir_fixes_an_existing_dir_with_the_wrong_mode_and_owner(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    path = tmp_path / "secrets"
    path.mkdir()
    previous_owner(path)
    path.chmod(0o755)
    converge_dir(path, service, 0o711, NO_READERS, root=tmp_path)
    after = os.stat(path)
    assert stat.S_IMODE(after.st_mode) == 0o711
    assert (after.st_uid, after.st_gid) == (service.uid, service.gid)


@pytest.mark.root
def test_converge_dir_leaves_ownership_alone_without_an_owner(tmp_path):
    path = tmp_path / "secrets"
    path.mkdir()
    previous_owner(path)
    converge_dir(path, None, 0o700, NO_READERS, root=tmp_path)
    assert os.stat(path).st_uid == OPERATOR_UID


@pytest.mark.root
def test_converge_tree_reassigns_existing_log_files(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    stale = resolve_service_account("nobody")
    logs = tmp_path / "logs"
    logs.mkdir()
    log = logs / "frpc.log"
    log.write_bytes(b"history")
    rotated = logs / "frpc.log.1"
    rotated.write_bytes(b"older")
    for path in (logs, log, rotated):
        assert stale.uid is not None and stale.gid is not None
        os.chown(path, stale.uid, stale.gid)
    converge_tree(logs, service, 0o750, root=tmp_path)
    for path in (logs, log, rotated):
        assert (os.stat(path).st_uid, os.stat(path).st_gid) == (service.uid, service.gid), path
    assert mode_of(logs) == 0o750
    assert log.read_bytes() == b"history"


@pytest.mark.root
def test_converge_dir_refuses_a_symlink_without_chowning_its_target(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    previous_owner(sentinel)
    sentinel.chmod(0o775)
    before = os.stat(sentinel)
    link = tmp_path / "secrets"
    link.symlink_to(sentinel)
    with pytest.raises(PermsError) as raised:
        converge_dir(link, service, 0o700, NO_READERS, root=tmp_path)
    assert str(link) in str(raised.value)
    after = os.stat(sentinel)
    assert (after.st_mode, after.st_uid, after.st_gid) == (before.st_mode, before.st_uid, before.st_gid)
    assert os.lstat(link).st_uid == 0


@pytest.mark.root
def test_converge_tree_refuses_a_symlinked_entry_without_chowning_its_target(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"")
    previous_owner(sentinel)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "frpc.log").symlink_to(sentinel)
    with pytest.raises(PermsError):
        converge_tree(logs, service, 0o750, root=tmp_path)
    assert os.stat(sentinel).st_uid == OPERATOR_UID


@pytest.mark.root
def test_write_secret_assigns_the_service_account_and_0600(tmp_path, umask0):
    service = resolve_service_account(TEST_ACCOUNT)
    path = tmp_path / "token"
    write_secret(path, b"secret", service, NO_READERS, root=tmp_path)
    after = os.stat(path)
    assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (service.uid, service.gid, 0o600)
    assert path.read_bytes() == b"secret"


@pytest.mark.root
def test_write_secret_does_not_chown_a_symlink_target(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"untouched")
    previous_owner(sentinel)
    link = tmp_path / "token"
    link.symlink_to(sentinel)
    with pytest.raises(PermsError):
        write_secret(link, b"secret", service, NO_READERS, root=tmp_path)
    assert os.stat(sentinel).st_uid == OPERATOR_UID
    assert sentinel.read_bytes() == b"untouched"


@pytest.mark.root
def test_harden_file_assigns_the_owner_through_the_descriptor(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    path = tmp_path / "token"
    path.write_bytes(b"")
    path.chmod(0o644)
    harden_file(path, service, NO_READERS, root=tmp_path)
    after = os.stat(path)
    assert (after.st_uid, stat.S_IMODE(after.st_mode)) == (service.uid, 0o600)


@pytest.mark.root
def test_account_mode_is_separate_for_a_service_that_does_not_own_the_root(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    assert os.stat(tmp_path).st_uid == 0
    assert account_mode(tmp_path, service) == AccountMode.SEPARATE


@pytest.mark.root
def test_principals_names_a_real_owner(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    path = tmp_path / "token"
    write_secret(path, b"", service, NO_READERS, root=tmp_path)
    assert principals(path) == frozenset({f"owner={TEST_ACCOUNT}", "mode=0600"})


@pytest.mark.root
def test_principals_falls_back_to_the_uid_for_an_unnamed_owner(tmp_path):
    path = tmp_path / "token"
    path.write_bytes(b"")
    previous_owner(path)
    assert f"owner={OPERATOR_UID}" in principals(path)


@pytest.mark.root
def test_converge_tree_does_not_chown_the_inode_behind_a_hard_link(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"private")
    previous_owner(foreign)
    foreign.chmod(0o600)
    logs = tmp_path / "logs"
    logs.mkdir()
    os.link(foreign, logs / "frpc.log")
    with pytest.raises(PermsError):
        converge_tree(logs, service, 0o750, root=tmp_path)
    after = os.stat(foreign)
    assert (after.st_uid, stat.S_IMODE(after.st_mode)) == (OPERATOR_UID, 0o600)


@pytest.mark.root
def test_harden_file_does_not_chmod_or_chown_the_inode_behind_a_hard_link(tmp_path):
    service = resolve_service_account(TEST_ACCOUNT)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"")
    previous_owner(foreign)
    foreign.chmod(0o644)
    os.link(foreign, tmp_path / ".env")
    with pytest.raises(PermsError):
        harden_file(tmp_path / ".env", service, NO_READERS, root=tmp_path)
    after = os.stat(foreign)
    assert (after.st_uid, stat.S_IMODE(after.st_mode)) == (OPERATOR_UID, 0o644)


def test_a_socket_swapped_in_after_the_check_is_reported_as_not_a_regular_file():
    failure = perms._failure(Path("logs/frpc.log"), OSError(errno.ENXIO, "Device not configured"))
    assert "not a regular file" in str(failure)


# assign_file ==========================================================================================================


def test_assign_file_sets_the_mode_through_the_descriptor(tmp_path):
    path = tmp_path / "record"
    path.write_text("x")
    path.chmod(0o600)
    perms.assign_file(path, me(), 0o644, root=tmp_path)
    assert mode_of(path) == 0o644 and path.stat().st_uid == os.getuid()


def test_assign_file_refuses_a_symlink_and_leaves_its_target_alone(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(PermsError, match="symlink"):
        perms.assign_file(link, me(), 0o644, root=tmp_path)
    assert mode_of(target) == 0o600


def test_assign_file_refuses_a_hard_linked_file(tmp_path):
    path = tmp_path / "record"
    path.write_text("x")
    path.chmod(0o600)
    os.link(path, tmp_path / "other-name")
    with pytest.raises(PermsError, match="hard link"):
        perms.assign_file(path, me(), 0o644, root=tmp_path)
    assert mode_of(path) == 0o600


def test_assign_file_refuses_a_directory(tmp_path):
    with pytest.raises(PermsError, match="not a regular file"):
        perms.assign_file(tmp_path, me(), 0o644, root=tmp_path)


def test_operator_account_is_the_owner_of_the_repository_root(tmp_path):
    operator = perms.operator_account(tmp_path)
    assert operator.uid == os.getuid() and operator.name == pwd.getpwuid(os.getuid()).pw_name
