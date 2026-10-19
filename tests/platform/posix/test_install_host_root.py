"""A host install in the separate-account mode, with real accounts: root runs it, the repository belongs to an
operator, and the daemons run as another account.

Needs uid 0 and the accounts `rt-test-svc` and `nobody`; run it in the throwaway container or on CI. The traversal check
is stubbed except in the last two tests: the scratch tree lives under pytest's `0700` base directory, which
`rt-test-svc` cannot search. Those two build their tree under `/tmp` instead, so the real check can pass.
"""

import dataclasses
import grp
import os
import pwd
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from ctl import access, host
from ctl.download import DIGESTS
from ctl.errors import InstallError
from ctl.install import install
from ctl.perms import Account, AccountMode
from tests.unit.deployment_support import tree
from tests.unit.host_support import build_host

OPERATOR = 4242
SERVICE = "rt-test-svc"
pytestmark = pytest.mark.root


def owner_and_mode(path) -> tuple[int, int]:
    status = os.lstat(path)
    return status.st_uid, stat.S_IMODE(status.st_mode)


def uid_of(name: str) -> int:
    return pwd.getpwnam(name).pw_uid


def hand_to_operator(root) -> None:
    os.chown(root, OPERATOR, OPERATOR)
    for directory, names, files in os.walk(root):
        for name in names + files:
            os.chown(os.path.join(directory, name), OPERATOR, OPERATOR)


@pytest.fixture
def host_tree(tmp_path, monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.setattr(access, "verify_traversable", lambda root, service: None)
    built = build_host(tmp_path, monkeypatch, RT_SERVICE_USER=SERVICE)
    hand_to_operator(built.root)
    return built


def run_install(host_tree) -> int:
    return install(host_tree.config, services=host_tree.services)


def ownership(root) -> dict[str, tuple[int, int, int]]:
    return {
        path.relative_to(root).as_posix(): (*owner_and_mode(path), os.lstat(path).st_gid)
        for path in sorted(root.rglob("*"))
    }


def test_each_path_gets_the_owner_the_ownership_table_names(host_tree):
    service = uid_of(SERVICE)
    assert host.preflight(host_tree.config, services=host_tree.services).mode is AccountMode.SEPARATE
    assert run_install(host_tree) == 0
    root = host_tree.root
    assert owner_and_mode(root / "secrets") == (service, 0o711)
    assert owner_and_mode(root / "secrets" / "token") == (service, 0o600)
    assert owner_and_mode(root / "logs") == (service, 0o750)
    assert owner_and_mode(root / "bin") == (0, 0o755)
    for name in host_tree.pins:
        assert owner_and_mode(root / "bin" / name) == (0, 0o755)
    assert owner_and_mode(root / "bin" / DIGESTS) == (OPERATOR, 0o644)
    assert owner_and_mode(root / ".env") == (OPERATOR, 0o600)
    assert owner_and_mode(root) == (OPERATOR, os.stat(root).st_mode & 0o7777)


def test_goetia_is_never_handed_a_root_owned_logs_directory(host_tree):
    run_install(host_tree)
    assert {record["logs"]["uid"] for record in host_tree.fake.records} == {uid_of(SERVICE)}


def test_the_service_cannot_write_what_root_runs_or_reads(host_tree):
    run_install(host_tree)
    root = host_tree.root
    service = pwd.getpwnam(SERVICE)
    for path in (root, root / "bin", root / "host", root / "goetia.yaml", root / "host" / "frpc.toml", root / ".env"):
        assert not access.service_can_write(path, Account(service.pw_name, service.pw_uid, service.pw_gid)), path


def test_changing_the_service_user_reassigns_existing_log_files(host_tree):
    """systemd opens a log's append target after dropping to `User=`, so a stale owner is EACCES and the daemon never
    starts."""
    host_tree.edit_env(RT_SERVICE_USER="nobody")
    run_install(host_tree)
    host_tree.script_running()
    log = host_tree.root / "logs" / "frpc.log"
    log.write_text("started as the old account\n")
    os.chown(log, uid_of("nobody"), -1)
    host_tree.edit_env(RT_SERVICE_USER=SERVICE)
    run_install(host_tree)
    assert owner_and_mode(log)[0] == uid_of(SERVICE)
    assert owner_and_mode(host_tree.root / "logs")[0] == uid_of(SERVICE)
    assert owner_and_mode(host_tree.root / "secrets" / "token")[0] == uid_of(SERVICE)


def test_preflight_changes_no_owner_and_no_mode(host_tree):
    run_install(host_tree)
    host_tree.script_running()
    host_tree.edit_env(RT_SERVICE_USER="nobody")
    before = ownership(host_tree.root)
    host.preflight(host_tree.config, services=host_tree.services)
    assert ownership(host_tree.root) == before


@pytest.mark.parametrize(("owner", "group", "mode"), [
    (None, SERVICE, 0o775),
    (None, None, 0o777),
    (None, None, 0o757),
])
def test_a_service_that_could_write_the_repository_root_is_refused_before_anything_is_staged(
    host_tree, owner, group, mode
):
    root = host_tree.root
    os.chown(root, uid_of(owner) if owner else OPERATOR, grp.getgrnam(group).gr_gid if group else OPERATOR)
    root.chmod(mode)
    before = tree(root)
    with pytest.raises(InstallError, match="writable"):
        run_install(host_tree)
    # The lock file is the one thing a refused run leaves: it holds no state.
    assert {k: v for k, v in tree(root).items() if k != ".install.lock"} == before and host_tree.fake.calls == []


def test_the_operator_s_own_group_may_write_when_the_service_is_not_in_it(host_tree):
    host_tree.root.chmod(0o775)  # group OPERATOR; the service is not a member
    assert run_install(host_tree) == 0


def test_a_deployment_the_service_owns_is_the_same_account_mode_and_is_not_asked_whether_it_can_write(host_tree):
    os.chown(host_tree.root, uid_of(SERVICE), -1)
    assert host.preflight(host_tree.config, services=host_tree.services).mode is AccountMode.SAME


def test_an_existing_operator_owned_bin_is_converged_to_root_and_0755(host_tree):
    """`bin/` holds what root executes, so it is root's even when the operator created it, stricter than the table."""
    (host_tree.root / "bin").mkdir()
    os.chown(host_tree.root / "bin", OPERATOR, OPERATOR)
    (host_tree.root / "bin").chmod(0o775)  # the service, in neither the owner nor the group, cannot write it
    run_install(host_tree)
    assert owner_and_mode(host_tree.root / "bin") == (0, 0o755)


def test_the_lock_file_and_the_install_log_belong_to_the_operator(host_tree):
    host_tree.fake.on("install", host.WEBSOCAT_ID, stderr="error: nope\n", exit=1)
    with pytest.raises(InstallError):
        run_install(host_tree)
    assert owner_and_mode(host_tree.root / ".install.lock") == (OPERATOR, 0o640)


def test_the_detached_install_log_is_the_operator_s_and_0640(host_tree):
    run_install(host_tree)
    host_tree.script_running()
    host_tree.set_spec(host.WEBSOCAT_ID, installed="command: [old]\n", manifest="command: [new]\n")
    seen = []

    def spawn(argv, *, cwd, log, inherit):
        seen.append(os.fstat(log.fileno()).st_ino)
        os.write(inherit[-1], b"1")
        return 1

    services = dataclasses.replace(host_tree.services, spawn=spawn)
    assert install(host_tree.config, allow_self_disconnect=True, services=services) == 0
    assert seen == [os.stat(host_tree.root / "install.log").st_ino]
    assert owner_and_mode(host_tree.root / "install.log") == (OPERATOR, 0o640)


# The traversal check, unstubbed ---------------------------------------------------------------------------------------


@pytest.fixture
def open_tree(request, monkeypatch):
    """A host tree under a `/tmp` directory every account can search, with the real traversal check. Not `tmp_path`:
    pytest's base directory is `0700`."""
    base = Path(tempfile.mkdtemp(prefix="rt-preflight-", dir="/tmp"))
    request.addfinalizer(lambda: shutil.rmtree(base))
    base.chmod(0o755)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    built = build_host(base, monkeypatch, RT_SERVICE_USER=SERVICE)
    hand_to_operator(built.root)
    for directory in (built.root, built.root / "host"):
        directory.chmod(0o755)
    (built.root / "host" / "frpc.toml").chmod(0o644)
    return built


def test_preflight_passes_an_open_tree_with_the_real_traversal_check(open_tree):
    assert host.preflight(open_tree.config, services=open_tree.services).mode is AccountMode.SEPARATE


def test_preflight_refuses_a_closed_parent_with_the_real_traversal_check_and_changes_nothing(open_tree):
    base = open_tree.root.parent
    base.chmod(0o700)
    before = (tree(open_tree.root), ownership(open_tree.root))
    with pytest.raises(InstallError) as raised:
        host.preflight(open_tree.config, services=open_tree.services)
    assert f"{base} is not searchable by {SERVICE}" in str(raised.value)
    assert (tree(open_tree.root), ownership(open_tree.root)) == before and open_tree.fake.calls == []
    with pytest.raises(InstallError, match="not searchable"):
        run_install(open_tree)
    assert not (open_tree.root / "secrets").exists()
