"""`ctl doctor`'s check of the service's access, run against the ACLs the install really writes."""

import os
from pathlib import Path

import pytest
from tests.platform.windows.acl_support import icacls
from tests.unit.deployment_support import write_env

from ctl import perms_windows, winacl
from ctl.config import Config, Role
from ctl.doctor import Outcome
from ctl.doctor.permissions import Permissions
from ctl.doctor.probes import Probes
from ctl.perms import SID_LOCAL_SERVICE, Account, converge_dir, converge_owned, converge_tree, write_secret

LOCAL_SERVICE = Account("LocalService", None, None)
BINARIES = ("frpc.exe", "websocat.exe", "goetia-shim.exe")


def installed_repo(tmp_path: Path) -> tuple[Path, Config]:
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    (repo / "host").mkdir()
    for name in BINARIES:
        (repo / "bin" / name).write_bytes(b"")
    (repo / "bin" / ".digests.json").write_bytes(b"{}")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    config = write_env(repo, Role.HOST)
    converge_owned(repo / "bin", LOCAL_SERVICE, root=repo)
    converge_owned(repo / "host", LOCAL_SERVICE, root=repo)
    converge_tree(repo / "logs", LOCAL_SERVICE, 0o750, root=repo)
    readers = frozenset({SID_LOCAL_SERVICE, perms_windows.operator_sid(repo)})
    converge_dir(repo / "secrets", LOCAL_SERVICE, 0o711, readers, root=repo)
    write_secret(repo / "secrets" / "token", b"secret", LOCAL_SERVICE, readers, root=repo)
    return repo, config


def service_read(config: Config) -> tuple[Outcome, str]:
    return Permissions(config, Probes()).service_read()


def test_doctor_passes_what_install_writes(tmp_path):
    _, config = installed_repo(tmp_path)
    outcome, detail = service_read(config)
    assert outcome is Outcome.PASS, detail


@pytest.mark.parametrize("where", ["bin", "bin/frpc.exe", "host", "host/frpc.toml", "secrets/token", "logs"])
def test_doctor_fails_a_deny_ace_added_after_the_install_naming_the_path(tmp_path, where):
    repo, config = installed_repo(tmp_path)
    icacls(str(repo / where), "/deny", f"*{winacl.SID_USERS}:(WD)")
    outcome, detail = service_read(config)
    assert outcome is Outcome.FAIL
    assert f"{repo / where}: has a deny ACE for {winacl.SID_USERS}" in detail and "ctl install" in detail


def test_doctor_fails_a_file_moved_into_host_that_keeps_the_acl_it_had(tmp_path):
    repo, config = installed_repo(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    icacls(str(elsewhere), "/inheritance:r", "/grant:r", f"*{winacl.SID_ADMINISTRATORS}:(OI)(CI)(F)")
    (elsewhere / "frpc.toml").write_bytes(b"new")
    os.replace(elsewhere / "frpc.toml", repo / "host" / "frpc.toml")
    outcome, detail = service_read(config)
    assert outcome is Outcome.FAIL
    assert f"{repo / 'host' / 'frpc.toml'}: LocalService is not allowed" in detail and "ctl install" in detail


def test_doctor_passes_a_frpc_toml_git_recreated_in_host(tmp_path):
    repo, config = installed_repo(tmp_path)
    (repo / "host" / "frpc.toml").unlink()
    (repo / "host" / "frpc.toml").write_bytes(b"new")
    outcome, detail = service_read(config)
    assert outcome is Outcome.PASS, detail


@pytest.mark.parametrize("where", ["bin", "host", "logs"])
def test_doctor_fails_a_directory_whose_allow_for_the_service_was_removed(tmp_path, where):
    repo, config = installed_repo(tmp_path)
    icacls(str(repo / where), "/remove:g", f"*{SID_LOCAL_SERVICE}")
    outcome, detail = service_read(config)
    assert outcome is Outcome.FAIL and f"{repo / where}: LocalService is not allowed" in detail


def test_doctor_does_not_read_the_repository_root(tmp_path):
    repo, config = installed_repo(tmp_path)
    icacls(str(repo), "/deny", f"*{SID_LOCAL_SERVICE}:(X)")
    outcome, detail = service_read(config)
    assert outcome is Outcome.PASS, detail
