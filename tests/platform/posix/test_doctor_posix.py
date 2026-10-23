"""Doctor against real files: modes, owners and links, who may run it, and the promise to stat the token, never open it.

The unit tests stand in for `perms.principals`; here it is the real thing. Under uid 0 (the CI recipe) the tree is
handed to the unprivileged test account first, as `build_host` does, so the repository's owner is never root.
"""

import builtins
import io
import os
import pwd
import tempfile
from pathlib import Path

import pytest

from ctl import doctor, perms
from ctl.doctor import Check, Outcome
from ctl.doctor.permissions import Permissions
from ctl.doctor.probes import Probes
from tests.unit.doctor_support import World, build_bridge, build_client, build_host_world, by_name
from tests.unit.host_support import SERVICE_ACCOUNT, hand_to

PERMISSION_CHECKS = ("env_permissions", "secrets_dir_permissions", "secrets_token_permissions")


def secure(root: Path) -> None:
    """`.env`, `secrets/` and `secrets/token` as `ctl install` leaves them, for the account that runs the test."""
    os.chmod(root / ".env", 0o600)
    if (root / "secrets").exists():
        os.chmod(root / "secrets", 0o711)
        os.chmod(root / "secrets" / "token", 0o600)
    if os.geteuid() == 0:
        hand_to(root, pwd.getpwnam(SERVICE_ACCOUNT))


def checks_of(world: World) -> dict[str, Check]:
    """Doctor with the real `perms.principals`: the files' own modes and owners decide."""
    return by_name(doctor.run(world.config, world.probes(principals=perms.principals)))


@pytest.fixture
def bridge(tmp_path) -> World:
    world = build_bridge(tmp_path)
    secure(world.root)
    return world


@pytest.fixture
def host(tmp_path, monkeypatch) -> World:
    world, _ = build_host_world(tmp_path, monkeypatch)
    secure(world.root)
    return world


# Modes and owners =====================================================================================================


@pytest.mark.parametrize("fixture", ["bridge", "host"])
def test_files_as_install_leaves_them_pass(fixture, request):
    checks = checks_of(request.getfixturevalue(fixture))
    assert {name: checks[name].outcome for name in PERMISSION_CHECKS} == dict.fromkeys(PERMISSION_CHECKS, Outcome.PASS)


def test_a_client_env_file_is_held_to_owner_only(tmp_path):
    world = build_client(tmp_path)
    secure(world.root)
    assert checks_of(world)["env_permissions"].outcome is Outcome.PASS
    os.chmod(world.root / ".env", 0o640)
    assert checks_of(world)["env_permissions"].outcome is Outcome.FAIL


@pytest.mark.parametrize("fixture", ["bridge", "host"])
@pytest.mark.parametrize(
    "relative,mode,check",
    [(".env", 0o644, "env_permissions"), (".env", 0o660, "env_permissions"),
     ("secrets", 0o755, "secrets_dir_permissions"), ("secrets", 0o700, "secrets_dir_permissions"),
     ("secrets", 0o777, "secrets_dir_permissions"), ("secrets/token", 0o644, "secrets_token_permissions"),
     ("secrets/token", 0o400, "secrets_token_permissions")]
)
def test_a_mode_other_than_install_sets_is_a_failure_naming_it(fixture, relative, mode, check, request):
    world = request.getfixturevalue(fixture)
    os.chmod(world.root / relative, mode)
    result = checks_of(world)[check]
    assert result.outcome is Outcome.FAIL and f"{mode:04o}" in result.detail


def test_a_symlink_in_place_of_the_token_is_a_failure(host, tmp_path):
    real = tmp_path / "elsewhere"
    real.write_text("x")
    (host.root / "secrets" / "token").unlink()
    (host.root / "secrets" / "token").symlink_to(real)
    assert checks_of(host)["secrets_token_permissions"].outcome is Outcome.FAIL


def test_a_service_account_that_does_not_exist_is_a_named_failure_not_a_crash(host):
    host.edit_env(RT_SERVICE_USER="no-such-account-rt")
    checks = checks_of(host)
    assert checks["secrets_dir_permissions"].outcome is Outcome.FAIL
    assert "no-such-account-rt" in checks["secrets_dir_permissions"].detail
    assert checks["env_permissions"].outcome is Outcome.PASS


# Stat, never open =====================================================================================================


def test_secrets_checks_stat_and_never_open(host, monkeypatch):
    opened: list[str] = []
    real_os_open, real_open, real_io_open = os.open, builtins.open, io.open

    def watch(path) -> None:
        text = path if isinstance(path, str) else os.fsdecode(path) if isinstance(path, (bytes, os.PathLike)) else ""
        if text.replace("\\", "/").endswith("secrets/token") or text == "token":
            opened.append(text)

    def os_open(path, *args, **kwargs):
        watch(path)
        return real_os_open(path, *args, **kwargs)

    def python_open(file, *args, **kwargs):
        watch(file)
        return real_open(file, *args, **kwargs)

    def io_open(file, *args, **kwargs):
        watch(file)
        return real_io_open(file, *args, **kwargs)

    monkeypatch.setattr(os, "open", os_open)
    monkeypatch.setattr(builtins, "open", python_open)
    monkeypatch.setattr(io, "open", io_open)
    checks = checks_of(host)
    assert opened == []
    assert checks["secrets_token_permissions"].outcome is Outcome.PASS


# Who runs it ==========================================================================================================


def test_a_run_by_another_account_is_one_named_permission_failure(bridge, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(bridge.root).st_uid + 1)
    checks = doctor.diagnose(bridge.root, bridge.probes())
    assert [(c.name, c.outcome) for c in checks] == [("runs_as_repository_owner", Outcome.FAIL)]
    assert str(bridge.root) in checks[0].detail and ".env" in checks[0].detail


def test_root_may_run_it(bridge, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    names = {c.name for c in doctor.diagnose(bridge.root, bridge.probes())}
    assert "runs_as_repository_owner" not in names and "docker_reachable" in names


# Separate accounts ====================================================================================================

OPERATOR = 4242


@pytest.mark.root
def test_the_operator_can_stat_the_services_secrets_without_elevation(monkeypatch):
    """The repository is the operator's and `secrets/` the service's: doctor, run as the operator, still gets a verdict."""
    # Under `/tmp`, which every account can enter: macOS's per-user temp directory is 0700, and no other account can
    # reach anything beneath it.
    with tempfile.TemporaryDirectory(dir="/tmp") as scratch:
        os.chmod(scratch, 0o755)
        verdicts = operator_verdicts(Path(scratch), monkeypatch)
    assert {name: (verdict.outcome, verdict.detail)
            for name, verdict in verdicts.items()
            } == {name: (Outcome.PASS, verdict.detail)
                  for name, verdict in verdicts.items()}


def operator_verdicts(tmp_path: Path, monkeypatch) -> dict:
    world, _ = build_host_world(tmp_path, monkeypatch, RT_SERVICE_USER=SERVICE_ACCOUNT)
    root, service = world.root, pwd.getpwnam(SERVICE_ACCOUNT)
    hand_to(root, pwd.getpwnam(SERVICE_ACCOUNT))
    for path in (root, root / ".env"):
        os.chown(path, OPERATOR, OPERATOR)
    os.chmod(root / ".env", 0o600)
    os.chmod(root / "secrets", 0o711)
    os.chmod(root / "secrets" / "token", 0o600)
    os.chown(root / "secrets", service.pw_uid, service.pw_gid)
    os.chown(root / "secrets" / "token", service.pw_uid, service.pw_gid)
    permissions = Permissions(world.config, Probes())
    os.setegid(OPERATOR)
    os.seteuid(OPERATOR)
    try:
        return {"env": permissions.env(), "dir": permissions.secrets_dir(), "token": permissions.secrets_token()}
    finally:
        os.seteuid(0)
        os.setegid(0)
