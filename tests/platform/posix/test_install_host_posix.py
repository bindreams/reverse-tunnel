"""A host install end to end as the repository's owner, who is also the service account: the same-account mode.

Everything here runs unprivileged, so nothing is chowned to another account; test_install_host_root.py covers that.
"""

import dataclasses
import os
import signal
import stat
import sys

import pytest

from ctl import access, binaries, detach, handshake, host, lock, perms
from ctl.config import ConfigError
from ctl.download import DIGESTS, read_digests
from ctl.errors import BinariesError, InstallError
from ctl.install import install, uninstall
from ctl.perms import AccountMode
from tests.unit.deployment_support import GOOD_TOKEN, tree
from tests.unit.goetia_support import daemon, error
from tests.unit.host_support import FRPC, WEBSOCAT, build_host

DECLARED = {
    "secrets", "secrets/token", "logs", ".install.lock", "bin", "bin/frpc", "bin/websocat", "bin/goetia",
    "bin/goetia-shim", f"bin/{DIGESTS}"
}


def mode_of(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def host_tree(tmp_path, monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    return build_host(tmp_path, monkeypatch)


OFF_TUNNEL = "192.0.2.10 51234 192.0.2.1 22"


def run_install(host_tree, **kwargs) -> int:
    return install(host_tree.config, services=host_tree.services, **kwargs)


def contents(root) -> dict[str, bytes]:
    """Every file under `root` with its bytes, except the lock file, whose text names the run that held it."""
    return {
        path: (root / path).read_bytes()
        for path, kind in tree(root).items() if kind == "file" and path != lock.LOCK_NAME
    }


def started(inherit) -> None:
    """What the detached child does once it holds the lock: tell the parent, on the last descriptor it was given."""
    os.write(inherit[-1], b"1")


def stopped(host_tree) -> None:
    """Both daemons installed and stopped, so nothing running is cut by an uninstall."""
    host_tree.script_running(websocat="stopped", frpc="stopped")


def settle(host_tree) -> None:
    """After a first install: goetia reports what it was asked to install, and the daemons run."""
    host_tree.script_running()


# First install ========================================================================================================


def test_a_first_install_stages_and_applies_everything(host_tree, capsys):
    assert run_install(host_tree) == 0
    root = host_tree.root
    assert (root / "secrets" / "token").read_bytes() == f"{GOOD_TOKEN}\n".encode()
    for name in host_tree.pins:
        assert (root / "bin" / name).read_bytes() == host_tree.pinned_bytes(name)
        assert mode_of(root / "bin" / name) == 0o755
    assert read_digests(root / "bin") == host_tree.record()
    assert not (root / "bin" / ".staging").exists()
    assert host_tree.fake.mutations() == [("install", FRPC), ("restart", FRPC), ("install", WEBSOCAT),
                                          ("restart", WEBSOCAT)]
    out = capsys.readouterr().out
    assert "goetia" in out and "attested" in out and "digest-only" in out


def test_a_first_install_does_not_install_frps(host_tree):
    run_install(host_tree)
    assert not (host_tree.root / "bin" / "frps").exists()


def test_install_writes_no_file_other_than_the_declared_set(host_tree):
    before = set(tree(host_tree.root))
    run_install(host_tree)
    assert set(tree(host_tree.root)) - before == DECLARED


def test_token_is_created_0600_and_owned_by_the_service_account(host_tree):
    run_install(host_tree)
    token = host_tree.root / "secrets" / "token"
    assert mode_of(token) == 0o600 and token.stat().st_uid == host_tree.uid


def test_secrets_dir_exists_and_is_0711_before_the_token_is_written(host_tree, monkeypatch):
    """`write_secret` creates the token inside `secrets/`, so the directory must already exist."""
    seen = []
    original = perms.write_secret

    def spy(path, data, owner, readers, *, root):
        seen.append((path.parent.is_dir(), mode_of(path.parent) if path.parent.is_dir() else None))
        return original(path, data, owner, readers, root=root)

    monkeypatch.setattr(perms, "write_secret", spy)
    run_install(host_tree)
    assert seen == [(True, 0o711)]


def test_logs_dir_is_created_owned_by_the_service_account_before_goetia_runs(host_tree):
    run_install(host_tree)
    first = host_tree.fake.records[0]
    assert first["logs"] == {"uid": host_tree.uid, "mode": 0o750}
    assert all(record["logs"] is not None for record in host_tree.fake.records)


def test_env_is_tightened_to_owner_only_and_stays_the_operators(host_tree):
    env = host_tree.root / ".env"
    assert mode_of(env) == 0o644
    run_install(host_tree)
    assert mode_of(env) == 0o600 and env.stat().st_uid == host_tree.uid


def test_the_record_is_0644_and_the_operators(host_tree):
    run_install(host_tree)
    record = host_tree.root / "bin" / DIGESTS
    assert mode_of(record) == 0o644 and record.stat().st_uid == host_tree.uid


def test_the_record_holds_the_digests_of_the_inputs_frpc_started_with(host_tree):
    run_install(host_tree)
    recorded = read_digests(host_tree.root / "bin")
    assert recorded["token"] == host_tree.token_digest() and recorded["frpc.toml"] == host_tree.frpc_toml_digest()
    assert GOOD_TOKEN not in (host_tree.root / "bin" / DIGESTS).read_text()


def test_stage_clears_what_a_failed_earlier_run_left_in_the_staging_directory(host_tree):
    staging = host_tree.root / "bin" / ".staging"
    staging.mkdir(parents=True)
    (staging / "leftover").write_bytes(b"half a download")
    run_install(host_tree)
    assert not staging.exists()


# Converged and partial installs =======================================================================================


def test_an_unchanged_install_restarts_nothing_and_rewrites_no_unit(host_tree):
    """The ssh-safety property: no `install` and no `restart` reaches goetia, so no unit is rewritten and no process
    started from an older spec is left behind a silently newer unit."""
    run_install(host_tree)
    settle(host_tree)
    mark = len(host_tree.fake.calls)
    before = tree(host_tree.root)
    assert run_install(host_tree) == 0
    assert host_tree.fake.mutations()[4:] == []
    assert all(call[1] in ("status", "show") for call in host_tree.fake.calls[mark:])
    assert tree(host_tree.root) == before


def test_an_unchanged_install_downloads_nothing(host_tree):
    run_install(host_tree)
    settle(host_tree)
    downloaded = len(host_tree.downloads)
    run_install(host_tree)
    assert len(host_tree.downloads) == downloaded


def test_install_is_invoked_per_scheduled_id(host_tree):
    run_install(host_tree)
    settle(host_tree)
    host_tree.script_running(websocat="stopped")
    run_install(host_tree)
    installs = host_tree.fake.calls_of("install")
    assert [call[-1] for call in installs[2:]] == [WEBSOCAT]
    for call in installs:
        assert call[-1] in (FRPC, WEBSOCAT) and sum(token in (FRPC, WEBSOCAT) for token in call) == 1
    assert host_tree.fake.mutations()[4:] == [("install", WEBSOCAT), ("restart", WEBSOCAT)]


def test_digests_json_is_written_only_after_restarts_succeed(host_tree, monkeypatch):
    run_install(host_tree)
    settle(host_tree)
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    previous = (host_tree.root / "bin" / DIGESTS).read_bytes()
    host_tree.edit_env(RT_TOKEN="f" * 64)
    host_tree.fake.on("restart", FRPC, stderr="error: failed to start\n", exit=4)
    with pytest.raises(InstallError):
        run_install(host_tree)
    assert (host_tree.root / "bin" / DIGESTS).read_bytes() == previous
    host_tree.fake.forget("restart", FRPC)
    assert run_install(host_tree) == 0
    assert read_digests(host_tree.root / "bin")["token"] == host_tree.token_digest("f" * 64)


def test_partial_failure_exits_nonzero_naming_the_step(host_tree):
    host_tree.fake.on("install", WEBSOCAT, stderr="error: cannot write the unit\n", exit=1)
    with pytest.raises(InstallError) as raised:
        run_install(host_tree)
    message = str(raised.value)
    assert f"installing {WEBSOCAT}" in message and "cannot write the unit" in message
    assert (host_tree.root / "secrets" / "token").exists() and (host_tree.root / "bin" / "frpc").exists()
    assert not (host_tree.root / "bin" / DIGESTS).exists()


def test_rerun_after_a_partial_failure_completes(host_tree, monkeypatch):
    host_tree.fake.on("install", WEBSOCAT, stderr="error: cannot write the unit\n", exit=1)
    with pytest.raises(InstallError):
        run_install(host_tree)
    host_tree.fake.forget("install", WEBSOCAT)
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)  # frpc is running again and is scheduled until a record exists
    host_tree.fake.status(daemon(FRPC), errors=[error("not-installed", WEBSOCAT)], exit=1)
    host_tree.set_spec(FRPC, installed="command: [frpc]\nuser: svc\n")
    assert run_install(host_tree) == 0
    assert read_digests(host_tree.root / "bin") == host_tree.record()
    # No record was written, so frpc's running process is not known to match: both daemons are brought up again.
    assert host_tree.fake.mutations()[-4:] == [("install", FRPC), ("restart", FRPC), ("install", WEBSOCAT),
                                               ("restart", WEBSOCAT)]


def test_a_stale_binary_on_disk_is_replaced_and_its_daemon_restarted(host_tree, monkeypatch):
    run_install(host_tree)
    settle(host_tree)
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    (host_tree.root / "bin" / "frpc").write_bytes(b"tampered")
    run_install(host_tree)
    assert (host_tree.root / "bin" / "frpc").read_bytes() == host_tree.pinned_bytes("frpc")
    assert host_tree.fake.mutations()[4:] == [("install", FRPC), ("restart", FRPC)]


def test_promoting_a_binary_never_follows_a_link_in_bin(host_tree, tmp_path):
    run_install(host_tree)
    settle(host_tree)
    target = tmp_path / "victim"
    target.write_bytes(b"precious")
    (host_tree.root / "bin" / "frpc").unlink()
    (host_tree.root / "bin" / "frpc").symlink_to(target)
    with pytest.raises(BinariesError, match="frpc"):
        run_install(host_tree)
    assert target.read_bytes() == b"precious"


@pytest.mark.parametrize("stop_first", [True, False])
def test_windows_stops_a_daemon_before_replacing_its_binary_and_posix_does_not(host_tree, monkeypatch, stop_first):
    run_install(host_tree)
    settle(host_tree)
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    monkeypatch.setattr(host, "STOP_BEFORE_REPLACE", stop_first)
    (host_tree.root / "bin" / "frpc").write_bytes(b"tampered")
    run_install(host_tree)
    expected = [("install", FRPC), ("restart", FRPC)]
    if stop_first:
        expected = [("stop", FRPC)] + expected
    assert host_tree.fake.mutations()[4:] == expected


# The self-disconnect guard through the whole install ==================================================================


@pytest.fixture
def pending(host_tree):
    """Installed and running, with websocat's unit out of date: the install would restart it."""
    run_install(host_tree)
    settle(host_tree)
    host_tree.set_spec(WEBSOCAT, installed="command: [old]\n", manifest="command: [new]\n")
    return host_tree


def test_guard_refusal_leaves_the_tree_untouched(pending):
    before = contents(pending.root)
    count = len(pending.fake.mutations())
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        run_install(pending)
    after = contents(pending.root)
    assert after == before and len(pending.fake.mutations()) == count


def test_a_frpc_restart_is_refused_too_when_the_session_cannot_be_proven_safe(host_tree):
    run_install(host_tree)
    settle(host_tree)
    host_tree.edit_env(RT_TOKEN="f" * 64)
    before = contents(host_tree.root)
    count = len(host_tree.fake.mutations())
    with pytest.raises(InstallError, match=f"{FRPC}.*--allow-self-disconnect"):
        run_install(host_tree)
    after = contents(host_tree.root)
    assert after == before and len(host_tree.fake.mutations()) == count


def test_install_proceeds_when_ssh_connection_shows_a_non_loopback_client(pending, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.10 51234 192.0.2.1 22")
    assert run_install(pending) == 0
    assert pending.fake.mutations()[-2:] == [("install", WEBSOCAT), ("restart", WEBSOCAT)]


@dataclasses.dataclass
class Spawned:
    argv: list[str]
    cwd: object
    log: int  # inode of the file the child's output goes to


def test_allow_self_disconnect_detaches_the_apply_phase(pending):
    """Intent only: the parent restarts nothing and a detached child was started. Proof that the child survives a real
    disconnect belongs to the end-to-end test."""
    launches = []

    def spawn(argv, *, cwd, log, inherit):
        launches.append(Spawned(list(argv), cwd, os.fstat(log.fileno()).st_ino))
        started(inherit)
        return 4321

    services = dataclasses.replace(pending.services, spawn=spawn)
    count = len(pending.fake.mutations())
    assert install(pending.config, allow_self_disconnect=True, services=services) == 0
    assert pending.fake.mutations()[count:] == []
    (launch, ) = launches
    assert launch.argv[:-4] == [sys.executable, "-m", "ctl", "install", "--allow-self-disconnect", "--apply-staged"]
    assert launch.argv[-4] == "--inherit-lock" and launch.argv[-2] == "--started-fd"
    assert launch.cwd == pending.root and launch.log == os.stat(pending.root / "install.log").st_ino
    log = pending.root / "install.log"
    assert mode_of(log) == 0o640 and log.stat().st_uid == pending.uid


def test_the_detached_child_applies_what_the_parent_staged_without_staging_again(pending):
    (pending.root / "bin" / "websocat").write_bytes(b"tampered")
    launches = []
    services = dataclasses.replace(
        pending.services, spawn=lambda argv, *, cwd, log, inherit: launches.append(argv) or started(inherit) or 1
    )
    child = dataclasses.replace(pending.services, spawn=lambda *a, **k: pytest.fail("the child detaches no further"))
    assert install(pending.config, allow_self_disconnect=True, services=services) == 0
    staged = pending.root / "bin" / ".staging"
    assert (staged / "websocat").read_bytes() == pending.pinned_bytes("websocat")
    assert (pending.root / "bin" / "websocat").read_bytes() == b"tampered"  # promoted only by the child
    downloads = len(pending.downloads)
    assert install(pending.config, allow_self_disconnect=True, apply_staged=True, services=child) == 0
    assert len(pending.downloads) == downloads
    assert (pending.root / "bin" / "websocat").read_bytes() == pending.pinned_bytes("websocat")
    assert not staged.exists()
    assert pending.fake.mutations()[-2:] == [("install", WEBSOCAT), ("restart", WEBSOCAT)]


def test_the_flag_does_not_detach_when_nothing_needs_it(host_tree):
    run_install(host_tree)
    settle(host_tree)
    services = dataclasses.replace(
        host_tree.services, spawn=lambda *a, **k: pytest.fail("nothing here can disconnect anyone", pytrace=False)
    )
    assert install(host_tree.config, allow_self_disconnect=True, services=services) == 0
    assert not (host_tree.root / "install.log").exists()


def test_apply_staged_without_staged_binaries_names_the_missing_one(host_tree):
    run_install(host_tree)
    settle(host_tree)
    (host_tree.root / "bin" / "frpc").write_bytes(b"tampered")
    with pytest.raises(InstallError, match="frpc"):
        install(host_tree.config, allow_self_disconnect=True, apply_staged=True, services=host_tree.services)


# Preflight and accounts ===============================================================================================


def test_preflight_rejects_a_service_user_that_does_not_exist(host_tree):
    host_tree.edit_env(RT_SERVICE_USER="no-such-account-here")
    before = tree(host_tree.root)
    with pytest.raises(ConfigError, match="no-such-account-here"):
        host.preflight(host_tree.config, services=host_tree.services)
    assert tree(host_tree.root) == before


def test_preflight_rejects_a_service_user_with_uid_zero(host_tree):
    host_tree.edit_env(RT_SERVICE_USER="root")
    with pytest.raises(ConfigError, match="uid 0"):
        host.preflight(host_tree.config, services=host_tree.services)


def test_preflight_detects_the_same_account_mode(host_tree):
    assert host.preflight(host_tree.config, services=host_tree.services).mode is AccountMode.SAME


def test_preflight_detects_the_separate_account_mode(host_tree, monkeypatch):
    monkeypatch.setattr(access, "verify_traversable", lambda root, service: None)
    host_tree.edit_env(RT_SERVICE_USER="nobody")
    assert host.preflight(host_tree.config, services=host_tree.services).mode is AccountMode.SEPARATE


def test_preflight_fails_closed_in_separate_account_mode_before_mutating(host_tree):
    """Until the owner decides how a separate account reaches the deployment, the seam refuses."""
    host_tree.edit_env(RT_SERVICE_USER="nobody")
    before = tree(host_tree.root)
    contents = {path: (host_tree.root / path).read_bytes() for path, kind in before.items() if kind == "file"}
    with pytest.raises(InstallError) as raised:
        host.preflight(host_tree.config, services=host_tree.services)
    assert "not yet available" in str(raised.value) and "nobody" in str(raised.value)
    assert tree(host_tree.root) == before
    assert {path: (host_tree.root / path).read_bytes() for path in contents} == contents
    assert host_tree.fake.calls == []
    with pytest.raises(InstallError, match="not yet available"):
        run_install(host_tree)
    assert not (host_tree.root / "secrets").exists()


def test_a_separate_account_is_refused_when_the_service_could_write_the_deployment(host_tree, monkeypatch):
    monkeypatch.setattr(access, "verify_traversable", lambda root, service: None)
    host_tree.edit_env(RT_SERVICE_USER="nobody")
    host_tree.root.chmod(0o777)
    with pytest.raises(InstallError) as raised:
        host.preflight(host_tree.config, services=host_tree.services)
    assert str(host_tree.root) in str(raised.value) and "nobody" in str(raised.value)
    assert "writable" in str(raised.value)


@pytest.mark.parametrize(
    "path", ["bin", "host", "goetia.yaml", "host/frpc.toml", ".env", "ctl", ".venv", "ctl/cli.py", ".venv/lib/site.py"]
)
def test_a_separate_account_is_refused_when_it_could_write_a_file_root_will_run_or_read(host_tree, monkeypatch, path):
    """`goetia.yaml` names the commands root installs as units, and `ctl` and `.venv` are what runs as root, so a
    service able to edit any of them owns the machine."""
    run_install(host_tree)
    for made in ("ctl", ".venv/lib"):
        (host_tree.root / made).mkdir(parents=True, exist_ok=True)
    (host_tree.root / "ctl" / "cli.py").write_text("x")
    (host_tree.root / ".venv" / "lib" / "site.py").write_text("x")
    monkeypatch.setattr(access, "verify_traversable", lambda root, service: None)
    host_tree.edit_env(RT_SERVICE_USER="nobody")
    (host_tree.root / path).chmod(0o777)
    with pytest.raises(InstallError, match="writable"):
        host.preflight(host_tree.config, services=host_tree.services)


def test_the_same_account_mode_does_not_ask_whether_the_service_can_write(host_tree):
    host_tree.root.chmod(0o777)
    assert host.preflight(host_tree.config, services=host_tree.services).mode is AccountMode.SAME


# Uninstall ============================================================================================================


def test_uninstall_removes_the_units_then_bin_logs_and_secrets(host_tree):
    run_install(host_tree)
    stopped(host_tree)
    (host_tree.root / "logs" / "frpc.log").write_text("log\n")
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    root = host_tree.root
    assert not (root / "bin").exists() and not (root / "logs").exists() and not (root / "secrets").exists()
    assert (root / ".env").exists() and (root / "goetia.yaml").exists() and (root / "host" / "frpc.toml").exists()
    assert host_tree.fake.calls_of("uninstall")[-2:] == [["daemon", "uninstall", FRPC],
                                                         ["daemon", "uninstall", WEBSOCAT]]


def test_uninstall_empties_a_leftover_staging_directory_first(host_tree):
    run_install(host_tree)
    stopped(host_tree)
    staging = host_tree.root / "bin" / ".staging"
    staging.mkdir()
    (staging / "frpc").write_bytes(b"x")
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    assert not (host_tree.root / "bin").exists()


def test_uninstall_is_idempotent_and_a_second_run_says_so(host_tree, capsys):
    run_install(host_tree)
    stopped(host_tree)
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    calls = len(host_tree.fake.calls)
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    assert len(host_tree.fake.calls) == calls  # no goetia to ask, and no bin/ for it to have been left in
    assert "already absent" in capsys.readouterr().out


def test_uninstall_tolerates_ids_goetia_does_not_know(host_tree):
    run_install(host_tree)
    stopped(host_tree)
    host_tree.fake.on("uninstall", stdout="not installed (nothing to do)\n")
    assert uninstall(host_tree.config, services=host_tree.services) == 0


def test_uninstall_keeps_everything_when_goetia_cannot_remove_a_unit(host_tree):
    run_install(host_tree)
    stopped(host_tree)
    host_tree.fake.on("uninstall", FRPC, stderr="error: permission denied\n", exit=1)
    with pytest.raises(InstallError, match="permission denied"):
        uninstall(host_tree.config, services=host_tree.services)
    root = host_tree.root
    assert (root / "bin" / "goetia").exists() and (root / "secrets" / "token").exists() and (root / "logs").exists()


def test_uninstall_with_bin_present_but_goetia_missing_refuses(host_tree):
    run_install(host_tree)
    (host_tree.root / "bin" / "goetia").unlink()
    with pytest.raises(InstallError, match="goetia"):
        uninstall(host_tree.config, services=host_tree.services)
    assert (host_tree.root / "secrets" / "token").exists()


# Uninstall after a failed or hand-damaged install =====================================================================


@pytest.fixture
def failed_first_install(host_tree):
    """What a first install leaves when it fails after stage: directories and a token, no goetia, no record."""
    root = host_tree.root
    for name in ("secrets", "logs"):
        (root / name).mkdir()
    (root / "secrets" / "token").write_text("t\n")
    return host_tree


@pytest.mark.parametrize("bin_state", ["absent", "empty", "staging-only"])
def test_uninstall_after_a_failed_first_install_removes_what_is_there(failed_first_install, bin_state, capsys):
    root = failed_first_install.root
    if bin_state != "absent":
        (root / "bin").mkdir()
    if bin_state == "staging-only":
        (root / "bin" / ".staging").mkdir()
        (root / "bin" / ".staging" / "frpc").write_bytes(b"half")
    assert uninstall(failed_first_install.config, services=failed_first_install.services) == 0
    assert not (root / "bin").exists() and not (root / "secrets").exists() and not (root / "logs").exists()
    assert failed_first_install.fake.calls == []
    assert "goetia" in capsys.readouterr().err  # the units, if any, could not be asked about
    assert uninstall(failed_first_install.config, services=failed_first_install.services) == 0


def test_a_second_uninstall_of_a_clean_tree_prints_no_warning(host_tree, capsys):
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    assert capsys.readouterr().err == ""


# The lock =============================================================================================================


def test_an_install_refuses_at_once_while_another_holds_the_lock_and_changes_nothing(host_tree):
    before = tree(host_tree.root)
    with lock.acquire(host_tree.root, command="install"):
        with pytest.raises(InstallError, match="already running"):
            run_install(host_tree)
    assert {k: v for k, v in tree(host_tree.root).items() if k != lock.LOCK_NAME} == before
    assert host_tree.fake.calls == []


def test_an_uninstall_takes_the_same_lock(host_tree):
    run_install(host_tree)
    settle(host_tree)
    host_tree.script_running(websocat="stopped", frpc="stopped")
    with lock.acquire(host_tree.root, command="install"):
        with pytest.raises(InstallError, match="already running"):
            uninstall(host_tree.config, services=host_tree.services)
    assert (host_tree.root / "bin").exists()


def test_the_lock_is_released_when_the_install_ends_whatever_the_outcome(host_tree, monkeypatch):
    host_tree.fake.on("install", WEBSOCAT, stderr="error: nope\n", exit=1)
    with pytest.raises(InstallError):
        run_install(host_tree)
    lock.acquire(host_tree.root, command="install").close()
    host_tree.fake.forget("install", WEBSOCAT)
    host_tree.script_running()
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    run_install(host_tree)
    lock.acquire(host_tree.root, command="install").close()


def test_the_lock_file_belongs_to_the_operator(host_tree):
    run_install(host_tree)
    status = os.stat(host_tree.root / lock.LOCK_NAME)
    assert status.st_uid == host_tree.uid and mode_of(host_tree.root / lock.LOCK_NAME) == 0o640


def test_the_detached_child_inherits_the_lock_and_the_parent_does_not_release_it(pending):
    inherited = []

    def spawn(argv, *, cwd, log, inherit):
        inherited.append(os.dup(inherit[0]))  # what the child process holds
        launches.append(list(argv))
        started(inherit)
        return 1

    launches: list[list[str]] = []
    services = dataclasses.replace(pending.services, spawn=spawn)
    assert install(pending.config, allow_self_disconnect=True, services=services) == 0
    (argv, ) = launches
    assert argv[-4] == "--inherit-lock" and argv[-3].isdigit() and argv[-2] == "--started-fd" and argv[-1].isdigit()
    # The parent has returned and closed its descriptor; the lock is still held through the child's.
    with pytest.raises(InstallError, match="already running"):
        run_install(pending)
    child = dataclasses.replace(pending.services, spawn=lambda *a, **k: pytest.fail("the child detaches no further"))
    fd = inherited[0]
    assert install(pending.config, allow_self_disconnect=True, apply_staged=True, inherit_lock=fd, services=child) == 0
    lock.acquire(pending.root, command="install").close()  # the child's adopted descriptor was the last one


# Uninstall and your own session =======================================================================================


@pytest.fixture
def running(host_tree):
    run_install(host_tree)
    settle(host_tree)
    return host_tree


def test_uninstall_is_refused_when_the_session_cannot_be_proven_safe_and_removes_nothing(running):
    with pytest.raises(InstallError) as raised:
        uninstall(running.config, services=running.services)
    message = str(raised.value)
    assert FRPC in message and WEBSOCAT in message and "--allow-self-disconnect" in message
    assert running.fake.calls_of("uninstall") == [] and (running.root / "bin").exists()
    assert (running.root / "secrets" / "token").exists()


def test_uninstall_proceeds_from_a_session_that_is_provably_off_the_tunnel(running, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    assert uninstall(running.config, services=running.services) == 0
    assert not (running.root / "bin").exists()


def test_uninstall_proceeds_when_nothing_is_running(running):
    running.script_running(websocat="stopped", frpc="stopped")
    assert uninstall(running.config, services=running.services) == 0


def test_uninstall_with_the_flag_detaches_and_the_child_does_the_work(running):
    launches = []

    def spawn(argv, *, cwd, log, inherit):
        launches.append((list(argv), list(inherit)))
        started(inherit)
        return 1

    services = dataclasses.replace(running.services, spawn=spawn)
    assert uninstall(running.config, allow_self_disconnect=True, services=services) == 0
    ((argv, inherit), ) = launches
    assert argv[1:-4] == ["-m", "ctl", "uninstall", "--allow-self-disconnect", "--detached"]
    assert argv[-4] == "--inherit-lock" and argv[-2] == "--started-fd" and len(inherit) == 2
    assert running.fake.calls_of("uninstall") == [] and (running.root / "bin").exists()
    assert (running.root / "install.log").exists()
    assert uninstall(running.config, allow_self_disconnect=True, detached=True, services=running.services) == 0
    assert not (running.root / "bin").exists()


def test_a_detached_uninstall_says_it_is_an_uninstall(running, capsys):
    services = dataclasses.replace(running.services, spawn=lambda argv, *, cwd, log, inherit: started(inherit) or 1)
    assert uninstall(running.config, allow_self_disconnect=True, services=services) == 0
    out = capsys.readouterr().out
    assert "The uninstall is running detached" in out and "ctl uninstall" in out and "ctl install" not in out


def test_the_flag_does_not_detach_an_uninstall_that_cannot_disconnect_anyone(running):
    running.script_running(websocat="stopped", frpc="stopped")
    services = dataclasses.replace(running.services, spawn=lambda *a, **k: pytest.fail("nothing to protect"))
    assert uninstall(running.config, allow_self_disconnect=True, services=services) == 0


# Staging directory ====================================================================================================


def test_stage_empties_the_staging_directory_before_converging_the_owned_directories(running, monkeypatch):
    """On Windows `converge_owned` refuses a subdirectory of `bin`, and a failed run leaves exactly that."""
    staging = running.root / "bin" / ".staging"
    (staging / "leftover-directory").mkdir(parents=True)
    (staging / "leftover").write_bytes(b"x")
    seen = []
    original = perms.converge_owned
    monkeypatch.setattr(
        perms, "converge_owned", lambda path, *args, **kwargs: seen.append((running.root / "bin" / ".staging").exists())
        or original(path, *args, **kwargs)
    )
    run_install(running)
    assert seen and set(seen) == {False}


def test_the_staging_directory_is_gone_after_a_failed_apply(running, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    (running.root / "bin" / "frpc").write_bytes(b"tampered")
    running.fake.on("restart", FRPC, stderr="error: failed\n", exit=4)
    with pytest.raises(InstallError):
        run_install(running)
    assert not (running.root / "bin" / ".staging").exists()


def test_the_staging_directory_is_gone_after_a_failed_download(running, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    (running.root / "bin" / "frpc").write_bytes(b"tampered")

    class Broken:

        def __enter__(self):
            raise BinariesError("the download failed")

        def __exit__(self, *exc):
            return None

    broken = dataclasses.replace(running.services, fetcher=Broken)
    with pytest.raises(BinariesError):
        install(running.config, services=broken)
    assert not (running.root / "bin" / ".staging").exists()


# The owned directories ================================================================================================
#
# On Windows `bin/`, `host/` and `logs/` are the install's outright: each is written whole, with the service's access in
# the same write, and the service's ACE is taken from the repository root only when all of them are done. These
# operations are no-ops on POSIX, where `bin/` and `logs/` have an owner and a mode; these tests record when and with
# what they are called.


@pytest.fixture
def events(monkeypatch):
    """Every permission operation of the install that the Windows install shapes, in order, with its path."""
    events = []
    for name in ("converge_owned", "converge_dir", "converge_tree", "revoke_root"):
        real = getattr(perms, name)

        def spy(path, *args, _name=name, _real=real, **kwargs):
            events.append((_name, path, kwargs))
            return _real(path, *args, **kwargs)

        monkeypatch.setattr(perms, name, spy)
    return events


def test_bin_and_host_are_converged_as_owned_directories(host_tree, events):
    run_install(host_tree)
    owned = [path for name, path, _ in events if name == "converge_owned"]
    assert owned == [host_tree.root / "bin", host_tree.root / "host"]


def test_the_service_is_taken_off_the_root_after_every_owned_directory_is_converged(host_tree, events):
    run_install(host_tree)
    root = host_tree.root
    names = [(name, path) for name, path, _ in events]
    revoked = [index for index, event in enumerate(names) if event[0] == "revoke_root"]
    assert len(revoked) == 1 and names[revoked[0]] == ("revoke_root", root)
    for done in (("converge_owned", root / "bin"), ("converge_owned", root / "host"),
                 ("converge_dir", root / "secrets"), ("converge_tree", root / "logs")):
        assert names.index(done) < revoked[0], done


def test_host_is_converged_with_no_mode_so_git_s_directory_keeps_its_own_on_posix(host_tree, events):
    (host_tree.root / "host").chmod(0o775)
    run_install(host_tree)
    assert mode_of(host_tree.root / "host") == 0o775
    (kwargs, ) = [kwargs for name, path, kwargs in events if name == "converge_owned" and path.name == "host"]
    assert kwargs.get("mode") is None


@pytest.fixture
def replacements(monkeypatch):
    """Every file the install writes into `bin/` through `replace_file`, with the bytes it was given."""
    events = []
    replace_file = host.replace_file
    replace_record = binaries.replace_file

    def spy_replace(directory, name, source, mode, **kwargs):
        events.append((directory / name, source.getvalue()))
        source.seek(0)
        return replace_file(directory, name, source, mode, **kwargs)

    def spy_record(directory, name, source, mode, **kwargs):
        events.append((directory / name, None))
        return replace_record(directory, name, source, mode, **kwargs)

    monkeypatch.setattr(host, "replace_file", spy_replace)
    monkeypatch.setattr(binaries, "replace_file", spy_record)
    return events


def test_every_binary_and_the_record_are_written_into_bin(host_tree, replacements):
    run_install(host_tree)
    bin_dir = host_tree.root / "bin"
    written = {path: content for path, content in replacements}
    assert written == {bin_dir / name: host_tree.pinned_bytes(name)
                       for name in host_tree.pins} | {bin_dir / DIGESTS: None}


def test_an_install_that_replaces_and_records_nothing_writes_no_file(host_tree, replacements):
    run_install(host_tree)
    settle(host_tree)
    replacements.clear()
    run_install(host_tree)
    assert replacements == []


def test_only_the_binary_that_was_replaced_is_written(host_tree, replacements, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    run_install(host_tree)
    settle(host_tree)
    (host_tree.root / "bin" / "frpc").write_bytes(b"tampered")
    replacements.clear()
    run_install(host_tree)
    assert [path for path, _ in replacements if path.name != DIGESTS] == [host_tree.root / "bin" / "frpc"]


# bin/ is the installer's ==============================================================================================


def test_an_existing_bin_is_converged_to_0755_and_the_installing_account(host_tree):
    (host_tree.root / "bin").mkdir()
    (host_tree.root / "bin").chmod(0o777)
    run_install(host_tree)
    assert mode_of(host_tree.root / "bin") == 0o755 and (host_tree.root / "bin").stat().st_uid == os.geteuid()


# The start handshake ==================================================================================================


def test_a_detached_child_that_never_starts_is_reported_with_the_tail_of_its_log_and_nothing_is_applied(pending):

    def spawn(argv, *, cwd, log, inherit):
        log.write(b"Failed to start transient scope unit: Access denied\n")
        log.flush()
        return 99  # the pid of a launcher that has already failed; nobody writes to the pipe

    services = dataclasses.replace(pending.services, spawn=spawn)
    count = len(pending.fake.mutations())
    with pytest.raises(InstallError) as raised:
        install(pending.config, allow_self_disconnect=True, services=services)
    assert "did not start" in str(raised.value) and "Access denied" in str(raised.value)
    assert len(pending.fake.mutations()) == count
    assert not (pending.root / "bin" / ".staging").exists()
    lock.acquire(pending.root, command="install").close()


def test_a_spawn_that_raises_clears_the_staging_directory_and_releases_the_lock(pending):

    def spawn(argv, *, cwd, log, inherit):
        raise OSError("no such launcher")

    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(InstallError, match="no such launcher") as raised:
        install(pending.config, allow_self_disconnect=True, services=services)
    assert isinstance(raised.value.__cause__, OSError)
    assert not (pending.root / "bin" / ".staging").exists()
    lock.acquire(pending.root, command="install").close()


def test_the_child_signals_only_after_it_has_adopted_the_lock(pending, monkeypatch):
    held = lock.acquire(pending.root, command="install")
    inherited = os.dup(held.descriptor)
    held.close()
    pipe = handshake.Pipe()
    order = []
    adopt, signal = lock.adopt, handshake.signal
    monkeypatch.setattr(lock, "adopt", lambda *a, **k: order.append("adopt") or adopt(*a, **k))
    monkeypatch.setattr(handshake, "signal", lambda token, **kw: order.append("signal") or signal(token, **kw))
    install(
        pending.config,
        allow_self_disconnect=True,
        apply_staged=True,
        inherit_lock=inherited,
        started_fd=os.dup(pipe.token),
        services=pending.services,
    )
    assert order == ["adopt", "signal"]
    assert pipe.wait() is True


def test_a_child_that_cannot_adopt_the_lock_never_signals(pending):
    pipe = handshake.Pipe()
    child_end = os.dup(pipe.token)
    with pytest.raises(InstallError, match="lock"):
        install(
            pending.config,
            allow_self_disconnect=True,
            apply_staged=True,
            inherit_lock=os.open(os.devnull, os.O_RDONLY),
            started_fd=child_end,
            services=pending.services,
        )
    os.close(child_end)  # the child exits, closing its end
    assert pipe.wait() is False


# Failures that the child must report ==================================================================================


def test_uninstall_whose_status_cannot_be_read_counts_as_uncertain_and_the_guard_applies(running):
    running.fake.forget("status")
    running.fake.on("status", stderr="error: bus unavailable\n", exit=1)
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        uninstall(running.config, services=running.services)
    assert running.fake.calls_of("uninstall") == [] and (running.root / "bin").exists()


def test_the_flag_gets_an_uninstall_past_a_status_that_cannot_be_read(running):
    running.fake.forget("status")
    running.fake.on("status", stderr="error: bus unavailable\n", exit=1)
    launches = []
    services = dataclasses.replace(
        running.services, spawn=lambda argv, *, cwd, log, inherit: launches.append(argv) or started(inherit) or 1
    )
    assert uninstall(running.config, allow_self_disconnect=True, services=services) == 0
    assert len(launches) == 1


def test_a_failure_after_the_download_clears_the_staging_directory(running, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", OFF_TUNNEL)
    (running.root / "bin" / "frpc").write_bytes(b"tampered")

    def fail(path, owner, readers, *, root):
        raise perms.PermsError("cannot tighten .env")

    monkeypatch.setattr(perms, "harden_file", fail)
    with pytest.raises(perms.PermsError):
        run_install(running)
    assert not (running.root / "bin" / ".staging").exists()


def test_a_child_whose_preflight_fails_clears_the_staging_directory(pending, monkeypatch):
    services = dataclasses.replace(pending.services, spawn=lambda argv, *, cwd, log, inherit: started(inherit) or 1)
    (pending.root / "bin" / "websocat").write_bytes(b"tampered")
    install(pending.config, allow_self_disconnect=True, services=services)
    assert (pending.root / "bin" / ".staging" / "websocat").exists()
    (pending.root / "host" / "frpc.toml").unlink()
    with pytest.raises(InstallError):
        install(pending.config, allow_self_disconnect=True, apply_staged=True, services=pending.services)
    assert not (pending.root / "bin" / ".staging").exists()


# What the parent may touch once the child exists ======================================================================


def interrupt() -> None:
    """Ctrl+C, delivered to this process now."""
    os.kill(os.getpid(), signal.SIGINT)


def staged_for_a_child(pending) -> None:
    (pending.root / "bin" / "websocat").write_bytes(b"tampered")


def test_an_interrupt_after_the_child_has_started_leaves_the_staging_directory_to_it(pending, capsys):
    staged_for_a_child(pending)

    def spawn(argv, *, cwd, log, inherit):
        started(inherit)
        interrupt()  # arrives after the byte; the parent must still learn the outcome before it is raised
        return 55

    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(KeyboardInterrupt):
        install(pending.config, allow_self_disconnect=True, services=services)
    assert (pending.root / "bin" / ".staging" / "websocat").exists()
    out = capsys.readouterr().out
    assert "The install is running detached (pid 55)" in out and "apply finished" in out


def test_an_interrupt_with_no_child_is_a_failure_to_start_and_clears_the_staging_directory(pending):
    staged_for_a_child(pending)

    def spawn(argv, *, cwd, log, inherit):
        interrupt()
        return 55  # never writes

    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(InstallError, match="did not start"):
        install(pending.config, allow_self_disconnect=True, services=services)
    assert not (pending.root / "bin" / ".staging").exists()


def test_a_child_that_cannot_confirm_because_the_parent_is_gone_says_so_and_cleans_up(pending):
    staged_for_a_child(pending)
    services = dataclasses.replace(pending.services, spawn=lambda argv, *, cwd, log, inherit: started(inherit) or 1)
    install(pending.config, allow_self_disconnect=True, services=services)
    assert (pending.root / "bin" / ".staging" / "websocat").exists()
    gone = handshake.Pipe()
    child_end = os.dup(gone.token)
    gone.close()  # the installing session ended: nobody reads
    count = len(pending.fake.mutations())
    with pytest.raises(
        InstallError, match="ended before the detached apply could confirm it started; nothing was applied"
    ):
        install(
            pending.config,
            allow_self_disconnect=True,
            apply_staged=True,
            started_fd=child_end,
            services=pending.services
        )
    assert not (pending.root / "bin" / ".staging").exists() and len(pending.fake.mutations()) == count


def test_a_child_that_cannot_survive_the_session_refuses_and_the_parent_reports_why(pending, monkeypatch):
    staged_for_a_child(pending)
    reason = "still inside a job object; cannot guarantee surviving the session"
    monkeypatch.setattr(detach, "survival_problem", lambda: reason)
    results = []

    def spawn(argv, *, cwd, log, inherit):
        child_end = os.dup(inherit[-1])
        try:
            install(
                pending.config,
                allow_self_disconnect=True,
                apply_staged=True,
                inherit_lock=os.dup(inherit[0]),
                started_fd=child_end,
                services=pending.services,
            )
        except InstallError as exc:
            results.append(str(exc))
        return 77

    count = len(pending.fake.mutations())
    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(InstallError, match="job object") as raised:
        install(pending.config, allow_self_disconnect=True, services=services)
    assert "refused" in str(raised.value) and results == [reason]
    assert not (pending.root / "bin" / ".staging").exists() and len(pending.fake.mutations()) == count


# The pipe alone decides ===============================================================================================


def test_a_spawn_that_raises_after_the_child_started_leaves_the_staging_directory_and_keeps_the_error(pending):
    """A launcher can die after the child exists (a failed close, a failed `set_handle_inheritable`): only the pipe knows."""
    staged_for_a_child(pending)

    def spawn(argv, *, cwd, log, inherit):
        started(inherit)
        raise OSError("launcher died after Popen")

    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(InstallError) as raised:
        install(pending.config, allow_self_disconnect=True, services=services)
    message = str(raised.value)
    assert "launcher died after Popen" in message and "running" in message
    assert (pending.root / "bin" / ".staging" / "websocat").exists()


def test_a_spawn_that_raises_and_a_ctrl_c_together_still_leave_the_staging_to_a_started_child(pending, capsys):
    staged_for_a_child(pending)

    def spawn(argv, *, cwd, log, inherit):
        started(inherit)
        interrupt()
        raise OSError("launcher died after Popen")

    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(KeyboardInterrupt):
        install(pending.config, allow_self_disconnect=True, services=services)
    assert (pending.root / "bin" / ".staging" / "websocat").exists()
    assert "launcher died after Popen" in capsys.readouterr().out  # the error is not lost to the interrupt


def test_a_ctrl_c_during_the_wait_leaves_the_staging_directory_and_says_the_outcome_is_unknown(
    pending, monkeypatch, capsys
):
    staged_for_a_child(pending)

    def interrupted_wait(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(handshake.Pipe, "wait", interrupted_wait)
    services = dataclasses.replace(pending.services, spawn=lambda argv, *, cwd, log, inherit: started(inherit) or 1)
    with pytest.raises(KeyboardInterrupt):
        install(pending.config, allow_self_disconnect=True, services=services)
    assert (pending.root / "bin" / ".staging" / "websocat").exists()
    out = capsys.readouterr().out
    assert "outcome unknown" in out and "apply finished:" in out and "ctl install" in out
    lock.acquire(pending.root, command="install").close()


def test_a_spawn_that_raises_before_any_child_clears_the_staging_directory_and_names_the_error(pending):
    staged_for_a_child(pending)

    def spawn(argv, *, cwd, log, inherit):
        raise OSError("no launcher here")

    services = dataclasses.replace(pending.services, spawn=spawn)
    with pytest.raises(InstallError, match="no launcher here"):
        install(pending.config, allow_self_disconnect=True, services=services)
    assert not (pending.root / "bin" / ".staging").exists()


def test_a_pipe_that_cannot_be_created_clears_the_staging_directory(pending, monkeypatch):
    staged_for_a_child(pending)

    def refuse():
        raise OSError(24, "Too many open files")

    monkeypatch.setattr(handshake, "Pipe", refuse)
    with pytest.raises(OSError, match="Too many open files"):
        install(pending.config, allow_self_disconnect=True, services=pending.services)
    assert not (pending.root / "bin" / ".staging").exists()


def test_a_refusing_child_leaves_the_clearing_to_its_parent(pending, monkeypatch):
    """Two processes clearing one directory would race; the parent is the one that learns the outcome."""
    staged_for_a_child(pending)
    services = dataclasses.replace(pending.services, spawn=lambda argv, *, cwd, log, inherit: started(inherit) or 1)
    install(pending.config, allow_self_disconnect=True, services=services)
    monkeypatch.setattr(detach, "survival_problem", lambda: "still inside a job object")
    pipe = handshake.Pipe()
    with pytest.raises(InstallError, match="job object"):
        install(
            pending.config,
            allow_self_disconnect=True,
            apply_staged=True,
            started_fd=os.dup(pipe.token),
            services=pending.services,
        )
    assert (pending.root / "bin" / ".staging" / "websocat").exists()
    assert pipe.wait() is False and pipe.refusal == "still inside a job object"
