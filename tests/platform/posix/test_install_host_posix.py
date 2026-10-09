"""A host install end to end as the repository's owner, who is also the service account: the same-account mode.

Everything here runs unprivileged, so nothing is chowned to another account; test_install_host_root.py covers that.
"""

import dataclasses
import os
import stat
import sys

import pytest

from ctl import access, host, perms
from ctl.config import ConfigError
from ctl.download import DIGESTS, read_digests
from ctl.errors import BinariesError, InstallError
from ctl.install import install, uninstall
from ctl.perms import AccountMode
from tests.unit.deployment_support import GOOD_TOKEN, tree
from tests.unit.goetia_support import daemon, error
from tests.unit.host_support import FRPC, WEBSOCAT, build_host

DECLARED = {
    "secrets", "secrets/token", "logs", "bin", "bin/frpc", "bin/websocat", "bin/goetia", "bin/goetia-shim",
    f"bin/{DIGESTS}"
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
    before = {path: (pending.root / path).read_bytes() for path, kind in tree(pending.root).items() if kind == "file"}
    count = len(pending.fake.mutations())
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        run_install(pending)
    after = {path: (pending.root / path).read_bytes() for path, kind in tree(pending.root).items() if kind == "file"}
    assert after == before and len(pending.fake.mutations()) == count


def test_a_frpc_restart_is_refused_too_when_the_session_cannot_be_proven_safe(host_tree):
    run_install(host_tree)
    settle(host_tree)
    host_tree.edit_env(RT_TOKEN="f" * 64)
    before = {
        path: (host_tree.root / path).read_bytes()
        for path, kind in tree(host_tree.root).items() if kind == "file"
    }
    count = len(host_tree.fake.mutations())
    with pytest.raises(InstallError, match=f"{FRPC}.*--allow-self-disconnect"):
        run_install(host_tree)
    after = {
        path: (host_tree.root / path).read_bytes()
        for path, kind in tree(host_tree.root).items() if kind == "file"
    }
    assert after == before and len(host_tree.fake.mutations()) == count


def test_install_proceeds_when_ssh_connection_shows_a_non_loopback_client(pending, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.10 51234 192.0.2.1 22")
    assert run_install(pending) == 0
    assert pending.fake.mutations()[-2:] == [("install", WEBSOCAT), ("restart", WEBSOCAT)]


@dataclasses.dataclass
class Spawned:
    argv: list[str]
    cwd: object
    log: str


def test_allow_self_disconnect_detaches_the_apply_phase(pending):
    """Intent only: the parent restarts nothing and a detached child was started. Proof that the child survives a real
    disconnect belongs to the end-to-end test."""
    launches = []

    def spawn(argv, *, cwd, log):
        launches.append(Spawned(list(argv), cwd, log.name))
        return 4321

    services = dataclasses.replace(pending.services, spawn=spawn)
    count = len(pending.fake.mutations())
    assert install(pending.config, allow_self_disconnect=True, services=services) == 0
    assert pending.fake.mutations()[count:] == []
    (launch, ) = launches
    assert launch.argv == [sys.executable, "-m", "ctl", "install", "--allow-self-disconnect", "--apply-staged"]
    assert launch.cwd == pending.root and launch.log == str(pending.root / "install.log")
    log = pending.root / "install.log"
    assert mode_of(log) == 0o640 and log.stat().st_uid == pending.uid


def test_the_detached_child_applies_what_the_parent_staged_without_staging_again(pending):
    (pending.root / "bin" / "websocat").write_bytes(b"tampered")
    launches = []
    services = dataclasses.replace(pending.services, spawn=lambda argv, *, cwd, log: launches.append(argv) or 1)
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


@pytest.mark.parametrize("path", ["bin", "host", "goetia.yaml", "host/frpc.toml", ".env"])
def test_a_separate_account_is_refused_when_it_could_write_a_file_root_will_run_or_read(host_tree, monkeypatch, path):
    """`goetia.yaml` names the commands root installs as units, so a service able to edit it owns the machine."""
    run_install(host_tree)
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
    (host_tree.root / "logs" / "frpc.log").write_text("log\n")
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    root = host_tree.root
    assert not (root / "bin").exists() and not (root / "logs").exists() and not (root / "secrets").exists()
    assert (root / ".env").exists() and (root / "goetia.yaml").exists() and (root / "host" / "frpc.toml").exists()
    assert host_tree.fake.calls_of("uninstall")[-2:] == [["daemon", "uninstall", FRPC],
                                                         ["daemon", "uninstall", WEBSOCAT]]


def test_uninstall_empties_a_leftover_staging_directory_first(host_tree):
    run_install(host_tree)
    staging = host_tree.root / "bin" / ".staging"
    staging.mkdir()
    (staging / "frpc").write_bytes(b"x")
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    assert not (host_tree.root / "bin").exists()


def test_uninstall_is_idempotent_and_a_second_run_says_so(host_tree, capsys):
    run_install(host_tree)
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    calls = len(host_tree.fake.calls)
    assert uninstall(host_tree.config, services=host_tree.services) == 0
    assert len(host_tree.fake.calls) == calls  # no goetia to ask, and no bin/ for it to have been left in
    assert "already absent" in capsys.readouterr().out


def test_uninstall_tolerates_ids_goetia_does_not_know(host_tree):
    run_install(host_tree)
    host_tree.fake.on("uninstall", stdout="not installed (nothing to do)\n")
    assert uninstall(host_tree.config, services=host_tree.services) == 0


def test_uninstall_keeps_everything_when_goetia_cannot_remove_a_unit(host_tree):
    run_install(host_tree)
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
