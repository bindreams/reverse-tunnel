"""What a host install decides before it changes anything: the plan, and the guard that protects your own session."""

import pytest
from tests.unit.deployment_support import write_env
from tests.unit.goetia_support import daemon, error
from tests.unit.host_support import FRPC, WEBSOCAT, build_host

from ctl import access, host
from ctl.config import Role
from ctl.errors import BinariesError, InstallError


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setattr(access, "verify_traversable", lambda root, service: None)  # covered in test_access.py
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    return build_host(tmp_path, monkeypatch)


@pytest.fixture
def converged(tree):
    tree.converge()
    return tree


def plan_of(tree, **kwargs) -> host.Plan:
    return host.preflight(tree.config, services=tree.services, **kwargs)


def snapshot(root):
    return {
        path.relative_to(root).as_posix(): (path.read_bytes() if path.is_file() else None)
        for path in sorted(root.rglob("*"))
    }


# Preflight changes nothing ============================================================================================


def test_preflight_mutates_nothing(converged):
    converged.edit_env(RT_WS_PORT="9000")  # a pending change, so the plan is not empty
    before = snapshot(converged.root)
    plan_of(converged)
    assert snapshot(converged.root) == before


def test_preflight_on_a_never_installed_tree_creates_no_directory(tree):
    before = snapshot(tree.root)
    plan_of(tree)
    assert snapshot(tree.root) == before
    assert not (tree.root / "bin").exists() and not (tree.root / "secrets").exists()


def test_preflight_downloads_nothing(converged):
    plan_of(converged)
    assert converged.downloads == []


def test_preflight_refuses_a_deployment_that_is_not_a_host(tree, tmp_path):
    root = tmp_path / "client"
    root.mkdir()
    with pytest.raises(InstallError, match="ROLE=host"):
        host.preflight(write_env(root, Role.CLIENT), services=tree.services)


def test_preflight_runs_the_traversal_check_before_asking_goetia_anything(tree, monkeypatch):

    def refuse(root, service):
        raise InstallError("/home/operator is not searchable by rt-test-svc")

    monkeypatch.setattr(access, "verify_traversable", refuse)
    with pytest.raises(InstallError, match="not searchable"):
        plan_of(tree)
    assert tree.fake.calls == []


# What is scheduled ====================================================================================================


def test_a_converged_install_schedules_nothing(converged):
    plan = plan_of(converged)
    assert plan.daemons_to_converge == () and plan.binaries_to_replace == ()


def test_a_never_installed_tree_schedules_both_daemons_and_every_binary(tree):
    plan = plan_of(tree)
    assert set(plan.daemons_to_converge) == {FRPC, WEBSOCAT}
    assert set(plan.binaries_to_replace) == {"frpc", "websocat", "goetia", "goetia-shim"}
    assert tree.fake.calls == []  # there is no goetia to ask yet


def test_plan_schedules_a_daemon_whose_binary_changed(converged):
    """The record matches websocat but not frpc: only frpc is scheduled."""
    converged.record({"frpc": "0" * 64})
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (FRPC, )
    assert "binary" in plan.reasons[FRPC]
    assert plan.binaries_to_replace == ()  # the file on disk is the pinned one; only the running process is stale


def test_plan_replaces_a_binary_whose_file_differs_from_the_pin_though_the_record_agrees(converged):
    (converged.bin / "frpc").write_bytes(b"tampered")
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.binaries_to_replace == ("frpc", ) and plan.daemons_to_converge == (FRPC, )


def test_plan_replaces_a_binary_that_is_missing(converged):
    (converged.bin / "websocat").unlink()
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.binaries_to_replace == ("websocat", ) and plan.daemons_to_converge == (WEBSOCAT, )


def test_a_goetia_update_alone_restarts_no_daemon(converged):
    (converged.bin / "goetia").write_bytes(b"older")
    converged.record({"goetia": "0" * 64})
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.binaries_to_replace == ("goetia", ) and plan.daemons_to_converge == ()


def test_plan_schedules_a_daemon_whose_goetia_spec_changed(converged):
    """Same record, a changed `.env` port: the websocat spec differs, frpc's does not."""
    converged.set_spec(WEBSOCAT, installed="command: [websocat, 8022]\n", manifest="command: [websocat, 9000]\n")
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (WEBSOCAT, ) and "spec" in plan.reasons[WEBSOCAT]


def test_plan_schedules_a_daemon_that_is_installed_but_stopped(converged):
    """The convergence property: identical digests and spec, yet it is not running, so a diff-only plan lies."""
    converged.script_running(websocat="stopped")
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (WEBSOCAT, ) and "stopped" in plan.reasons[WEBSOCAT]


def test_plan_schedules_a_daemon_that_is_installed_but_not_enabled(converged):
    converged.script_running(enabled=False)
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (WEBSOCAT, ) and "enabled" in plan.reasons[WEBSOCAT]


def test_plan_schedules_a_daemon_that_goetia_does_not_know(converged):
    converged.fake.forget("status")
    converged.fake.status(daemon(FRPC), errors=[error("not-installed", WEBSOCAT)], exit=1)
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (WEBSOCAT, ) and "not installed" in plan.reasons[WEBSOCAT]


def test_plan_schedules_frpc_when_the_token_digest_changed(converged):
    """Rotation: frp reads `tokenSource` once per process, and `loginFailExit = false` keeps frpc from ever exiting."""
    converged.edit_env(RT_TOKEN="f" * 64)
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (FRPC, ) and "token" in plan.reasons[FRPC]


def test_plan_schedules_frpc_when_host_frpc_toml_changed(converged):
    """The `git pull` case."""
    path = converged.root / "host" / "frpc.toml"
    path.write_text(path.read_text() + "# edited\n")
    plan = plan_of(converged, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (FRPC, ) and "frpc.toml" in plan.reasons[FRPC]


def test_plan_schedules_frpc_when_the_input_record_is_missing(converged):
    converged.record({"token": None})
    assert plan_of(converged, allow_self_disconnect=True).daemons_to_converge == (FRPC, )


def test_plan_records_what_the_running_daemons_will_have_read(converged):
    plan = plan_of(converged)
    assert plan.inputs == {"token": converged.token_digest(), "frpc.toml": converged.frpc_toml_digest()}


def test_a_missing_frpc_config_is_an_error(converged):
    (converged.root / "host" / "frpc.toml").unlink()
    with pytest.raises(InstallError, match="frpc.toml"):
        plan_of(converged)


def test_a_malformed_record_is_an_error_not_an_empty_one(converged):
    (converged.bin / ".digests.json").write_text("not json")
    with pytest.raises(BinariesError, match="digests"):
        plan_of(converged)


def test_goetia_reporting_a_daemon_it_cannot_read_stops_the_plan(converged):
    converged.fake.forget("status")
    converged.fake.status(daemon(FRPC), errors=[error("unreadable", WEBSOCAT)], exit=4)
    with pytest.raises(InstallError, match="unreadable"):
        plan_of(converged)


# The self-disconnect guard ============================================================================================


@pytest.fixture
def websocat_pending(converged):
    """websocat is running and scheduled for a restart: the one case the guard exists for."""
    converged.set_spec(WEBSOCAT, installed="command: [old]\n", manifest="command: [new]\n")
    return converged


@pytest.mark.parametrize("ssh_connection", [None, "127.0.0.1 51234 127.0.0.1 22", "::1 51234 ::1 22"])
def test_the_guard_refuses_when_the_session_cannot_be_proven_safe(websocat_pending, monkeypatch, ssh_connection):
    if ssh_connection:
        monkeypatch.setenv("SSH_CONNECTION", ssh_connection)
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        plan_of(websocat_pending)


def test_guard_refusal_names_the_failing_disjunct(websocat_pending, monkeypatch):
    with pytest.raises(InstallError) as absent:
        plan_of(websocat_pending)
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 51234 127.0.0.1 22")
    with pytest.raises(InstallError) as loopback:
        plan_of(websocat_pending)
    monkeypatch.setenv("SSH_CONNECTION", "garbage")
    with pytest.raises(InstallError) as malformed:
        plan_of(websocat_pending)
    assert "SSH_CONNECTION is not set" in str(absent.value) and "sudo" in str(absent.value)
    assert "127.0.0.1" in str(loopback.value) and "loopback" in str(loopback.value)
    assert "garbage" in str(malformed.value)
    assert len({str(absent.value), str(loopback.value), str(malformed.value)}) == 3


def test_guard_refusal_leaves_the_tree_untouched(websocat_pending):
    before = snapshot(websocat_pending.root)
    with pytest.raises(InstallError):
        plan_of(websocat_pending)
    assert snapshot(websocat_pending.root) == before
    assert websocat_pending.fake.mutations() == []


def test_the_plan_proceeds_when_ssh_connection_shows_a_non_loopback_client(websocat_pending, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.10 51234 192.0.2.1 22")
    plan = plan_of(websocat_pending)
    assert plan.daemons_to_converge == (WEBSOCAT, ) and plan.detach is False


def test_the_refusal_names_the_real_ways_forward(websocat_pending):
    with pytest.raises(InstallError) as raised:
        plan_of(websocat_pending)
    message = str(raised.value)
    assert "--allow-self-disconnect" in message and "--preserve-env=SSH_CONNECTION" in message


def test_the_plan_proceeds_when_websocat_is_not_yet_running(tree):
    """A first install never needs the flag: nothing is installed, so nothing can be serving this session."""
    plan = plan_of(tree)
    assert WEBSOCAT in plan.daemons_to_converge and plan.detach is False


@pytest.mark.parametrize("state", ["stopped", "failed"])
def test_the_plan_proceeds_when_websocat_is_installed_but_not_running(converged, state):
    converged.script_running(websocat=state)
    assert plan_of(converged).daemons_to_converge == (WEBSOCAT, )


def test_an_unknown_websocat_state_counts_as_running(converged):
    converged.script_running(websocat="unknown")
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        plan_of(converged)


def test_a_daemon_that_is_not_in_the_plan_needs_no_proof(converged):
    """websocat is running and unchanged; frpc is stopped and is the only one scheduled."""
    converged.script_running(frpc="stopped")
    assert plan_of(converged).daemons_to_converge == (FRPC, )


def test_the_flag_overrides_the_guard_and_asks_for_the_apply_phase_to_be_detached(websocat_pending):
    plan = plan_of(websocat_pending, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (WEBSOCAT, ) and plan.detach is True


def test_the_flag_does_not_detach_when_the_session_is_provably_safe(websocat_pending, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.10 51234 192.0.2.1 22")
    assert plan_of(websocat_pending, allow_self_disconnect=True).detach is False


def test_the_flag_does_not_detach_when_no_scheduled_daemon_is_running(converged):
    converged.script_running(frpc="stopped")
    assert plan_of(converged, allow_self_disconnect=True).detach is False


# Traces of an earlier install =========================================================================================
# With no goetia to ask, "nothing is installed" is only believable on a tree that has never been installed.


@pytest.mark.parametrize("trace", ["secrets", "logs", "bin"])
def test_a_trace_of_an_earlier_install_makes_not_installed_uncertain(tree, trace):
    (tree.root / trace).mkdir()
    if trace == "bin":
        (tree.root / "bin" / "frpc").write_bytes(b"x")
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        plan_of(tree)
    plan = plan_of(tree, allow_self_disconnect=True)
    assert set(plan.daemons_to_converge) == {FRPC, WEBSOCAT}


def test_bin_removed_by_hand_after_a_real_install_does_not_open_the_guard(converged):
    """`rm -rf bin` leaves secrets/ and logs/ behind, and the daemons it installed may still be running."""
    (converged.root / "secrets").mkdir()
    (converged.root / "logs").mkdir()
    for entry in (converged.root / "bin").iterdir():
        entry.unlink()
    (converged.root / "bin").rmdir()
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        plan_of(converged)


@pytest.mark.parametrize("leftover", [".install.lock", "install.log"])
def test_files_the_installer_itself_leaves_are_not_traces(tree, leftover):
    (tree.root / leftover).write_text("x")
    assert plan_of(tree).detach is False


def test_a_staging_directory_alone_is_not_a_trace(tree):
    (tree.root / "bin" / ".staging").mkdir(parents=True)
    assert plan_of(tree).detach is False


# The guard covers frpc too ============================================================================================
# A session through the tunnel rides frps -> frpc -> websocat -> sshd, so restarting either one drops it.


@pytest.fixture
def frpc_pending(converged):
    """frpc is running and its token has been rotated, so the install would restart it; websocat is untouched."""
    converged.edit_env(RT_TOKEN="f" * 64)
    return converged


def test_the_guard_refuses_a_restart_of_frpc_alone_and_names_it(frpc_pending):
    with pytest.raises(InstallError) as raised:
        plan_of(frpc_pending)
    message = str(raised.value)
    assert FRPC in message and WEBSOCAT not in message and "--allow-self-disconnect" in message
    assert "SSH_CONNECTION is not set" in message


def test_the_guard_names_both_daemons_when_both_would_restart(frpc_pending):
    frpc_pending.set_spec(WEBSOCAT, installed="command: [old]\n", manifest="command: [new]\n")
    with pytest.raises(InstallError) as raised:
        plan_of(frpc_pending)
    assert FRPC in str(raised.value) and WEBSOCAT in str(raised.value)


def test_a_loopback_session_is_refused_for_frpc_and_the_message_says_loopback(frpc_pending, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "127.0.0.1 51234 127.0.0.1 22")
    with pytest.raises(InstallError, match="loopback"):
        plan_of(frpc_pending)


def test_frpc_may_be_restarted_from_a_session_that_is_provably_off_the_tunnel(frpc_pending, monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.10 51234 192.0.2.1 22")
    plan = plan_of(frpc_pending)
    assert plan.daemons_to_converge == (FRPC, ) and plan.detach is False


def test_the_flag_detaches_the_apply_phase_for_a_frpc_restart(frpc_pending):
    plan = plan_of(frpc_pending, allow_self_disconnect=True)
    assert plan.daemons_to_converge == (FRPC, ) and plan.detach is True


@pytest.mark.parametrize("state", ["stopped", "failed"])
def test_frpc_may_be_restarted_when_it_is_not_running(frpc_pending, state):
    frpc_pending.script_running(frpc=state)
    assert plan_of(frpc_pending).daemons_to_converge == (FRPC, )


def test_a_frpc_that_goetia_does_not_know_needs_no_proof(tree):
    assert plan_of(tree).detach is False


def test_a_missing_goetia_with_a_record_cannot_show_websocat_is_stopped(converged):
    """bin/ was damaged after an install: whether websocat is running is unknowable, so it is assumed to be."""
    (converged.bin / "goetia").unlink()
    with pytest.raises(InstallError, match="--allow-self-disconnect"):
        plan_of(converged)
    assert set(plan_of(converged, allow_self_disconnect=True).daemons_to_converge) == {FRPC, WEBSOCAT}


def test_session_is_provably_safe_reads_the_environment(monkeypatch):
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    assert host.session_is_provably_safe() is False
    monkeypatch.setenv("SSH_CONNECTION", "198.51.100.7 40000 198.51.100.1 22")
    assert host.session_is_provably_safe() is True
