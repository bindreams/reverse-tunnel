"""What every `ctl doctor` run promises, whatever the role: one verdict per check, none hidden, none able to stop the rest."""

import pytest
from tests.unit.doctor_support import (
    World,
    build_bridge,
    build_client,
    build_host_world,
    by_name,
    failures,
)

from ctl import cli, doctor
from ctl.config import ConfigError
from ctl.doctor import Check, Outcome
from ctl.env import EnvError

BRIDGE_CHECKS = {
    "docker_reachable", "container_healthy", "restart_policy", "control_port_published", "admin_healthz",
    "vhost_answers_404", "registered_labels", "label_collisions", "config_skew", "token_skew", "tls_chain_validates",
    "tls_issuer_is_not_staging", "env_permissions", "secrets_dir_permissions", "secrets_token_permissions"
}
HOST_CHECKS = {
    "bin_digests_match_record", "token_matches_record", "frpc_config_matches_record", "frpc_service",
    "websocat_service", "frpc_spec_current", "websocat_spec_current", "websocat_listening", "local_target_answers",
    "env_permissions", "secrets_dir_permissions", "secrets_token_permissions", "tunnel_end_to_end"
}
WINDOWS_ONLY = {"service_read_permissions"}
CLIENT_CHECKS = {"bin_digests_match_record", "env_permissions"}


@pytest.fixture
def bridge(tmp_path) -> World:
    return build_bridge(tmp_path, RT_PUBLIC_HOST="tunnel.example.com")


@pytest.fixture
def host(tmp_path, monkeypatch) -> World:
    world, _ = build_host_world(tmp_path, monkeypatch)
    return world


@pytest.fixture
def client(tmp_path) -> World:
    return build_client(tmp_path)


def diagnose(world: World) -> list[Check]:
    return doctor.run(world.config, world.probes())


# A healthy deployment =================================================================================================


@pytest.mark.parametrize(
    "fixture,expected", [("bridge", BRIDGE_CHECKS), ("host", HOST_CHECKS), ("client", CLIENT_CHECKS)]
)
def test_all_checks_pass_reports_exit_zero(fixture, expected, request):
    checks = diagnose(request.getfixturevalue(fixture))
    assert {check.name for check in checks} == expected
    assert [(c.name, c.detail) for c in checks if c.outcome is not Outcome.PASS] == []
    assert doctor.exit_code(checks) == 0


def test_a_windows_host_also_checks_what_the_service_may_open(host):
    names = {check.name for check in doctor.run(host.config, host.probes(windows=True))}
    assert names == HOST_CHECKS | WINDOWS_ONLY


def test_diagnose_loads_the_env_and_runs_the_checks_of_its_role(bridge):
    checks = doctor.diagnose(bridge.root, bridge.probes())
    assert {check.name for check in checks} == BRIDGE_CHECKS


def test_every_check_says_what_it_found(bridge):
    assert all(check.detail for check in diagnose(bridge))


# Failures do not spread ===============================================================================================


def test_one_failure_does_not_abort_the_others(bridge):
    healthy = by_name(diagnose(bridge))
    bridge.net.healthz = bridge.net.healthz.__class__(503, text="starting")
    checks = by_name(diagnose(bridge))
    assert failures(list(checks.values())) == ["admin_healthz"]
    assert checks.keys() == healthy.keys()
    assert doctor.exit_code(list(checks.values())) == 1


def test_an_exception_inside_a_check_is_that_checks_failure_and_the_rest_still_run(host):

    def explode(*args, **kwargs):
        raise RuntimeError("probe bug")

    checks = doctor.run(host.config, host.probes(tcp=explode))
    assert set(failures(checks)) == {"websocat_listening", "local_target_answers"}
    named = by_name(checks)
    assert "RuntimeError" in named["websocat_listening"].detail and "probe bug" in named["websocat_listening"].detail
    assert named["frpc_service"].outcome is Outcome.PASS


def test_several_failures_are_all_reported(bridge):
    bridge.net.healthz = bridge.net.healthz.__class__(503, text="starting")
    bridge.docker.healthy(restart="no")
    assert set(failures(diagnose(bridge))) == {"admin_healthz", "restart_policy"}


# Not applicable =======================================================================================================


def test_not_applicable_is_reported_and_does_not_fail(tmp_path):
    world = build_bridge(tmp_path)  # no RT_PUBLIC_HOST
    checks = diagnose(world)
    skipped = [check for check in checks if check.outcome is Outcome.NOT_APPLICABLE]
    assert {check.name for check in skipped} == {"tls_chain_validates", "tls_issuer_is_not_staging"}
    assert doctor.exit_code(checks) == 0


def test_tls_check_is_not_applicable_when_rt_public_host_is_unset(tmp_path):
    world = build_bridge(tmp_path)
    named = by_name(diagnose(world))
    for name in ("tls_chain_validates", "tls_issuer_is_not_staging"):
        assert named[name].outcome is Outcome.NOT_APPLICABLE
        assert "RT_PUBLIC_HOST" in named[name].detail
    assert world.tls.validations == [] and world.tls.issuer_lookups == []


# Rendering ============================================================================================================


def test_render_shows_every_check_with_its_outcome_and_detail():
    checks = [
        Check("alpha", Outcome.PASS, "all good"),
        Check("beta", Outcome.FAIL, "went wrong"),
        Check("gamma", Outcome.NOT_APPLICABLE, "no front configured"),
    ]
    lines = doctor.render(checks).splitlines()
    assert any(line.startswith("pass") and "alpha" in line and "all good" in line for line in lines)
    assert any(line.startswith("FAIL") and "beta" in line and "went wrong" in line for line in lines)
    assert any(line.startswith("n/a") and "gamma" in line and "no front configured" in line for line in lines)
    assert "1 passed, 1 failed, 1 not applicable" in lines[-1]


def test_render_indents_a_multiline_detail_under_its_check():
    text = doctor.render([Check("alpha", Outcome.FAIL, "first line\nsecond line")])
    assert "first line" in text and "\n    second line" in text


@pytest.mark.parametrize(
    "outcomes,code", [([Outcome.PASS], 0), ([Outcome.PASS, Outcome.NOT_APPLICABLE], 0), ([Outcome.NOT_APPLICABLE], 0),
                      ([Outcome.PASS, Outcome.FAIL], 1), ([Outcome.FAIL], 1), ([], 0)]
)
def test_exit_code_is_nonzero_only_when_a_check_failed(outcomes, code):
    assert doctor.exit_code([Check(f"c{i}", outcome, "x") for i, outcome in enumerate(outcomes)]) == code


# Who runs it ==========================================================================================================


def test_an_env_file_that_cannot_be_read_is_the_same_named_failure(bridge, monkeypatch):

    def refuse(cls, root):
        error = EnvError(f"{root / '.env'}: Permission denied")
        error.__cause__ = PermissionError(13, "Permission denied")
        raise ConfigError(str(error)) from error

    monkeypatch.setattr(doctor.Config, "load", classmethod(refuse))
    checks = doctor.diagnose(bridge.root, bridge.probes())
    assert [c.name for c in checks] == ["runs_as_repository_owner"]
    assert checks[0].outcome is Outcome.FAIL


def test_a_broken_env_is_a_configuration_error_not_a_check(tmp_path):
    world = build_bridge(tmp_path)
    (world.root / ".env").write_text("ROLE=nonsense\n", encoding="utf-8", newline="\n")
    with pytest.raises(ConfigError, match="ROLE"):
        doctor.diagnose(world.root, world.probes())


# The command ==========================================================================================================


def test_the_doctor_command_prints_the_report_and_returns_its_exit_code(bridge, monkeypatch, capsys):
    monkeypatch.setattr(doctor, "diagnose", lambda root: doctor.run(bridge.config, bridge.probes()))
    assert cli.main(["doctor"], root=bridge.root) == 0
    out = capsys.readouterr().out
    assert "container_healthy" in out and "passed" in out


def test_the_doctor_command_exits_one_when_a_check_fails(bridge, monkeypatch, capsys):
    bridge.docker.healthy(restart="no")
    monkeypatch.setattr(doctor, "diagnose", lambda root: doctor.run(bridge.config, bridge.probes()))
    assert cli.main(["doctor"], root=bridge.root) == 1
    assert "FAIL" in capsys.readouterr().out
