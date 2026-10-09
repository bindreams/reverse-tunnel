"""The host's checks: what is installed matches what is tracked, both daemons run, and the tunnel carries traffic."""

from pathlib import Path

import httpx
import pytest
from tests.unit.deployment_support import GOOD_TOKEN, OTHER_TOKEN
from tests.unit.doctor_support import World, build_host_world, by_name, failures
from tests.unit.goetia_support import daemon, error
from tests.unit.host_support import FRPC, WEBSOCAT, HostTree

from ctl import doctor, perms
from ctl.doctor import Outcome
from ctl.doctor.probes import Probes, TlsProbeError
from ctl.perms import Account


@pytest.fixture
def built(tmp_path, monkeypatch) -> tuple[World, HostTree]:
    return build_host_world(tmp_path, monkeypatch)


@pytest.fixture
def world(built) -> World:
    return built[0]


@pytest.fixture
def tree(built) -> HostTree:
    return built[1]


def checks_of(world: World, **overrides):
    return by_name(doctor.run(world.config, world.probes(**overrides)))


# bin/ and the inputs the daemons started with =========================================================================


def test_digest_drift_in_bin_is_a_failure(world, tree):
    (tree.bin / "frpc").write_bytes(b"tampered")
    check = checks_of(world)["bin_digests_match_record"]
    assert check.outcome is Outcome.FAIL and "frpc" in check.detail and "websocat" not in check.detail


def test_a_missing_digest_record_is_a_failure_saying_to_install(world, tree):
    (tree.bin / ".digests.json").unlink()
    check = checks_of(world)["bin_digests_match_record"]
    assert check.outcome is Outcome.FAIL and "ctl install" in check.detail


def test_a_missing_binary_is_a_failure(world, tree):
    (tree.bin / "websocat").unlink()
    check = checks_of(world)["bin_digests_match_record"]
    assert check.outcome is Outcome.FAIL and "websocat" in check.detail


def test_a_binary_the_record_does_not_cover_is_a_failure(world, tree):
    tree.record({"websocat": None})
    check = checks_of(world)["bin_digests_match_record"]
    assert check.outcome is Outcome.FAIL and "websocat" in check.detail


def test_the_inputs_recorded_by_install_are_not_treated_as_files_in_bin(world, tree):
    assert not (tree.bin / "token").exists()
    assert checks_of(world)["bin_digests_match_record"].outcome is Outcome.PASS


@pytest.mark.parametrize(
    "name,disturb", [
        pytest.param("token_matches_record", lambda w, t: w.edit_env(RT_TOKEN=OTHER_TOKEN), id="rotated-token"),
        pytest.param(
            "frpc_config_matches_record",
            lambda w, t: (t.root / "host" / "frpc.toml").write_text("# edited\n"),
            id="edited-frpc-toml"
        ),
    ]
)
def test_token_and_config_input_skew_is_a_failure_on_a_host(world, tree, name, disturb):
    assert checks_of(world)[name].outcome is Outcome.PASS
    disturb(world, tree)
    check = checks_of(world)[name]
    assert check.outcome is Outcome.FAIL
    assert "ctl install" in check.detail
    assert OTHER_TOKEN not in check.detail and GOOD_TOKEN not in check.detail


def test_a_changed_input_does_not_fail_the_other_input_or_the_binaries(world, tree):
    world.edit_env(RT_TOKEN=OTHER_TOKEN)
    assert failures(list(checks_of(world).values())) == ["token_matches_record"]


@pytest.mark.parametrize("key,name", [("token", "token_matches_record"), ("frpc.toml", "frpc_config_matches_record")])
def test_an_input_the_record_never_held_is_a_failure(world, tree, key, name):
    tree.record({key: None})
    assert checks_of(world)[name].outcome is Outcome.FAIL


# goetia: services =====================================================================================================


def test_host_reads_goetia_json_not_text(world, tree):
    checks_of(world)
    statuses = tree.fake.calls_of("status")
    assert statuses and all("--json" in call for call in statuses)
    assert tree.fake.calls_of("list") == []


def test_host_reads_goetia_json_from_a_nonzero_exit(world, tree):
    tree.fake.forget("status")
    tree.fake.status(
        daemon(FRPC, "stopped"), errors=[error("not-installed", WEBSOCAT, "daemon `x` is not installed")], exit=1
    )
    checks = checks_of(world)
    assert checks["frpc_service"].outcome is Outcome.FAIL and "stopped" in checks["frpc_service"].detail
    assert checks["websocat_service"].outcome is Outcome.FAIL
    assert "not-installed" in checks["websocat_service"].detail


def test_both_daemons_running_and_enabled_pass(world):
    checks = checks_of(world)
    assert checks["frpc_service"].outcome is Outcome.PASS and checks["websocat_service"].outcome is Outcome.PASS


def test_status_is_asked_for_exactly_the_two_ids(world, tree):
    checks_of(world)
    assert [call[-2:] for call in tree.fake.calls_of("status")] == [[FRPC, WEBSOCAT]]


@pytest.mark.parametrize(
    "state,enabled,words", [("stopped", True, "stopped"), ("failed", True, "failed"), ("unknown", True, "unknown"),
                            ("running", False, "not enabled")]
)
def test_a_daemon_that_is_not_running_and_enabled_fails_saying_why(world, tree, state, enabled, words):
    tree.script_running(websocat=state, enabled=enabled)
    check = checks_of(world)["websocat_service"]
    assert check.outcome is Outcome.FAIL and words in check.detail
    assert checks_of(world)["frpc_service"].outcome is Outcome.PASS


@pytest.mark.parametrize("kind", ["foreign", "unreadable", "invalid-id", "unavailable", "other", "not-installed"])
def test_every_error_kind_goetia_reports_is_surfaced(world, tree, kind):
    tree.fake.forget("status")
    tree.fake.status(daemon(FRPC), daemon(WEBSOCAT), errors=[error(kind, None, "scripted message")], exit=1)
    checks = checks_of(world)
    for name in ("frpc_service", "websocat_service"):
        assert checks[name].outcome is Outcome.FAIL
        assert kind in checks[name].detail and "scripted message" in checks[name].detail


def test_an_undetermined_entry_is_surfaced_and_fails(world, tree):
    tree.fake.forget("status")
    tree.fake.status(
        daemon(FRPC), daemon(WEBSOCAT), undetermined=[{"name": WEBSOCAT, "reason": "could not read the unit"}], exit=4
    )
    check = checks_of(world)["websocat_service"]
    assert check.outcome is Outcome.FAIL and "could not read the unit" in check.detail


def test_an_error_about_a_daemon_that_was_not_asked_for_is_not_this_hosts_problem(world, tree):
    tree.fake.forget("status")
    tree.fake.status(daemon(FRPC), daemon(WEBSOCAT), errors=[error("foreign", "other-thing")], exit=1)
    checks = checks_of(world)
    assert checks["frpc_service"].outcome is Outcome.PASS and checks["websocat_service"].outcome is Outcome.PASS


def test_output_that_is_not_the_envelope_is_a_failure_not_a_crash(world, tree):
    tree.fake.forget("status")
    tree.fake.on("status", stdout="not json at all\n")
    checks = checks_of(world)
    assert checks["frpc_service"].outcome is Outcome.FAIL
    assert checks["frpc_spec_current"].outcome is Outcome.PASS  # show is independent of status


def test_without_goetia_in_bin_the_services_fail_and_name_the_remedy(world, tree):
    (tree.bin / "goetia").unlink()
    checks = checks_of(world)
    assert checks["frpc_service"].outcome is Outcome.FAIL and "ctl install" in checks["frpc_service"].detail
    assert checks["frpc_spec_current"].outcome is Outcome.NOT_APPLICABLE
    assert tree.fake.calls == []


# goetia: the installed spec ===========================================================================================


def test_spec_drift_is_reported_from_show_not_diff(world, tree):
    tree.set_spec(FRPC, installed="command: [old]\n", manifest="command: [new]\n")
    checks = checks_of(world)
    assert checks["frpc_spec_current"].outcome is Outcome.FAIL
    assert "ctl install" in checks["frpc_spec_current"].detail
    assert checks["websocat_spec_current"].outcome is Outcome.PASS
    assert "diff" not in tree.fake.verbs()
    shows = tree.fake.calls_of("show")
    assert any("-f" in call for call in shows) and any("-f" not in call for call in shows)


def test_an_uninstalled_daemons_spec_is_not_applicable(world, tree):
    tree.fake.forget("status")
    tree.fake.status(daemon(FRPC), errors=[error("not-installed", WEBSOCAT)], exit=1)
    checks = checks_of(world)
    assert checks["websocat_spec_current"].outcome is Outcome.NOT_APPLICABLE
    assert "websocat_service" in checks["websocat_spec_current"].detail


def test_a_show_that_fails_is_a_failure_with_goetias_words(world, tree):
    tree.fake.forget("show", FRPC)
    tree.fake.on("show", FRPC, stderr="boom from goetia", exit=1)
    check = checks_of(world)["frpc_spec_current"]
    assert check.outcome is Outcome.FAIL and "boom from goetia" in check.detail


# Listening and answering ==============================================================================================


def test_websocat_is_probed_on_loopback_at_the_ws_port(world):
    checks_of(world)
    assert ("127.0.0.1", 8022, False) in world.tcp.calls


def test_a_websocat_that_is_not_listening_is_a_failure(world):
    world.tcp.refusing(8022)
    check = checks_of(world)["websocat_listening"]
    assert check.outcome is Outcome.FAIL and "8022" in check.detail and "connection refused" in check.detail


def test_the_local_target_is_asked_for_its_banner_at_the_ssh_port(world):
    checks_of(world)
    assert ("127.0.0.1", 22, True) in world.tcp.calls


def test_a_local_target_that_refuses_is_a_failure(world):
    world.tcp.refusing(22)
    check = checks_of(world)["local_target_answers"]
    assert check.outcome is Outcome.FAIL and "22" in check.detail


@pytest.mark.parametrize("banner", ["", "HTTP/1.1 400 Bad Request"])
def test_a_local_target_that_does_not_speak_ssh_is_a_failure(world, banner):
    world.tcp.listening(22, banner)
    check = checks_of(world)["local_target_answers"]
    assert check.outcome is Outcome.FAIL and "SSH" in check.detail


def test_custom_ports_are_the_ones_probed(tmp_path, monkeypatch):
    world, _ = build_host_world(tmp_path, monkeypatch, RT_SSH_PORT="2222", RT_WS_PORT="9000")
    checks = checks_of(world)
    assert checks["websocat_listening"].outcome is Outcome.PASS and checks["local_target_answers"
                                                                           ].outcome is Outcome.PASS
    assert ("127.0.0.1", 9000, False) in world.tcp.calls and ("127.0.0.1", 2222, True) in world.tcp.calls


# The data path ========================================================================================================


def probe_url(world: World) -> str:
    (request, ) = [r for r in world.net.requests if r.url.host.endswith("example.com")]
    return str(request.url)


def test_the_probe_goes_through_the_public_front_for_this_label(world):
    checks_of(world)
    assert probe_url(world) == "https://alpha.tunnel.example.com/"


def test_the_probe_url_carries_a_port_that_is_not_the_schemes_default(tmp_path, monkeypatch):
    world, _ = build_host_world(tmp_path, monkeypatch, RT_PUBLIC_PORT="8443")
    checks_of(world)
    assert probe_url(world) == "https://alpha.tunnel.example.com:8443/"


@pytest.mark.parametrize(
    "scheme,port,expected", [("ws", "80", "http://alpha.tunnel.example.com/"),
                             ("ws", "8080", "http://alpha.tunnel.example.com:8080/"),
                             ("wss", "443", "https://alpha.tunnel.example.com/")]
)
def test_the_probe_speaks_http_for_the_websocket_schemes(tmp_path, monkeypatch, scheme, port, expected):
    world, _ = build_host_world(tmp_path, monkeypatch, RT_SCHEME=scheme, RT_PUBLIC_PORT=port)
    checks_of(world)
    assert probe_url(world) == expected


def front_answers(world: World, response: httpx.Response | Exception) -> tuple[Outcome, str]:
    world.net.front = response
    check = checks_of(world)["tunnel_end_to_end"]
    return check.outcome, check.detail


def test_host_probe_distinguishes_frps_404_from_a_websocat_400(world):
    passed, passed_detail = front_answers(
        world, httpx.Response(400, headers={"Server": "websocat"}, text="Only WebSocket connections are welcome here")
    )
    no_route, no_route_detail = front_answers(world, httpx.Response(404, text="The page you requested was not found."))
    down, down_detail = front_answers(world, httpx.ConnectError("connection refused"))
    other, other_detail = front_answers(world, httpx.Response(502, headers={"Server": "nginx"}, text="Bad Gateway"))
    assert (passed, no_route, down, other) == (Outcome.PASS, Outcome.FAIL, Outcome.FAIL, Outcome.FAIL)
    assert len({passed_detail, no_route_detail, down_detail, other_detail}) == 4
    assert "no route" in no_route_detail and "alpha" in no_route_detail
    assert "unreachable" in down_detail and "connection refused" in down_detail
    assert "502" in other_detail and "nginx" in other_detail


def test_the_probe_trusts_the_configured_ca_bundle(tmp_path, monkeypatch):
    world, _ = build_host_world(tmp_path, monkeypatch, RT_TLS_CA_BUNDLE="/etc/rt/ca.pem")
    asked = []
    real = Probes.http

    def spy(self, ca_bundle=None):
        asked.append(ca_bundle)
        return real(self, ca_bundle)

    monkeypatch.setattr(Probes, "http", spy)
    checks_of(world)
    assert asked == ["/etc/rt/ca.pem"]


def test_a_bundle_that_cannot_be_loaded_is_the_probes_failure_with_the_reason(world, monkeypatch):

    def refuse(self, ca_bundle=None):
        raise TlsProbeError("RT_TLS_CA_BUNDLE /nope.pem: No such file or directory")

    monkeypatch.setattr(Probes, "http", refuse)
    check = checks_of(world)["tunnel_end_to_end"]
    assert check.outcome is Outcome.FAIL and "/nope.pem" in check.detail


def test_a_404_names_both_possible_causes(world):
    _, detail = front_answers(world, httpx.Response(404))
    assert "not registered" in detail and "websocat_listening" in detail


def test_a_404_with_a_server_header_is_reported_verbatim_not_as_a_missing_route(world):
    outcome, detail = front_answers(world, httpx.Response(404, headers={"Server": "nginx/1.27"}))
    assert outcome is Outcome.FAIL and "no route" not in detail and "404" in detail and "nginx/1.27" in detail


def test_a_400_from_something_other_than_websocat_is_reported_verbatim(world):
    outcome, detail = front_answers(world, httpx.Response(400, headers={"Server": "nginx"}))
    assert outcome is Outcome.FAIL and "400" in detail and "nginx" in detail


def test_a_400_with_no_server_header_is_reported_verbatim(world):
    outcome, detail = front_answers(world, httpx.Response(400))
    assert outcome is Outcome.FAIL and "400" in detail


def test_a_redirect_is_not_followed(world):
    outcome, detail = front_answers(world, httpx.Response(301, headers={"Location": "https://elsewhere.example.net/"}))
    assert outcome is Outcome.FAIL and "301" in detail


def test_the_host_never_asks_the_bridge_admin_api(world):
    checks_of(world)
    assert world.net.asked("127.0.0.1") == []


# Files: stat only =====================================================================================================


def test_loose_env_permissions_are_a_failure(world):
    world.loosen(world.root / ".env", 0o644)
    check = checks_of(world)["env_permissions"]
    assert check.outcome is Outcome.FAIL and "0644" in check.detail


def test_loose_secrets_dir_permissions_are_a_failure(world):
    world.loosen(world.root / "secrets", 0o755)
    check = checks_of(world)["secrets_dir_permissions"]
    assert check.outcome is Outcome.FAIL and "0755" in check.detail


def test_a_secrets_dir_that_is_not_traversable_would_hide_the_token_and_is_named(world):
    world.loosen(world.root / "secrets", 0o700)
    assert checks_of(world)["secrets_dir_permissions"].outcome is Outcome.FAIL


def test_a_token_readable_by_others_is_a_failure(world):
    world.loosen(world.root / "secrets" / "token", 0o644)
    assert checks_of(world)["secrets_token_permissions"].outcome is Outcome.FAIL


def test_an_unexpected_principal_on_env_is_a_failure(world):
    env = world.root / ".env"
    world.granted[env] = world.expected(env) | {"owner=mallory"}
    check = checks_of(world)["env_permissions"]
    assert check.outcome is Outcome.FAIL and "mallory" in check.detail


def test_a_missing_secrets_directory_is_named_with_the_remedy(world):
    (world.root / "secrets" / "token").unlink()
    (world.root / "secrets").rmdir()
    checks = checks_of(world)
    for name in ("secrets_dir_permissions", "secrets_token_permissions"):
        assert checks[name].outcome is Outcome.FAIL and "ctl install" in checks[name].detail


def test_doctor_runs_unelevated_in_separate_account_mode(world, monkeypatch):
    """The service owns `secrets/`, the operator everything else; each path is held to its own owner."""
    monkeypatch.setattr(perms, "operator_account", lambda root: Account("operator-x", 4242, 4242))
    service = perms.service_account(world.config).name
    installed = {
        world.root / ".env": ("operator-x", 0o600),
        world.root / "secrets": (service, 0o711),
        world.root / "secrets" / "token": (service, 0o600),
    }
    for path, (owner, mode) in installed.items():
        world.granted[path] = frozenset({f"owner={owner}", f"mode={mode:04o}"})
    checks = checks_of(world)
    for name in ("env_permissions", "secrets_dir_permissions", "secrets_token_permissions"):
        assert checks[name].outcome is Outcome.PASS, checks[name].detail


def test_the_secrets_owner_must_be_the_service_not_the_operator(world, monkeypatch):
    monkeypatch.setattr(perms, "operator_account", lambda root: Account("operator-x", 4242, 4242))
    service = perms.service_account(world.config).name
    world.granted[world.root / "secrets"] = frozenset({"owner=operator-x", "mode=0711"})
    check = checks_of(world)["secrets_dir_permissions"]
    assert check.outcome is Outcome.FAIL and "operator-x" in check.detail and service in check.detail


@pytest.mark.parametrize("denied", [("token", ), ("secrets", "token")])
def test_every_permission_check_reports_rather_than_raises_when_the_operator_cannot_stat(world, denied):

    def principals(path: Path) -> frozenset[str]:
        if path.name in denied:
            raise PermissionError(13, "Permission denied", str(path))
        return world.principals(path)

    checks = checks_of(world, principals=principals)
    assert checks["secrets_token_permissions"].outcome is Outcome.FAIL
    assert "Permission denied" in checks["secrets_token_permissions"].detail
    assert checks["env_permissions"].outcome is Outcome.PASS
