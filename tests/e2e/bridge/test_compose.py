import json

import pytest
from bridge_support import GOOD_TOKEN, REPO_ROOT, Project, make_project

TRAEFIK_LABELS = "traefik.docker.network"


def ports(config: dict) -> set[tuple[str | None, str, int, str]]:
    """`(host_ip, published, target, protocol)` for each publish of the frps service."""
    return {(p.get("host_ip"), p["published"], p["target"], p["protocol"]) for p in config["services"]["frps"]["ports"]}


# compose.yaml =========================================================================================================


def test_service_declares_a_restart_policy(config_project: Project):
    assert config_project.config()["services"]["frps"]["restart"] == "unless-stopped"


def test_compose_environment_does_not_carry_the_token(config_project: Project):
    result = config_project.compose("config", "--format", "json")
    assert result.returncode == 0, result.stderr
    service = config_project.config()["services"]["frps"]
    assert set(service["environment"]) == {"RT_DOMAIN", "RT_ADMIN_PASSWORD"}
    assert "env_file" not in service
    assert "RT_TOKEN" not in result.stdout
    assert GOOD_TOKEN not in result.stdout


def test_compose_publishes_the_control_port_on_tcp_and_udp_and_the_admin_port_on_loopback(config_project: Project):
    assert ports(config_project.config()) == {
        (None, "17000", 8001, "tcp"),
        (None, "17000", 8001, "udp"),
        ("127.0.0.1", "18080", 8080, "tcp"),
        ("127.0.0.1", "17500", 7500, "tcp"),
    }


def test_compose_publishes_the_vhost_on_the_configured_address(tmp_path):
    project = make_project(tmp_path, RT_VHOST_BIND="192.0.2.7")
    assert ("192.0.2.7", "18080", 8080, "tcp") in ports(project.config())


def test_compose_mounts_the_token_and_the_config_read_only(config_project: Project):
    mounts = {v["target"]: v for v in config_project.config()["services"]["frps"]["volumes"]}
    assert set(mounts) == {"/rt/secrets/token", "/rt/bridge/frps.toml"}
    for mount in mounts.values():
        assert mount["type"] == "bind"
        assert mount["read_only"] is True
        # The rendered model omits `false`; test_stack checks that a missing source is refused.
        assert mount["bind"].get("create_host_path") is not True
    assert mounts["/rt/secrets/token"]["source"].endswith("/secrets/token")
    assert mounts["/rt/bridge/frps.toml"]["source"].endswith("/bridge/frps.toml")


def test_compose_healthcheck_probes_the_internal_admin_port(config_project: Project):
    test = config_project.config()["services"]["frps"]["healthcheck"]["test"]
    assert test == ["CMD", "wget", "-qO-", "http://127.0.0.1:7500/healthz"]


@pytest.mark.parametrize(
    "variable",
    ["RT_VHOST_BIND", "RT_VHOST_PORT", "RT_CONTROL_PORT", "RT_ADMIN_PORT", "RT_DOMAIN", "RT_ADMIN_PASSWORD"]
)
def test_compose_config_fails_when_a_required_variable_is_unset(config_project: Project, variable: str):
    config_project.values.pop(variable)
    result = config_project.compose("config")
    assert result.returncode != 0
    assert variable in result.stderr


@pytest.mark.parametrize("variable", ["RT_VHOST_BIND", "RT_CONTROL_PORT"])
def test_compose_config_fails_when_a_required_variable_is_empty(config_project: Project, variable: str):
    config_project.values[variable] = ""
    result = config_project.compose("config")
    assert result.returncode != 0
    assert variable in result.stderr


def test_service_is_hardened(config_project: Project):
    service = config_project.config()["services"]["frps"]
    assert service["cap_drop"] == ["ALL"]
    assert service["cap_add"] == ["DAC_READ_SEARCH"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["read_only"] is True
    assert service["tmpfs"] == ["/run/rt:mode=0700"]


# compose.traefik.yaml =================================================================================================


def test_traefik_overlay_redeclares_the_control_publishes(config_project: Project):
    assert ports(config_project.config(overlay=True)) == {
        (None, "17000", 8001, "tcp"),
        (None, "17000", 8001, "udp"),
        ("127.0.0.1", "17500", 7500, "tcp"),
    }


def test_traefik_overlay_sets_the_docker_network_label(config_project: Project):
    labels = config_project.config(overlay=True)["services"]["frps"]["labels"]
    assert labels[TRAEFIK_LABELS] == "rt-e2e-proxy"


def test_traefik_overlay_routes_the_vhost_and_the_control_connection(config_project: Project):
    labels = config_project.config(overlay=True)["services"]["frps"]["labels"]
    assert labels["traefik.enable"] == "true"
    assert labels["traefik.http.routers.rt-vhost.service"] == "rt-vhost"
    assert labels["traefik.http.services.rt-vhost.loadbalancer.server.port"] == "8080"
    assert labels["traefik.http.services.rt-vhost.loadbalancer.passhostheader"] == "true"
    assert labels["traefik.http.routers.rt-control.rule"] == "Host(`bridge.example.com`)"
    assert labels["traefik.http.routers.rt-control.service"] == "rt-control"
    assert labels["traefik.http.services.rt-control.loadbalancer.server.port"] == "8001"


def test_traefik_vhost_rule_is_case_insensitive_and_quotes_the_domain(config_project: Project):
    rule = config_project.config(overlay=True)["services"]["frps"]["labels"]["traefik.http.routers.rt-vhost.rule"]
    # `config` prints a literal `$` as `$$`, the escape the file itself uses.
    assert rule == r"HostRegexp(`(?i)^[a-z0-9-]+\.\Qtunnel.example.com\E$$`)"


def test_traefik_overlay_attaches_frps_to_the_external_proxy_network(config_project: Project):
    config = config_project.config(overlay=True)
    assert set(config["services"]["frps"]["networks"]) == {"default", "proxy"}
    assert config["networks"]["proxy"]["external"] is True
    assert config["networks"]["proxy"]["name"] == "rt-e2e-proxy"


@pytest.mark.parametrize("variable", ["RT_CONTROL_HOST", "RT_PROXY_NETWORK"])
def test_traefik_overlay_fails_when_its_variable_is_unset_or_empty(config_project: Project, variable: str):
    for value in (None, ""):
        if value is None:
            config_project.values.pop(variable, None)
        else:
            config_project.values[variable] = value
        result = config_project.compose("config", overlay=True)
        assert result.returncode != 0
        assert variable in result.stderr


# COMPOSE_FILE =========================================================================================================


def bare_labels(project: Project) -> dict[str, str]:
    result = project.bare_compose("config", "--format", "json")
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["services"]["frps"].get("labels", {})


def test_compose_file_in_env_selects_the_override_for_every_compose_call(tmp_path):
    project = make_project(tmp_path)
    override = "services:\n  frps:\n    labels:\n      rt.e2e.override: present\n"
    (project.root / "compose.override.yaml").write_text(override, newline="\n")
    # Without COMPOSE_FILE, Compose would load the override on its own; with a list that omits it, it does not.
    project.values["COMPOSE_FILE"] = "compose.yaml"
    assert "rt.e2e.override" not in bare_labels(project)
    project.values["COMPOSE_FILE"] = "compose.yaml:compose.override.yaml"
    # No `-f` here: this is how `ctl`'s own calls (doctor's `ps` and `exec`, uninstall's `down`) run, so they load the
    # same files as the operator's.
    assert bare_labels(project)["rt.e2e.override"] == "present"


def test_the_example_override_merges_with_the_traefik_overlay(tmp_path):
    project = make_project(
        tmp_path, copy_in={"compose.override.yaml": REPO_ROOT / "examples" / "compose.override.yaml"}
    )
    project.values["COMPOSE_FILE"] = "compose.yaml:compose.traefik.yaml:compose.override.yaml"
    labels = bare_labels(project)
    assert labels["traefik.http.routers.rt-vhost.tls.certresolver"] == "letsencrypt"
    assert labels["traefik.http.routers.rt-vhost.tls.domains[0].sans"] == "*.tunnel.example.com"
    assert labels["traefik.http.routers.rt-control.tls.domains[0].main"] == "bridge.example.com"
    # The overlay's own labels survive the merge.
    assert labels["traefik.http.routers.rt-vhost.service"] == "rt-vhost"
