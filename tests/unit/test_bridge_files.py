import re
import tomllib

import pytest

from ctl import config
from ctl.env import GO_TEMPLATE_REFERENCE
from ctl.config import EXAMPLE_ADMIN_PASSWORD, EXAMPLE_TOKEN
from scanner_support import REPO_ROOT

BRIDGE = REPO_ROOT / "bridge"
FRPS_TOML = BRIDGE / "frps.toml"
DOCKERFILE = BRIDGE / "Dockerfile"
ENTRYPOINT = BRIDGE / "entrypoint.sh"
COMPOSE_FILES = [
    REPO_ROOT / "compose.yaml", REPO_ROOT / "compose.traefik.yaml", REPO_ROOT / "examples" / "compose.override.yaml"
]
LOCK = REPO_ROOT / "binaries.lock.toml"

# frps.toml ============================================================================================================


def frps_config() -> dict:
    return tomllib.loads(FRPS_TOML.read_text(encoding="utf-8"))


def string_values(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from string_values(value)
    elif isinstance(node, list):
        for value in node:
            yield from string_values(value)


def test_frps_config_contains_no_container_path():
    text = FRPS_TOML.read_text(encoding="utf-8")
    assert "/run/" not in text
    assert "/etc/" not in text
    assert not any(value.startswith("/") for value in string_values(frps_config()))


def test_frps_config_names_no_host_and_no_proxy():
    config = frps_config()
    assert "proxies" not in config
    assert "[[proxies]]" not in FRPS_TOML.read_text(encoding="utf-8")
    for value in string_values(config):
        value = re.sub(r"\{\{[^}]*\}\}", "", value)
        if value == "0.0.0.0":  # the bind address of the admin API, not a host
            continue
        assert not re.search(r"[A-Za-z0-9-]+\.[A-Za-z0-9-]+", value), f"literal host-like value {value!r}"


def test_frps_config_reads_the_token_from_a_relative_file():
    assert frps_config()["auth"]["tokenSource"] == {"type": "file", "file": {"path": "secrets/token"}}


def test_frps_admin_api_binds_every_interface_of_the_container():
    config = frps_config()
    assert config["webServer"]["addr"] == "0.0.0.0"
    assert config["webServer"]["port"] == 7500


def test_frps_config_takes_its_two_secrets_from_the_environment():
    config = frps_config()
    assert config["subDomainHost"] == "{{ .Envs.RT_DOMAIN }}"
    assert config["webServer"]["password"] == "{{ .Envs.RT_ADMIN_PASSWORD }}"


# Dockerfile ===========================================================================================================

ARCHITECTURES = [
    pytest.param("AMD64", "linux-x86_64", id="amd64"),
    pytest.param("ARM64", "linux-aarch64", id="arm64"),
]


def dockerfile_args() -> dict[str, str]:
    text = DOCKERFILE.read_text(encoding="utf-8")
    return dict(re.findall(r"^ARG (\w+)=(\S+)$", text, re.MULTILINE))


@pytest.mark.parametrize(("arch", "platform"), ARCHITECTURES)
def test_dockerfile_arg_defaults_match_the_lock(arch, platform):
    pins = [
        pin for pin in tomllib.loads(LOCK.read_text(encoding="utf-8"))["frp"][platform] if pin["install_name"] == "frps"
    ]
    assert len(pins) == 1
    pin = pins[0]
    args = dockerfile_args()
    assert args[f"FRP_{arch}_URL"] == pin["url"]
    assert args[f"FRP_{arch}_SHA256"] == pin["asset_sha256"]
    assert args[f"FRP_{arch}_MEMBER"] == pin["archive_member"]
    assert args[f"FRP_{arch}_MEMBER_SHA256"] == pin["member_sha256"]


def test_dockerfile_pins_its_base_image_by_digest():
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert text.startswith("# syntax=docker/dockerfile:1\n")
    images = re.findall(r"^FROM (\S+)", text, re.MULTILINE)
    assert images
    assert all(re.fullmatch(r"\S+@sha256:[0-9a-f]{64}", image) for image in images)


def test_dockerfile_does_not_copy_the_config_into_the_image():
    copies = re.findall(r"^(?:COPY|ADD)\b.*$", DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)
    assert copies
    assert not any("frps.toml" in line for line in copies)


# entrypoint.sh ========================================================================================================


def test_entrypoint_is_posix_sh():
    assert ENTRYPOINT.read_text(encoding="utf-8").startswith("#!/bin/sh\n")


def test_entrypoint_placeholders_match_the_ones_ctl_refuses():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert f"example_token={EXAMPLE_TOKEN}\n" in text
    assert f"example_admin_password={EXAMPLE_ADMIN_PASSWORD}\n" in text


def entrypoint_constant(name: str) -> str:
    match = re.search(rf"^{name}='?([^'\n]*)'?$", ENTRYPOINT.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, name
    return match.group(1)


def test_entrypoint_value_rules_are_the_ones_ctl_applies():
    assert entrypoint_constant("admin_password_pattern") == f"^{config.ADMIN_PASSWORD.pattern}$"
    assert entrypoint_constant("dns_label_pattern") == config.DNS_LABEL.pattern
    assert entrypoint_constant("numeric_label_pattern") == "^" + config.NUMERIC_LABEL.pattern.replace("(?:", "(")
    assert int(entrypoint_constant("max_dns_name_length")) == config.MAX_DNS_NAME_LENGTH


def test_entrypoint_template_pattern_is_the_one_ctl_applies():
    """The awk literal is `GO_TEMPLATE_REFERENCE` anchored, as an ERE with `\\` doubled before a metacharacter."""
    literal = re.search(r'^\s*pattern = "(.*)"$', ENTRYPOINT.read_text(encoding="utf-8"), re.MULTILINE)
    assert literal
    expected = re.sub(r"\\([{}$.])", r"\\\\\1", GO_TEMPLATE_REFERENCE.pattern).replace("(?:", "(")
    assert literal.group(1) == "^" + expected


# compose files ========================================================================================================


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda path: path.name)
def test_every_compose_variable_is_required_with_a_message(path):
    references = re.findall(r"\$\{[^}]*\}", path.read_text(encoding="utf-8"))
    assert references
    for reference in references:
        assert re.fullmatch(r"\$\{[A-Z][A-Z0-9_]*:\?[^}$]+\}", reference), reference


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda path: path.name)
def test_compose_files_do_not_load_env_file(path):
    assert "env_file" not in path.read_text(encoding="utf-8")


# front proxy examples =================================================================================================


def test_nginx_example_forwards_websocket_upgrades_and_the_host():
    text = (REPO_ROOT / "examples" / "nginx.conf").read_text(encoding="utf-8")
    assert text.count("server_name") == 2
    assert "proxy_http_version 1.1;" in text
    assert "proxy_set_header Upgrade $http_upgrade;" in text
    assert 'proxy_set_header Connection "upgrade";' in text
    assert "proxy_set_header Host $host;" in text


def test_nginx_example_passes_websocats_server_header_through_for_the_vhost():
    """nginx hides the upstream's Server header by default, and `ctl doctor` recognises a live tunnel by it."""
    text = (REPO_ROOT / "examples" / "nginx.conf").read_text(encoding="utf-8")
    vhost = text.split("server {")[1]
    assert "proxy_pass_header Server;" in vhost


def test_caddy_example_ships_the_vhost_and_the_control_site():
    text = (REPO_ROOT / "examples" / "Caddyfile").read_text(encoding="utf-8")
    assert re.findall(r"^(\S+) \{$", text, re.MULTILINE) == ["*.tunnel.example.com", "bridge.example.com"]


def test_traefik_overlay_says_it_needs_traefik_v3():
    assert "Traefik v3" in (REPO_ROOT / "compose.traefik.yaml").read_text(encoding="utf-8")
