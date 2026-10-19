import re
import sys

import pytest

from ctl.client import render_ssh_config
from ctl.config import Config, ConfigError, Role
from deployment_support import REPO_ROOT, write_env

WEBSOCAT = "websocat.exe" if sys.platform == "win32" else "websocat"


def client(root, **overrides: str) -> Config:
    return write_env(root, Role.CLIENT, **overrides)


def proxy_command(block: str) -> str:
    (line, ) = [line.strip() for line in block.splitlines() if line.strip().startswith("ProxyCommand")]
    return line


def test_emits_wss_when_rt_scheme_is_wss(tmp_path):
    block = render_ssh_config(client(tmp_path, RT_SCHEME="wss", RT_PUBLIC_PORT="443"), "alpha")
    assert proxy_command(block) == "ProxyCommand websocat --binary wss://%h/"


def test_emits_ws_when_it_is_ws(tmp_path):
    block = render_ssh_config(client(tmp_path, RT_SCHEME="ws", RT_PUBLIC_PORT="80"), "alpha")
    assert proxy_command(block) == "ProxyCommand websocat --binary ws://%h/"


def test_names_the_host_by_its_label_under_the_domain(tmp_path):
    block = render_ssh_config(client(tmp_path, RT_DOMAIN="tunnel.example.com"), "alpha")
    lines = [line.strip() for line in block.splitlines()]
    assert "Host alpha" in lines
    assert "HostName alpha.tunnel.example.com" in lines


def test_always_emits_serveraliveinterval(tmp_path):
    for scheme, port in (("ws", "80"), ("wss", "443"), ("ws", "8080")):
        block = render_ssh_config(client(tmp_path, RT_SCHEME=scheme, RT_PUBLIC_PORT=port), "alpha")
        lines = block.splitlines()
        index = next(i for i, line in enumerate(lines) if line.strip() == "ServerAliveInterval 10")
        assert re.search(r"required, not cosmetic", lines[index - 1], re.IGNORECASE)


@pytest.mark.parametrize(
    ("scheme", "port", "authority"),
    [
        ("ws", "80", "%h"),
        ("wss", "443", "%h"),
        ("ws", "8080", "%h:8080"),
        ("wss", "8443", "%h:8443"),
        ("ws", "443", "%h:443"),  # 443 is wss's default, not ws's
        ("wss", "80", "%h:80"),
    ],
)
def test_client_config_carries_a_non_default_public_port(tmp_path, scheme, port, authority):
    block = render_ssh_config(client(tmp_path, RT_SCHEME=scheme, RT_PUBLIC_PORT=port), "alpha")
    assert proxy_command(block) == f"ProxyCommand websocat --binary {scheme}://{authority}/"


def test_client_config_takes_the_label_as_an_argument(tmp_path):
    config = client(tmp_path)
    first, second = render_ssh_config(config, "alpha"), render_ssh_config(config, "bravo")
    assert first != second
    assert "HostName bravo.tunnel.example.com" in second and "alpha" not in second


def test_client_config_needs_no_rt_label_in_the_environment(tmp_path):
    (tmp_path /
     ".env").write_bytes("ROLE=client\nRT_DOMAIN=tunnel.example.com\nRT_SCHEME=wss\nRT_PUBLIC_PORT=443\n".encode())
    config = Config.load(tmp_path)
    assert "RT_LABEL" not in config.values
    assert "HostName bravo.tunnel.example.com" in render_ssh_config(config, "bravo")


@pytest.mark.parametrize("port", ["80", "443", "8080"])
def test_emitted_block_contains_no_placeholder_angle_brackets(tmp_path, port):
    block = render_ssh_config(client(tmp_path, RT_PUBLIC_PORT=port), "alpha")
    assert "<" not in block and ">" not in block


def test_emitted_block_is_one_host_stanza_with_no_blank_lines(tmp_path):
    block = render_ssh_config(client(tmp_path), "alpha")
    assert block.endswith("\n") and not block.endswith("\n\n")
    assert [line for line in block.splitlines() if not line.strip()] == []
    assert len([line for line in block.splitlines() if line.startswith("Host ")]) == 1


@pytest.mark.parametrize(
    "label",
    [
        "Alpha", "al pha", "alpha\nProxyCommand evil", "alpha.beta", "-alpha", "alpha-", "", "example", "a" * 64, "al*",
        "?"
    ],
)
def test_a_label_that_could_not_name_a_host_is_refused(tmp_path, label):
    with pytest.raises(ConfigError) as raised:
        render_ssh_config(client(tmp_path), label)
    assert "evil" not in str(raised.value)


def test_a_hostname_longer_than_dns_allows_is_refused(tmp_path):
    domain = ".".join(["a" * 60] * 4) + ".com"
    with pytest.raises(ConfigError, match="253"):
        render_ssh_config(client(tmp_path, RT_DOMAIN=domain), "a" * 20)


def test_the_installed_websocat_is_used_when_there_is_one(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / WEBSOCAT).write_text("x")
    line = proxy_command(render_ssh_config(client(tmp_path), "alpha"))
    assert str(tmp_path / "bin" / WEBSOCAT) in line
    assert line.endswith("--binary wss://%h/")


def test_an_installed_path_with_spaces_is_quoted_for_the_shell(tmp_path):
    root = tmp_path / "my deployment"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / WEBSOCAT).write_text("x")
    line = proxy_command(render_ssh_config(client(root), "alpha"))
    quoted = f'"{root / "bin" / WEBSOCAT}"' if sys.platform == "win32" else f"'{root / 'bin' / WEBSOCAT}'"
    assert quoted in line


def test_a_bridge_cannot_render_a_client_block(tmp_path):
    config = write_env(tmp_path, Role.BRIDGE)
    with pytest.raises(ConfigError, match="client"):
        render_ssh_config(config, "alpha")


def test_a_host_can_render_one(tmp_path):
    config = write_env(tmp_path, Role.HOST)
    assert "HostName alpha.tunnel.example.com" in render_ssh_config(config, "alpha")


def test_the_shipped_example_is_what_the_command_prints_for_the_shipped_env(tmp_path):
    shipped = (REPO_ROOT / "examples" / "ssh_config").read_text()
    config = write_env(tmp_path, Role.CLIENT)
    assert render_ssh_config(config, "alpha") in shipped


def test_a_percent_in_the_installed_path_is_escaped_for_ssh(tmp_path):
    """ssh expands `%` tokens in a ProxyCommand, so a literal one is written `%%`."""
    root = tmp_path / "100%h"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / WEBSOCAT).write_text("x")
    line = proxy_command(render_ssh_config(client(root), "alpha"))
    assert str(root / "bin" / WEBSOCAT).replace("%", "%%") in line
    assert line.count("%h") == 2  # the escaped `%%h` of the path and the real one in the URL
