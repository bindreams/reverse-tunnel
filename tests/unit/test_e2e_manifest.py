"""The end-to-end tests run the commands `goetia.yaml` declares, with its variables filled in."""

import pytest
from manifest import daemon

VALUES = {
    "RT_WS_PORT": "18022", "RT_SSH_PORT": "22", "RT_LABEL": "alpha", "RT_SERVER_ADDR": "bridge.example.com",
    "RT_SERVER_PORT": "7000", "RT_PROTOCOL": "quic"
}  # fmt: skip


def test_the_websocat_daemon_is_the_manifests_command_with_its_ports_filled_in():
    entry = daemon("reverse-tunnel-websocat", VALUES)
    assert entry.argv == ["bin/websocat", "--binary", "ws-l:127.0.0.1:18022", "tcp:127.0.0.1:22"]
    assert entry.cwd == "logs"


def test_the_frpc_daemon_carries_the_environment_the_manifest_gives_it():
    entry = daemon("reverse-tunnel-frpc", VALUES)
    assert entry.argv == ["bin/frpc", "-c", "../host/frpc.toml"]
    assert entry.env == {
        "RT_LABEL": "alpha",
        "RT_SERVER_ADDR": "bridge.example.com",
        "RT_SERVER_PORT": "7000",
        "RT_PROTOCOL": "quic",
        "RT_WS_PORT": "18022",
    }


def test_a_variable_the_manifest_uses_and_the_caller_does_not_supply_is_an_error():
    with pytest.raises(AssertionError, match="RT_SSH_PORT"):
        daemon("reverse-tunnel-websocat", {"RT_WS_PORT": "1"})
