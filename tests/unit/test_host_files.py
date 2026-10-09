"""The tracked host files, read statically: the goetia manifest and the frpc config that its daemons run with."""

import re
import tomllib
from pathlib import PurePosixPath

import pytest
import yaml

from ctl.env import GO_TEMPLATE_REFERENCE, referenced_in_file
from tests.unit.deployment_support import REPO_ROOT

MANIFEST = REPO_ROOT / "goetia.yaml"
FRPC_TOML = REPO_ROOT / "host" / "frpc.toml"
FRPC, WEBSOCAT = "reverse-tunnel-frpc", "reverse-tunnel-websocat"
SAMPLE = {
    "RT_LABEL": "alpha",
    "RT_SERVER_ADDR": "bridge.example.com",
    "RT_SERVER_PORT": "7000",
    "RT_PROTOCOL": "quic",
    "RT_WS_PORT": "8022",
}


def daemons() -> dict:
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["daemons"]


def frpc_config() -> dict:
    """The tracked file as frpc sees it once it has expanded `{{ .Envs.X }}`."""
    text = FRPC_TOML.read_text(encoding="utf-8")
    rendered = GO_TEMPLATE_REFERENCE.sub(lambda match: SAMPLE[match.group(1)], text)
    assert "{{" not in rendered
    return tomllib.loads(rendered)


def resolve(cwd: str, relative: str) -> str:
    """Where a relative argument lands for a process whose working directory is `cwd` (both relative to the root)."""
    parts: list[str] = []
    for part in PurePosixPath(cwd, relative).parts:
        if part == "..":
            parts.pop()
        elif part != ".":
            parts.append(part)
    return "/".join(parts)


# goetia.yaml ==========================================================================================================


def test_goetia_manifest_declares_two_separate_daemons_with_restart_always():
    declared = daemons()
    assert set(declared) == {FRPC, WEBSOCAT}
    for spec in declared.values():
        assert spec["restart"] == "always" and spec["restart-delay"] == "5s"


def test_every_daemon_runs_with_cwd_logs_and_logs_into_it():
    for name, spec in daemons().items():
        assert spec["cwd"] == "logs"
        assert PurePosixPath(spec["logs"]).parent == PurePosixPath("logs"), name


def test_every_command_runs_a_binary_from_bin():
    for spec in daemons().values():
        assert spec["command"][0].startswith("bin/")
        assert spec["backend-specific"]["scm"]["command"][0].startswith("bin/") and spec["backend-specific"]["scm"][
            "command"][0].endswith(".exe")


def test_manifest_uses_a_relative_config_path_matching_its_cwd():
    """goetia absolutises `command[0]`, `cwd` and `logs` only, so `-c` must climb out of `cwd` by itself."""
    spec = daemons()[FRPC]
    for command in (spec["command"], spec["backend-specific"]["scm"]["command"]):
        flag = command.index("-c")
        assert resolve(spec["cwd"], command[flag + 1]) == "host/frpc.toml"


def test_the_service_account_comes_from_the_environment_on_posix_and_is_local_service_on_windows():
    for spec in daemons().values():
        backends = spec["backend-specific"]
        assert backends["systemd"]["user"] == "${RT_SERVICE_USER}"
        assert backends["launchd"]["user"] == "${RT_SERVICE_USER}"
        assert backends["scm"]["user"] == "LocalService"
        assert "user" not in spec  # an unset user is root


def test_frpc_receives_exactly_the_variables_its_config_expands():
    env = daemons()[FRPC]["env"]
    assert set(env) == referenced_in_file(FRPC_TOML)
    assert all(value == "${" + name + "}" for name, value in env.items())


def test_websocat_listens_on_loopback_only_and_forwards_to_the_local_ssh_daemon():
    command = daemons()[WEBSOCAT]["command"]
    assert command[1:] == ["--binary", "ws-l:127.0.0.1:${RT_WS_PORT}", "tcp:127.0.0.1:${RT_SSH_PORT}"]
    assert daemons()[WEBSOCAT]["backend-specific"]["scm"]["command"][1:] == command[1:]


def test_the_manifest_references_only_rt_names():
    names = set(re.findall(r"\$\{([^}:]+)", MANIFEST.read_text(encoding="utf-8")))
    assert names and all(re.fullmatch(r"RT_[A-Z0-9_]+", name) for name in names)


# host/frpc.toml =======================================================================================================


def test_frpc_tokensource_resolves_from_cwd_to_secrets_token():
    path = frpc_config()["auth"]["tokenSource"]["file"]["path"]
    assert frpc_config()["auth"]["tokenSource"]["type"] == "file"
    assert resolve(daemons()[FRPC]["cwd"], path) == "secrets/token"


def test_frpc_config_carries_loginfailexit_false_at_top_level():
    """frp's default (`true`) makes frpc exit for good after one failed login, which is wrong on a laptop at boot."""
    assert frpc_config()["loginFailExit"] is False


def test_frpc_config_does_not_enable_webserver():
    """With no password, frpc's admin server accepts an unauthenticated `PUT /api/config` that rewrites the file."""
    text = FRPC_TOML.read_text(encoding="utf-8")
    assert "webServer" not in frpc_config() and "webServer" not in text


def test_frpc_config_embeds_no_secret_and_no_literal_host():
    text = FRPC_TOML.read_text(encoding="utf-8")
    assert "auth.token " not in text and not re.search(r"^\s*token\s*=", text, re.MULTILINE)
    assert "example.com" not in text


def test_frpc_registers_one_http_proxy_for_the_label_that_websocat_serves():
    config = frpc_config()
    (proxy, ) = config["proxies"]
    assert proxy["type"] == "http" and proxy["name"] == "ssh"
    assert proxy["subdomain"] == SAMPLE["RT_LABEL"] == config["user"]
    assert proxy["localIP"] == "127.0.0.1" and proxy["localPort"] == int(SAMPLE["RT_WS_PORT"])


def test_frpc_connects_to_the_bridge_with_the_configured_protocol():
    config = frpc_config()
    assert config["serverAddr"] == SAMPLE["RT_SERVER_ADDR"] and config["serverPort"] == int(SAMPLE["RT_SERVER_PORT"])
    assert config["transport"]["protocol"] == SAMPLE["RT_PROTOCOL"]
    assert config["auth"]["method"] == "token"


@pytest.mark.parametrize("path", [MANIFEST, FRPC_TOML])
def test_the_files_the_env_gate_scans_include_the_host_files(path):
    from ctl.env import KNOWN_MINIMUM, tracked_config_files

    assert path.relative_to(REPO_ROOT).as_posix() in KNOWN_MINIMUM
    assert path in tracked_config_files(REPO_ROOT)
