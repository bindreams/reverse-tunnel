import argparse
import subprocess
import sys
from pathlib import Path

import pytest

from ctl import binaries, cli
from ctl.cli import build_parser, main
from ctl.config import ConfigError, Role
from ctl.errors import BinariesError, InstallError
from ctl.perms import PermsError
from ctl.env import EnvError
from deployment_support import write_env

SPEC_SUBCOMMANDS = {"install", "uninstall", "doctor", "client-config", "pin"}
REPO_ROOT = Path(__file__).resolve().parents[2]
UNIMPLEMENTED_SUBCOMMANDS = {"doctor"}


def declared_subcommands() -> set[str]:
    (action, ) = [a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)]
    return set(action.choices)


def test_help_exits_zero():
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0


def test_every_spec_subcommand_is_declared():
    assert declared_subcommands() == SPEC_SUBCOMMANDS


@pytest.mark.parametrize("name", sorted(UNIMPLEMENTED_SUBCOMMANDS))
def test_unimplemented_subcommand_exits_nonzero_naming_itself(name, capsys):
    assert main([name]) != 0
    assert name in capsys.readouterr().err


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as raised:
        main([])
    assert raised.value.code != 0


def test_module_entrypoint_propagates_the_exit_code():
    result = subprocess.run(
        [sys.executable, "-m", "ctl", "doctor"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "doctor" in result.stderr


@pytest.mark.parametrize(
    "error",
    [EnvError("bad.env:3: nope"),
     ConfigError("RT_DOMAIN is empty"),
     BinariesError("frp 0.71.0: no digest")],
)
def test_a_configuration_error_is_a_message_and_exit_1_not_a_traceback(error, monkeypatch, capsys):

    def fail(args):
        raise error

    monkeypatch.setattr(cli, "run_command", fail)
    assert main(["doctor"]) == 1
    err = capsys.readouterr().err
    assert str(error) in err
    assert "Traceback" not in err


# pin ==================================================================================================================


@pytest.fixture
def refreshed(monkeypatch):
    calls = []
    monkeypatch.setattr(binaries, "refresh", lambda *args, **kwargs: calls.append((args, kwargs)))
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    return calls


def test_pin_shows_every_pinned_tool_and_platform(capsys):
    assert main(["pin"]) == 0
    out = capsys.readouterr().out
    lock = binaries.load_lock(binaries.LOCK_PATH)
    for tool, by_platform in lock.items():
        for platform in binaries.PLATFORMS:
            line = next(line for line in out.splitlines() if line.startswith(f"{tool} ") and f" {platform} " in line)
            assert by_platform[platform][0].version in line


def test_pin_update_refreshes_the_whole_lock_when_no_tool_is_named(refreshed, capsys):
    assert main(["pin", "--update"]) == 0
    assert refreshed == [((binaries.LOCK_PATH, None), {"token": None})]


def test_pin_update_refreshes_only_the_named_tools(refreshed):
    assert main(["pin", "--update", "frp", "goetia"]) == 0
    assert refreshed == [((binaries.LOCK_PATH, ["frp", "goetia"]), {"token": None})]


@pytest.mark.parametrize("variable", ["GITHUB_TOKEN", "GH_TOKEN"])
def test_pin_update_authenticates_with_a_token_from_the_environment_and_never_prints_it(
    refreshed, monkeypatch, capsys, variable
):
    monkeypatch.setenv(variable, "s3cret-token")
    assert main(["pin", "--update"]) == 0
    assert refreshed[0][1] == {"token": "s3cret-token"}
    captured = capsys.readouterr()
    assert "s3cret-token" not in captured.out + captured.err


def test_pin_update_treats_an_empty_token_as_none(refreshed, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "")
    assert main(["pin", "--update"]) == 0
    assert refreshed[0][1] == {"token": None}


def test_naming_tools_without_update_is_a_usage_error(refreshed, capsys):
    with pytest.raises(SystemExit) as raised:
        main(["pin", "frp"])
    assert raised.value.code == 2
    assert "--update" in capsys.readouterr().err
    assert refreshed == []


def test_pin_update_failure_is_a_message_and_exit_1(monkeypatch, capsys):

    def fail(*args, **kwargs):
        raise BinariesError("frp 0.71.0: asset frp.tar.gz has no digest")

    monkeypatch.setattr(binaries, "refresh", fail)
    assert main(["pin", "--update"]) == 1
    err = capsys.readouterr().err
    assert "asset frp.tar.gz has no digest" in err
    assert "Traceback" not in err


# install, uninstall, client-config ====================================================================================

CLIENT_ENV = "ROLE=client\nRT_DOMAIN=tunnel.example.com\nRT_SCHEME=ws\nRT_PUBLIC_PORT=8080\n"


@pytest.fixture
def deployment(tmp_path) -> Path:
    (tmp_path / ".env").write_bytes(CLIENT_ENV.encode())
    return tmp_path


def test_client_config_prints_the_block_for_the_label_it_is_given(deployment, capsys):
    assert main(["client-config", "alpha"], root=deployment) == 0
    out = capsys.readouterr().out
    assert "HostName alpha.tunnel.example.com" in out
    assert "ws://%h:8080/" in out


def test_client_config_without_a_label_is_a_usage_error(deployment, capsys):
    with pytest.raises(SystemExit) as raised:
        main(["client-config"], root=deployment)
    assert raised.value.code == 2


def test_client_config_with_a_bad_label_is_a_message_and_exit_1(deployment, capsys):
    assert main(["client-config", "Not A Label"], root=deployment) == 1
    assert "client-config" in capsys.readouterr().err


def test_install_accepts_allow_self_disconnect_for_a_host(tmp_path, monkeypatch):
    write_env(tmp_path, Role.HOST)
    seen = []
    monkeypatch.setattr(
        cli, "install", lambda config, *, allow_self_disconnect=False: seen.append(allow_self_disconnect) or 0
    )
    assert main(["install", "--allow-self-disconnect"], root=tmp_path) == 0
    assert main(["install"], root=tmp_path) == 0
    assert seen == [True, False]


@pytest.mark.parametrize("role", [Role.CLIENT, Role.BRIDGE])
def test_allow_self_disconnect_is_refused_where_there_is_no_websocat_to_disconnect(tmp_path, role, capsys):
    write_env(tmp_path, role)
    with pytest.raises(SystemExit) as raised:
        main(["install", "--allow-self-disconnect"], root=tmp_path)
    assert raised.value.code == 2
    assert "ROLE=host" in capsys.readouterr().err


@pytest.mark.parametrize("role", [Role.CLIENT, Role.HOST])
def test_force_is_refused_where_there_is_no_container_to_skip_checking(tmp_path, role, capsys):
    write_env(tmp_path, role)
    with pytest.raises(SystemExit) as raised:
        main(["uninstall", "--force"], root=tmp_path)
    assert raised.value.code == 2
    assert "ROLE=bridge" in capsys.readouterr().err


def test_force_reaches_a_bridge_uninstall(tmp_path, monkeypatch):
    write_env(tmp_path, Role.BRIDGE)
    seen = []
    monkeypatch.setattr(cli, "uninstall", lambda config, *, force=False: seen.append(force) or 0)
    assert main(["uninstall", "--force"], root=tmp_path) == 0
    assert main(["uninstall"], root=tmp_path) == 0
    assert seen == [True, False]


def test_force_is_documented_in_the_help(capsys):
    with pytest.raises(SystemExit):
        main(["uninstall", "--help"])
    assert "--force" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["install", "uninstall"])
@pytest.mark.parametrize("role", [Role.BRIDGE, Role.CLIENT])
def test_install_and_uninstall_refuse_to_run_as_root_for_these_roles(tmp_path, monkeypatch, capsys, command, role):
    """Root would leave `secrets/` or `bin/` that the operator can no longer replace, which is how the hazard starts."""
    write_env(tmp_path, role)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    monkeypatch.setattr(cli, "install", lambda *a, **k: pytest.fail("must not install as root"))
    monkeypatch.setattr(cli, "uninstall", lambda *a, **k: pytest.fail("must not uninstall as root"))
    assert main([command], root=tmp_path) == 1
    err = capsys.readouterr().err
    assert "root" in err and "sudo" in err


@pytest.mark.parametrize(
    "error", [PermissionError(13, "Permission denied", "/x/secrets/token"),
              OSError(5, "I/O error")]
)
def test_an_operating_system_error_is_a_message_and_exit_1_not_a_traceback(error, deployment, monkeypatch, capsys):

    def fail(config, **kwargs):
        raise error

    monkeypatch.setattr(cli, "uninstall", fail)
    assert main(["uninstall"], root=deployment) == 1
    err = capsys.readouterr().err
    assert "uninstall" in err and "Traceback" not in err


def test_allow_self_disconnect_belongs_to_install_only(deployment):
    with pytest.raises(SystemExit) as raised:
        main(["uninstall", "--allow-self-disconnect"], root=deployment)
    assert raised.value.code == 2


def test_install_without_an_env_file_names_it(tmp_path, capsys):
    assert main(["install"], root=tmp_path) == 1
    assert ".env" in capsys.readouterr().err


@pytest.mark.parametrize("error", [InstallError("secrets/token is a directory"), PermsError("secrets: is a symlink")])
def test_an_install_failure_is_a_message_and_exit_1_not_a_traceback(error, deployment, monkeypatch, capsys):

    def fail(config, **kwargs):
        raise error

    monkeypatch.setattr(cli, "uninstall", fail)
    assert main(["uninstall"], root=deployment) == 1
    err = capsys.readouterr().err
    assert str(error) in err and "Traceback" not in err


def test_a_host_is_not_refused_when_elevated(tmp_path, monkeypatch):
    """The host role is installed with elevation; goetia needs root."""
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    seen = []
    monkeypatch.setattr(cli, "install", lambda config, **kwargs: seen.append(config.role) or 0)
    assert main(["install"], root=tmp_path) == 0
    assert seen == [Role.HOST]


def test_the_refusal_names_root_and_an_elevated_administrator(tmp_path, monkeypatch, capsys):
    write_env(tmp_path, Role.CLIENT)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    assert main(["install"], root=tmp_path) == 1
    assert "Administrator" in capsys.readouterr().err
