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


def declared_subcommands() -> set[str]:
    (action, ) = [a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)]
    return set(action.choices)


def test_help_exits_zero():
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0


def test_every_spec_subcommand_is_declared():
    assert declared_subcommands() == SPEC_SUBCOMMANDS


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as raised:
        main([])
    assert raised.value.code != 0


def test_module_entrypoint_propagates_the_exit_code():
    result = subprocess.run(
        [sys.executable, "-m", "ctl", "pin", "frp"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "--update" in result.stderr


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
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    seen = []
    monkeypatch.setattr(
        cli,
        "install",
        lambda config, *, allow_self_disconnect=False, apply_staged=False, inherit_lock=None, started_fd=None: seen.
        append((allow_self_disconnect, apply_staged, inherit_lock)) or 0
    )
    assert main(["install", "--allow-self-disconnect"], root=tmp_path) == 0
    assert main(["install"], root=tmp_path) == 0
    assert seen == [(True, False, None), (False, False, None)]


def test_the_detached_child_is_started_with_a_flag_that_help_does_not_advertise(tmp_path, monkeypatch, capsys):
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    seen = []
    monkeypatch.setattr(
        cli,
        "install",
        lambda config, *, allow_self_disconnect=False, apply_staged=False, inherit_lock=None, started_fd=None: seen.
        append((allow_self_disconnect, apply_staged, inherit_lock)) or 0
    )
    assert main(["install", "--allow-self-disconnect", "--apply-staged", "--inherit-lock", "7"], root=tmp_path) == 0
    assert seen == [(True, True, 7)]
    with pytest.raises(SystemExit):
        main(["install", "--help"])
    out = capsys.readouterr().out
    assert "apply-staged" not in out and "inherit-lock" not in out


def test_apply_staged_requires_allow_self_disconnect(tmp_path, monkeypatch, capsys):
    """It exists only for the detached child, which has already been allowed."""
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    with pytest.raises(SystemExit) as raised:
        main(["install", "--apply-staged"], root=tmp_path)
    assert raised.value.code == 2
    assert "--allow-self-disconnect" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["install", "uninstall"])
def test_a_host_command_without_elevation_says_how_to_elevate(tmp_path, monkeypatch, capsys, command):
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "install", lambda *a, **k: pytest.fail("goetia needs root"))
    monkeypatch.setattr(cli, "uninstall", lambda *a, **k: pytest.fail("goetia needs root"))
    assert main([command], root=tmp_path) == 1
    err = capsys.readouterr().err
    assert "ROLE=host" in err and "sudo .venv/bin/python -m ctl" in err and "Administrator" in err


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


def test_allow_self_disconnect_reaches_a_host_uninstall(tmp_path, monkeypatch):
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    seen = []
    monkeypatch.setattr(
        cli,
        "uninstall",
        lambda config, *, force=False, allow_self_disconnect=False, detached=False, inherit_lock=None, started_fd=None:
        seen.append((allow_self_disconnect, detached, inherit_lock)) or 0
    )
    assert main(["uninstall", "--allow-self-disconnect"], root=tmp_path) == 0
    assert main(["uninstall", "--allow-self-disconnect", "--detached", "--inherit-lock", "9"], root=tmp_path) == 0
    assert seen == [(True, False, None), (True, True, 9)]


@pytest.mark.parametrize("role", [Role.CLIENT, Role.BRIDGE])
def test_allow_self_disconnect_on_uninstall_is_refused_where_there_are_no_daemons(tmp_path, role, capsys):
    write_env(tmp_path, role)
    with pytest.raises(SystemExit) as raised:
        main(["uninstall", "--allow-self-disconnect"], root=tmp_path)
    assert raised.value.code == 2
    assert "ROLE=host" in capsys.readouterr().err


def test_detached_requires_allow_self_disconnect(tmp_path, monkeypatch):
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    with pytest.raises(SystemExit) as raised:
        main(["uninstall", "--detached"], root=tmp_path)
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


# The detached child ===================================================================================================

CHILD = ["install", "--allow-self-disconnect", "--apply-staged", "--inherit-lock", "7", "--started-fd", "8"]


@pytest.fixture
def host_root(tmp_path, monkeypatch):
    write_env(tmp_path, Role.HOST)
    monkeypatch.setattr(cli, "is_elevated", lambda: True)
    return tmp_path


def last_line(capsys) -> str:
    return capsys.readouterr().out.splitlines()[-1]


def test_the_child_ends_its_log_with_ok(host_root, monkeypatch, capsys):
    monkeypatch.setattr(cli, "install", lambda config, **kwargs: 0)
    assert main(CHILD, root=host_root) == 0
    assert last_line(capsys) == "apply finished: ok"


@pytest.mark.parametrize("error", [InstallError("goetia refused"), PermsError("cannot chown"), OSError(5, "I/O error")])
def test_the_child_ends_its_log_with_the_failure(host_root, monkeypatch, capsys, error):

    def fail(config, **kwargs):
        raise error

    monkeypatch.setattr(cli, "install", fail)
    assert main(CHILD, root=host_root) == 1
    line = last_line(capsys)
    assert line.startswith("apply finished: failed: ") and str(error) in line


def test_the_child_reports_a_broken_configuration(host_root, capsys):
    (host_root / ".env").write_text("ROLE=host\n")
    assert main(CHILD, root=host_root) == 1
    assert last_line(capsys).startswith("apply finished: failed: ")


def test_the_child_reports_a_missing_env_file(tmp_path, capsys):
    assert main(CHILD, root=tmp_path) == 1
    line = last_line(capsys)
    assert line.startswith("apply finished: failed: ") and ".env" in line


def test_the_child_reports_a_lock_it_cannot_adopt(host_root, capsys):
    assert main(["install", "--allow-self-disconnect", "--apply-staged", "--inherit-lock", "987654"],
                root=host_root) == 1
    line = last_line(capsys)
    assert line.startswith("apply finished: failed: ") and "lock" in line


def test_the_child_reports_a_usage_error(host_root, capsys):
    with pytest.raises(SystemExit) as raised:
        main(["install", "--apply-staged", "--inherit-lock", "7"], root=host_root)
    assert raised.value.code == 2
    assert last_line(capsys).startswith("apply finished: failed: ")


def test_an_ordinary_run_prints_no_outcome_line(host_root, monkeypatch, capsys):
    monkeypatch.setattr(cli, "install", lambda config, **kwargs: 0)
    assert main(["install"], root=host_root) == 0
    assert "apply finished" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv", [
        ["install", "--inherit-lock", "7"],
        ["install", "--allow-self-disconnect", "--inherit-lock", "7"],
        ["install", "--allow-self-disconnect", "--apply-staged", "--started-fd", "8"],
        ["uninstall", "--allow-self-disconnect", "--inherit-lock", "7"],
        ["uninstall", "--allow-self-disconnect", "--detached", "--started-fd", "8"],
    ]
)
def test_the_internal_descriptors_are_refused_outside_the_detached_child(host_root, monkeypatch, capsys, argv):
    monkeypatch.setattr(cli, "install", lambda *a, **k: pytest.fail("must not run"))
    monkeypatch.setattr(cli, "uninstall", lambda *a, **k: pytest.fail("must not run"))
    with pytest.raises(SystemExit) as raised:
        main(argv, root=host_root)
    assert raised.value.code == 2
    err = capsys.readouterr().err
    assert "detached" in err or "inherit" in err


@pytest.mark.parametrize("error", [RuntimeError("unexpected"), KeyboardInterrupt()])
def test_the_child_ends_its_log_even_when_it_dies_of_something_unforeseen(host_root, monkeypatch, capsys, error):

    def explode(config, **kwargs):
        raise error

    monkeypatch.setattr(cli, "install", explode)
    with pytest.raises(type(error)):
        main(CHILD, root=host_root)
    assert last_line(capsys).startswith("apply finished: failed: ")


def test_the_child_is_recognised_whichever_way_the_flag_is_written(host_root, capsys):
    assert main(["install", "--allow-self-disconnect", "--apply-staged", "--inherit-lock=987654"], root=host_root) == 1
    assert last_line(capsys).startswith("apply finished: failed: ")


def test_an_abbreviation_of_an_internal_flag_is_refused_rather_than_guessed(host_root, capsys):
    with pytest.raises(SystemExit) as raised:
        main(["install", "--allow-self-disconnect", "--apply-staged", "--inherit-l", "7"], root=host_root)
    assert raised.value.code == 2


def test_the_usage_message_for_a_started_fd_without_a_lock_reads_plainly(host_root, capsys):
    with pytest.raises(SystemExit):
        main(["install", "--allow-self-disconnect", "--apply-staged", "--started-fd", "8"], root=host_root)
    assert "only with --inherit-lock" in capsys.readouterr().err
