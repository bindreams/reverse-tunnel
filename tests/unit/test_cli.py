import argparse
import subprocess
import sys
from pathlib import Path

import pytest

from ctl import binaries, cli
from ctl.cli import build_parser, main
from ctl.config import ConfigError
from ctl.errors import BinariesError
from ctl.env import EnvError

SPEC_SUBCOMMANDS = {"install", "uninstall", "doctor", "client-config", "pin"}
REPO_ROOT = Path(__file__).resolve().parents[2]
UNIMPLEMENTED_SUBCOMMANDS = SPEC_SUBCOMMANDS - {"pin"}


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
