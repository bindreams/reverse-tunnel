import argparse
import subprocess
import sys
from pathlib import Path

import pytest

from ctl.cli import build_parser, main

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


@pytest.mark.parametrize("name", sorted(SPEC_SUBCOMMANDS))
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
