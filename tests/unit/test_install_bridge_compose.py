"""How `COMPOSE_FILE` in a bridge's `.env` meets `ctl install`, `ctl uninstall` and `ctl doctor`."""

from pathlib import Path

import pytest
from tests.unit.deployment_support import tree, write_env
from tests.unit.doctor_support import build_bridge

from ctl import doctor
from ctl.config import Role
from ctl.errors import InstallError
from ctl.install import Services, install, uninstall

# `;` is spelled out in `.env`, so these tests read the same on every OS.
SEPARATOR = {"COMPOSE_PATH_SEPARATOR": ";"}
MISSING = "compose.override.yaml"


def bridge_with_missing_override(root: Path):
    (root / "compose.yaml").write_text("services: {}\n", newline="\n")
    return write_env(root, Role.BRIDGE, COMPOSE_FILE=f"compose.yaml;{MISSING}", **SEPARATOR)


def test_bridge_install_refuses_a_bad_compose_file_before_mutating(tmp_path):
    config = bridge_with_missing_override(tmp_path)
    before = tree(tmp_path)
    with pytest.raises(InstallError, match="COMPOSE_FILE") as caught:
        install(config, services=Services(run=lambda args, *, cwd: pytest.fail("docker must not run")))
    assert MISSING in str(caught.value)
    assert tree(tmp_path) == before
    assert not (tmp_path / "secrets").exists()


def test_bridge_install_lists_every_compose_file_problem(tmp_path):
    (tmp_path / "compose.yaml").write_text("services: {}\n", newline="\n")
    config = write_env(tmp_path, Role.BRIDGE, COMPOSE_FILE="compose.yaml;/abs.yaml;gone.yaml", **SEPARATOR)
    with pytest.raises(InstallError) as caught:
        install(config)
    assert "/abs.yaml" in str(caught.value) and "gone.yaml" in str(caught.value)


def test_doctor_runs_with_a_bad_compose_file(tmp_path):
    world = build_bridge(tmp_path, COMPOSE_FILE=f"compose.yaml;{MISSING}", **SEPARATOR)
    checks = doctor.run(world.config, world.probes())
    assert {check.name for check in checks} >= {"docker_reachable", "container_healthy"}


def test_uninstall_names_the_bad_compose_file_entry_when_down_fails(tmp_path, capsys):
    config = bridge_with_missing_override(tmp_path)
    assert uninstall(config, services=Services(run=lambda args, *, cwd: 1)) == 1
    err = capsys.readouterr().err
    assert "docker compose down failed (exit 1)" in err
    assert "COMPOSE_FILE" in err and MISSING in err and "--force" in err
    # `down` can fail for reasons of its own, so the hint reports the problems without claiming they caused it.
    assert "cannot read" not in err


def test_uninstall_without_a_compose_file_problem_does_not_mention_it(tmp_path, capsys):
    config = write_env(tmp_path, Role.BRIDGE)
    assert uninstall(config, services=Services(run=lambda args, *, cwd: 1)) == 1
    assert "COMPOSE_FILE" not in capsys.readouterr().err


def test_install_remedy_names_the_env_file_when_that_was_judged(tmp_path):
    config = bridge_with_missing_override(tmp_path)
    with pytest.raises(InstallError) as caught:
        install(config)
    assert "fix COMPOSE_FILE in .env" in str(caught.value)


def test_install_remedy_names_the_exported_variables_when_that_was_judged(tmp_path, monkeypatch):
    config = write_env(tmp_path, Role.BRIDGE)
    (tmp_path / "compose.yaml").write_text("services: {}" + chr(10), newline=chr(10))
    monkeypatch.setenv("COMPOSE_FILE", MISSING)
    with pytest.raises(InstallError) as caught:
        install(config)
    assert "fix or unset the exported COMPOSE_FILE / COMPOSE_ENV_FILES" in str(caught.value)
    assert ".env" not in str(caught.value).split("Nothing was changed;")[1]


def test_uninstall_hint_follows_the_judged_source(tmp_path, capsys, monkeypatch):
    config = write_env(tmp_path, Role.BRIDGE)
    (tmp_path / "compose.yaml").write_text("services: {}" + chr(10), newline=chr(10))
    monkeypatch.setenv("COMPOSE_FILE", MISSING)
    assert uninstall(config, services=Services(run=lambda args, *, cwd: 1)) == 1
    err = capsys.readouterr().err
    assert "fix or unset the exported COMPOSE_FILE / COMPOSE_ENV_FILES" in err and "--force" in err


def test_uninstall_hint_names_the_env_file_when_that_was_judged(tmp_path, capsys):
    config = bridge_with_missing_override(tmp_path)
    assert uninstall(config, services=Services(run=lambda args, *, cwd: 1)) == 1
    assert "fix COMPOSE_FILE in .env" in capsys.readouterr().err
