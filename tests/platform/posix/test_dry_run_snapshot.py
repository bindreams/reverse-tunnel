"""What the real goetia would install for the tracked manifest, checked property by property and against a snapshot.

The properties are the source of truth; the snapshot only catches a later change. It is not trusted until the
properties pass, so a bug cannot be committed into it. Needs a goetia executable (see `dry_run_support`).
"""

import os
import plistlib
import re
import sys
from pathlib import Path

import pytest

from tests.unit.deployment_support import REPO_ROOT
from tests.unit.dry_run_support import SERVICE_USER, goetia_binary, manifest_directory, normalize, render

pytestmark = pytest.mark.goetia

FAMILY = "launchd" if sys.platform == "darwin" else "systemd"
SNAPSHOT = REPO_ROOT / "tests" / "snapshots" / f"dry-run.{FAMILY}.txt"
UPDATE = "RT_UPDATE_SNAPSHOT"
IDS = ("reverse-tunnel-frpc", "reverse-tunnel-websocat")


@pytest.fixture(scope="module")
def goetia(tmp_path_factory) -> Path:
    return goetia_binary(tmp_path_factory)


@pytest.fixture
def directory(tmp_path) -> Path:
    return manifest_directory(tmp_path.resolve() / "deployment")


def entries(output: str) -> dict[str, str]:
    """goetia's output, split into the artifact of each daemon."""
    parts = re.split(r"^# (\S+)\n", output, flags=re.MULTILINE)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_there_are_two_independent_entries(goetia, directory):
    assert tuple(entries(render(goetia, directory, "install", "--dry-run"))) == IDS


def systemd_properties(artifact: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in artifact.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            found.setdefault(key, []).append(value)
    return found


def launchd_properties(artifact: str) -> dict:
    return plistlib.loads(artifact.encode())


def test_every_path_is_absolute_the_user_is_the_service_account_and_the_restart_policy_is_present(goetia, directory):
    root = directory
    for name, artifact in entries(render(goetia, directory, "install", "--dry-run")).items():
        binary = "frpc" if name.endswith("frpc") else "websocat"
        if FAMILY == "systemd":
            found = systemd_properties(artifact)
            assert found["User"] == [SERVICE_USER] and found["Restart"] == ["always"] and found["RestartSec"] == ["5"]
            assert found["ExecStart"][0].split()[0] == str(root / "bin" / binary)
            assert found["WorkingDirectory"] == [str(root / "logs")]
            assert found["StandardOutput"] == [f"append:{root / 'logs' / (binary + '.log')}"]
            assert found["StandardError"] == found["StandardOutput"]
        else:
            found = launchd_properties(artifact)
            assert found["UserName"] == SERVICE_USER and found["KeepAlive"] is True and found["ThrottleInterval"] == 5
            assert found["ProgramArguments"][0] == str(root / "bin" / binary)
            assert found["WorkingDirectory"] == str(root / "logs")
            assert found["StandardOutPath"] == str(root / "logs" / f"{binary}.log")


def test_frpc_receives_its_configuration_through_the_environment_and_websocat_receives_none(goetia, directory):
    rendered = entries(render(goetia, directory, "show"))
    assert "RT_LABEL: alpha" in rendered[IDS[0]] and "env: {}" in rendered[IDS[1]]


def test_dry_run_artifact_matches_snapshot(goetia, directory):
    actual = normalize(render(goetia, directory, "install", "--dry-run"), directory)
    if os.environ.get(UPDATE):
        SNAPSHOT.write_text(actual, encoding="utf-8", newline="\n")
    assert actual == SNAPSHOT.read_text(encoding="utf-8"), f"review the change, then rerun with {UPDATE}=1 to accept it"
