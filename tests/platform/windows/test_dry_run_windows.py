"""What the real goetia would install for the tracked manifest under the `scm` block, checked property by property.

Needs a goetia.exe (see `dry_run_support`).
"""

import ntpath
import re

import pytest
import yaml

from tests.unit.dry_run_support import goetia_binary, manifest_directory, render

pytestmark = pytest.mark.goetia
IDS = ("reverse-tunnel-frpc", "reverse-tunnel-websocat")
LOCAL_SERVICE = "nt authority\\localservice"


@pytest.fixture(scope="module")
def goetia(tmp_path_factory):
    return goetia_binary(tmp_path_factory)


@pytest.fixture
def directory(tmp_path):
    return manifest_directory(tmp_path.resolve() / "deployment")


def specs(output: str) -> dict[str, dict]:
    parts = re.split(r"^# (\S+)\r?\n", output, flags=re.MULTILINE)
    return {name: yaml.safe_load(body) for name, body in zip(parts[1::2], parts[2::2], strict=True)}


def test_there_are_two_independent_entries_resolved_for_the_scm_backend(goetia, directory):
    rendered = specs(render(goetia, directory, "show"))
    assert tuple(rendered) == IDS
    for name, spec in rendered.items():
        binary = "frpc" if name.endswith("frpc") else "websocat"
        assert spec["command"][0] == str(directory / "bin" / f"{binary}.exe"), name


def test_every_path_is_absolute_and_the_restart_policy_is_present(goetia, directory):
    for spec in specs(render(goetia, directory, "show")).values():
        assert ntpath.isabs(spec["command"][0]) and ntpath.isabs(spec["cwd"]) and ntpath.isabs(spec["logs"])
        assert ntpath.normcase(spec["cwd"]) == ntpath.normcase(str(directory / "logs"))
        assert spec["restart"] == "always" and spec["restart-delay"] == "5s"


def test_the_service_account_is_local_service(goetia, directory):
    for spec in specs(render(goetia, directory, "show")).values():
        assert str(spec["user"]).lower().replace("\\\\", "\\") in (LOCAL_SERVICE, "localservice")
    artifact = render(goetia, directory, "install", "--dry-run")
    assert LOCAL_SERVICE in artifact.lower().replace("\\\\", "\\")
