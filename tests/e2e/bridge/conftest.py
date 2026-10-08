"""Fixtures for the bridge tests, which build the real image and start real containers.

They bind ports and create containers, so they run only in a throwaway VM or on CI, which say so through
`RT_E2E_SANDBOX=1`. Without it, or without Docker, every test fails: a skip would let a green run mean nothing.
"""

import os
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from bridge_support import REPO_ROOT, SANDBOX_VARIABLE, Entrypoint, Project, make_project, run


@pytest.fixture(autouse=True)
def sandbox():
    if os.environ.get(SANDBOX_VARIABLE) != "1":
        pytest.fail(
            f"these tests start containers and publish ports; run them in a throwaway VM or on CI with "
            f"{SANDBOX_VARIABLE}=1 (see tests/e2e/README.md), never on a development machine",
            pytrace=False,
        )
    result = subprocess.run(["docker", "info"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(f"Docker is not available: {result.stderr.strip()}", pytrace=False)


# Image ================================================================================================================


@pytest.fixture(scope="session")
def image() -> Iterator[str]:
    tag = f"rt-bridge-e2e:{uuid.uuid4().hex[:12]}"
    build = run("docker", "build", "--quiet", "--tag", tag, str(REPO_ROOT / "bridge"))
    assert build.returncode == 0, build.stderr
    yield tag
    removal = run("docker", "rmi", "--force", tag)
    assert removal.returncode == 0, removal.stderr


@pytest.fixture
def entrypoint(image: str, tmp_path: Path) -> Entrypoint:
    return Entrypoint(image, tmp_path)


@pytest.fixture(scope="session")
def tracked_config() -> str:
    return (REPO_ROOT / "bridge" / "frps.toml").read_text(encoding="utf-8")


# Compose project ======================================================================================================


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Project]:
    """A project whose published ports are all dynamic (`0`), so no test depends on a port being free."""
    project = make_project(tmp_path, RT_CONTROL_PORT="0", RT_VHOST_PORT="0", RT_ADMIN_PORT="0")
    yield project
    down = project.compose("down", "--volumes", "--remove-orphans", "--rmi", "local")
    assert down.returncode == 0, down.stderr


@pytest.fixture
def config_project(tmp_path: Path) -> Project:
    """A project for `docker compose config`, which starts nothing."""
    return make_project(tmp_path)
