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
from echo_target import EchoTarget
from front_support import Stack, running_stack
from pinned import fetch_pinned
from pki import Pki
from tunnel_support import Hosts


@pytest.fixture(autouse=True, scope="session")
def sandbox():
    """Session-scoped so it runs before every other session fixture, `image` and `pinned` included."""
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


@pytest.fixture(scope="session")
def service(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """The frps service of `compose.yaml`, rendered by compose."""
    return make_project(tmp_path_factory.mktemp("service")).config()["services"]["frps"]


@pytest.fixture
def entrypoint(image: str, tmp_path: Path, service: dict) -> Entrypoint:
    return Entrypoint(image, tmp_path, service)


@pytest.fixture(scope="session")
def tracked_config() -> str:
    return (REPO_ROOT / "bridge" / "frps.toml").read_text(encoding="utf-8")


# Compose project ======================================================================================================


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Project]:
    """A project whose published ports are all dynamic (`0`), so no test depends on a port being free."""
    project = make_project(tmp_path, RT_CONTROL_PORT="0", RT_VHOST_PORT="0", RT_ADMIN_PORT="0")
    yield project
    project.down()


@pytest.fixture
def config_project(tmp_path: Path) -> Project:
    """A project for `docker compose config`, which starts nothing."""
    return make_project(tmp_path)


# Fronts ===============================================================================================================


@pytest.fixture(scope="session")
def pinned(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """frpc, frps and websocat from `binaries.lock.toml`, fetched and verified by ctl's own downloader."""
    return fetch_pinned(tmp_path_factory.mktemp("pinned"), "frp", "websocat")


@pytest.fixture(scope="session")
def pki() -> Pki:
    return Pki()


@pytest.fixture
def echo() -> Iterator[EchoTarget]:
    """What a host's websocat forwards to, in place of sshd."""
    with EchoTarget() as target:
        yield target


@pytest.fixture
def hosts(tmp_path: Path, pinned: dict[str, Path], echo: EchoTarget) -> Iterator[Hosts]:
    """Starts hosts whose websocat forwards to `echo`; each is stopped when the test ends, whatever happened."""
    hosts = Hosts(tmp_path, pinned, echo.port)
    yield hosts
    hosts.close()


@pytest.fixture
def bare_stack(tmp_path: Path, pki: Pki) -> Iterator[Stack]:
    with running_stack(tmp_path, pki, "bare") as stack:
        yield stack


@pytest.fixture
def nginx_stack(tmp_path: Path, pki: Pki) -> Iterator[Stack]:
    with running_stack(tmp_path, pki, "nginx") as stack:
        yield stack


@pytest.fixture
def caddy_stack(tmp_path: Path, pki: Pki) -> Iterator[Stack]:
    with running_stack(tmp_path, pki, "caddy") as stack:
        yield stack


@pytest.fixture
def traefik_stack(tmp_path: Path, pki: Pki) -> Iterator[Stack]:
    with running_stack(tmp_path, pki, "traefik") as stack:
        yield stack


@pytest.fixture
def host_rewriting_nginx_stack(tmp_path: Path, pki: Pki) -> Iterator[Stack]:
    """nginx configured as a careless copy of the example would be: the vhost's `Host` line is left out."""
    with running_stack(tmp_path, pki, "nginx", rewrite_host=True) as stack:
        yield stack
