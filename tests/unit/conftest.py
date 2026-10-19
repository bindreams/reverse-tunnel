from pathlib import Path

import pytest
from binaries_support import SEED_LOCK, VERSIONS, Upstream
from scanner_support import init_repo, write_hashes_file

from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

from ctl import binaries, cli
from tests.offline import refuse_network


@pytest.fixture
def hashes_file(tmp_path: Path) -> Path:
    return write_hashes_file(tmp_path)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)


# Who is running =======================================================================================================


@pytest.fixture(autouse=True)
def not_root(monkeypatch):
    """The CLI refuses root for some roles. These tests are about the commands, not about who runs them, and the
    container recipe runs the whole suite as root."""
    monkeypatch.setattr(cli, "is_elevated", lambda: False)


# No network ===========================================================================================================


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    refuse_network(monkeypatch)


# Pinned binaries ======================================================================================================


@pytest.fixture
def upstream() -> Upstream:
    return Upstream()


@pytest.fixture
def published(upstream: Upstream) -> Upstream:
    """`upstream` carrying the release every tool in the seed lock names."""
    for tool, version in VERSIONS.items():
        upstream.add_tool(tool, version)
    return upstream


@pytest.fixture
def lock_path(tmp_path: Path) -> Path:
    """A seed lock: versions and Renovate comments, no pins yet."""
    path = tmp_path / "binaries.lock.toml"
    path.write_text(SEED_LOCK)
    return path


@pytest.fixture
def generated_lock_path(published: Upstream, lock_path: Path) -> Path:
    binaries.refresh(lock_path, None, transport=published.transport)
    return lock_path


# Sigstore =============================================================================================================

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def verifier() -> Verifier:
    """A verifier rooted in a committed snapshot of Sigstore's trusted root, so no test refreshes it over TUF."""
    return Verifier(trusted_root=TrustedRoot.from_file(str(FIXTURES / "sigstore-trusted-root.json")))
