import hashlib
import socket
from pathlib import Path

import pytest
from binaries_support import SEED_LOCK, VERSIONS, Upstream
from scanner_support import TERM, git

from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

from ctl import binaries


@pytest.fixture
def hashes_file(tmp_path: Path) -> Path:
    path = tmp_path / "hashes.txt"
    path.write_text(f"# banned\n{len(TERM)} {hashlib.sha256(TERM.encode()).hexdigest()}\n")
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


# No network ===========================================================================================================


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Unit tests are offline: any socket connection fails the test, so a live call cannot slip in unnoticed."""

    def refuse(self, address, *args, **kwargs):
        pytest.fail(f"unit tests must not touch the network (connect to {address!r})", pytrace=False)

    def refuse_lookup(host, *args, **kwargs):
        pytest.fail(f"unit tests must not touch the network (name lookup of {host!r})", pytrace=False)

    def refuse_send(self, data, *args):
        pytest.fail(f"unit tests must not touch the network (sendto {args[-1]!r})", pytrace=False)

    for method in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, method, refuse)
    monkeypatch.setattr(socket.socket, "sendto", refuse_send)
    for function in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, function, refuse_lookup)


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
