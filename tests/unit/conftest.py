import hashlib
from pathlib import Path

import pytest
from binaries_support import SEED_LOCK, VERSIONS, Upstream
from scanner_support import TERM, git

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


# Pinned binaries ======================================================================================================


@pytest.fixture
def upstream():
    with Upstream() as server:
        yield server


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
    binaries.refresh(lock_path, None, api=published.base_url)
    return lock_path
