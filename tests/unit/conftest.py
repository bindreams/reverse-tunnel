import hashlib
from pathlib import Path

import pytest
from scanner_support import TERM, git


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
