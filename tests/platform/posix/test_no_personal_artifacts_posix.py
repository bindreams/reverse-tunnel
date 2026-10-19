"""A clean absolute message path is displayed verbatim. The unit tests name message files relative to the repository,
because a Windows temp directory is under a home directory and a home path is itself redacted; `tmp_path` here is not."""

import hashlib
from pathlib import Path

import pytest

from tests.unit.scanner_support import TERM, git, run_script


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


def test_message_mode_names_the_commit_message_by_its_absolute_path(repo, hashes_file, tmp_path):
    message = tmp_path / "msg"
    message.write_text(f"feat: add {TERM}\n")
    result = run_script(repo, hashes_file, "--message", str(message))
    assert result.returncode == 1
    assert f"{message}:1: banned-term" in result.stderr
    message.write_text("feat: add thing\n")
    assert run_script(repo, hashes_file, "--message", str(message)).returncode == 0


def test_a_missing_clean_message_file_is_named_by_its_absolute_path_in_the_error(repo, hashes_file, tmp_path):
    absent = tmp_path / "absent.msg"
    result = run_script(repo, hashes_file, "--message", str(absent))
    assert result.returncode == 2 and str(absent) in result.stderr


def test_message_mode_names_a_hash_line_finding_by_its_absolute_path(repo, hashes_file, tmp_path):
    message = tmp_path / "msg"
    message.write_text(f"feat: x\n\n# {TERM}\n")
    result = run_script(repo, hashes_file, "--message", str(message))
    assert result.returncode == 1
    assert f"{message}:3: banned-term" in result.stderr
