"""A clean absolute message path is displayed verbatim (the unit tests use relative paths; see test_message_mode_flags_the_commit_message)."""

import pytest

from tests.unit.scanner_support import TERM, kinds, run_script


@pytest.fixture
def message_dir(tmp_path, hashes_file):
    """A directory whose absolute path the scanner does not redact as a home path, or these tests would fail for it."""
    directory = tmp_path / "messages"
    directory.mkdir()
    assert "home-path" not in kinds(str(directory), hashes_file), (
        f"{directory} is under a home directory, which the scanner redacts, so a clean absolute path cannot be shown "
        "verbatim here; run with a --basetemp (or TMPDIR) outside /home and /Users"
    )
    return directory


def test_message_mode_names_the_commit_message_by_its_absolute_path(repo, hashes_file, message_dir):
    message = message_dir / "msg"
    message.write_text(f"feat: add {TERM}\n")
    result = run_script(repo, hashes_file, "--message", str(message))
    assert result.returncode == 1
    assert f"{message}:1: banned-term" in result.stderr
    message.write_text("feat: add thing\n")
    assert run_script(repo, hashes_file, "--message", str(message)).returncode == 0


def test_a_missing_clean_message_file_is_named_by_its_absolute_path_in_the_error(repo, hashes_file, message_dir):
    absent = message_dir / "absent.msg"
    result = run_script(repo, hashes_file, "--message", str(absent))
    assert result.returncode == 2 and str(absent) in result.stderr


def test_message_mode_names_a_hash_line_finding_by_its_absolute_path(repo, hashes_file, message_dir):
    message = message_dir / "msg"
    message.write_text(f"feat: x\n\n# {TERM}\n")
    result = run_script(repo, hashes_file, "--message", str(message))
    assert result.returncode == 1
    assert f"{message}:3: banned-term" in result.stderr
