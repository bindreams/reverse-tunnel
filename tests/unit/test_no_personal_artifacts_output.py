"""Findings go to public CI logs: banned text, in content or in a path, must never be printed."""

import os

import pytest
from scanner_support import TERM, git, run_script

NAMED = f"{TERM}-box.txt"
REDACTED = "<path redacted: banned-term>"


def everything(result):
    return result.stdout + result.stderr


def test_a_banned_path_is_redacted_for_a_file_named_on_the_command_line(repo, hashes_file):
    (repo / NAMED).write_text(f"host = {TERM}\n")
    result = run_script(repo, hashes_file, NAMED)
    assert result.returncode == 1
    assert TERM not in everything(result)
    assert f"{REDACTED} (argument 1):1: banned-term" in result.stderr
    assert f"{REDACTED} (argument 1): banned-term" in result.stderr


def test_redacted_arguments_stay_distinguishable(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    (repo / NAMED).write_text("clean\n")
    result = run_script(repo, hashes_file, "a.txt", NAMED)
    assert "(argument 2)" in result.stderr and "(argument 1)" not in result.stderr


@pytest.mark.parametrize("mode", ["--staged", "--tree"])
def test_a_banned_path_is_redacted_in_index_modes_and_names_the_blob(repo, hashes_file, mode):
    (repo / NAMED).write_text(f"host = {TERM}\n")
    git(repo, "add", NAMED)
    blob = git(repo, "rev-parse", f":{NAMED}").strip()
    result = run_script(repo, hashes_file, mode)
    assert result.returncode == 1
    assert TERM not in everything(result)
    assert f"{REDACTED} (blob {blob[:12]})" in result.stderr


def test_a_path_without_a_finding_is_printed_verbatim(repo, hashes_file):
    (repo / "plain.txt").write_text(f"host = {TERM}\n")
    git(repo, "add", "plain.txt")
    assert "plain.txt:1: banned-term" in run_script(repo, hashes_file, "--staged").stderr


def test_a_banned_symlink_name_and_target_are_redacted(repo, hashes_file):
    os.symlink(f"/elsewhere/{TERM}", repo / NAMED)
    git(repo, "add", NAMED)
    result = run_script(repo, hashes_file, "--staged")
    assert result.returncode == 1 and TERM not in everything(result)


def test_a_banned_message_file_path_is_redacted(repo, hashes_file, tmp_path):
    message = tmp_path / f"{TERM}.msg"
    message.write_text(f"feat: x {TERM}\n")
    result = run_script(repo, hashes_file, "--message", str(message))
    assert result.returncode == 1
    assert TERM not in everything(result)


def test_history_never_prints_a_banned_path_ref_or_tag_name(repo, hashes_file):
    (repo / TERM).mkdir()
    (repo / TERM / NAMED).write_text(f"host = {TERM}\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", f"feat: {TERM}")
    git(repo, "tag", "-a", TERM, "-m", f"release {TERM}")
    git(repo, "branch", f"feature/{TERM}")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1
    assert TERM not in everything(result)


def test_a_structural_path_finding_is_redacted_too(repo, hashes_file):
    name = "alice" + "@" + "corp.invalid.txt"
    (repo / name).write_text("clean\n")
    result = run_script(repo, hashes_file, name)
    assert result.returncode == 1
    assert "alice" not in everything(result)
    assert "<path redacted: email>" in result.stderr
