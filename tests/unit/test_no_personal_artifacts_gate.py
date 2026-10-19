"""The scanner must fail closed: every route to a banned name has to be scanned."""

import hashlib
import os
import tomllib

import pytest
from scanner_support import REPO_ROOT, TERM, git, run_script

TEXT = f"host = {TERM}\n"
ENCODINGS = ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"]  # all caught, by name or as binary


def commit(repo, message="feat: add"):
    git(repo, "commit", "-q", "-m", message)


# Binary and wide-character content ====================================================================================


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_wide_encoded_text_is_scanned_by_name(repo, hashes_file, encoding):
    (repo / "a.txt").write_bytes(TEXT.encode(encoding))
    result = run_script(repo, hashes_file, "a.txt")
    assert result.returncode == 1
    assert "a.txt" in result.stderr


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_wide_encoded_text_is_scanned_when_staged(repo, hashes_file, encoding):
    (repo / "a.txt").write_bytes(TEXT.encode(encoding))
    git(repo, "add", "a.txt")
    assert run_script(repo, hashes_file, "--staged").returncode == 1


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-32-be"])
def test_history_finds_wide_encoded_content_removed_later(repo, hashes_file, encoding):
    (repo / "a.txt").write_bytes(TEXT.encode(encoding))
    git(repo, "add", "a.txt")
    commit(repo)
    (repo / "a.txt").write_text("clean\n")
    git(repo, "commit", "-q", "-am", "fix: clean")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_finds_a_name_in_a_binary_blob(repo, hashes_file):
    (repo / "b.bin").write_bytes(b"\x00\x01" + TERM.encode() + b"\x00")
    git(repo, "add", "b.bin")
    commit(repo)
    assert run_script(repo, hashes_file, "--history").returncode == 1


# Symlinks, tree reads and files named on the command line =============================================================


def link(repo, name, target):
    os.symlink(target, repo / name)
    git(repo, "add", name)


def test_a_staged_symlink_target_is_scanned(repo, hashes_file):
    link(repo, "tc", f"/elsewhere/{TERM}")
    assert run_script(repo, hashes_file, "--staged").returncode == 1


def test_a_tracked_symlink_target_is_scanned_in_tree_mode(repo, hashes_file):
    link(repo, "tc", f"/elsewhere/{TERM}")
    assert run_script(repo, hashes_file, "--tree").returncode == 1


def test_a_symlink_target_in_history_is_scanned(repo, hashes_file):
    link(repo, "tc", f"/elsewhere/{TERM}")
    commit(repo)
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_symlink_named_on_the_command_line_is_scanned_by_target(repo, hashes_file):
    os.symlink(f"/elsewhere/{TERM}", repo / "tc")
    assert run_script(repo, hashes_file, "tc").returncode == 1


def test_a_type_change_to_a_symlink_is_scanned(repo, hashes_file):
    (repo / "a").write_text("clean\n")
    git(repo, "add", "a")
    commit(repo)
    (repo / "a").unlink()
    link(repo, "a", f"/elsewhere/{TERM}")
    assert git(repo, "diff", "--cached", "--name-status").startswith("T")
    assert run_script(repo, hashes_file, "--staged").returncode == 1


def test_tree_mode_reads_the_index_not_the_working_tree(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    (repo / "a.txt").write_text(TEXT)
    assert run_script(repo, hashes_file, "--tree").returncode == 0
    git(repo, "add", "a.txt")
    assert run_script(repo, hashes_file, "--tree").returncode == 1


def test_tree_mode_ignores_untracked_files(repo, hashes_file):
    (repo / "tracked.txt").write_text("clean\n")
    git(repo, "add", "tracked.txt")
    (repo / "untracked.txt").write_text(TEXT)
    assert run_script(repo, hashes_file, "--tree").returncode == 0


def test_tree_mode_flags_a_tracked_path(repo, hashes_file):
    (repo / f"{TERM}.txt").write_text("clean\n")
    git(repo, "add", ".")
    assert run_script(repo, hashes_file, "--tree").returncode == 1


def test_a_missing_file_named_on_the_command_line_is_an_error(repo, hashes_file):
    result = run_script(repo, hashes_file, "absent.txt")
    assert result.returncode == 2
    assert "absent.txt" in result.stderr


def test_a_directory_named_on_the_command_line_is_an_error(repo, hashes_file):
    (repo / "d").mkdir()
    assert run_script(repo, hashes_file, "d").returncode == 2


# Line splitting =======================================================================================================


@pytest.mark.parametrize("separator", ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\r"])
def test_history_scans_text_after_a_unicode_line_separator(repo, hashes_file, separator):
    (repo / "a.txt").write_text(f"ok{separator}{TERM}\n", encoding="utf-8", newline="")
    git(repo, "add", "a.txt")
    commit(repo)
    assert run_script(repo, hashes_file, "--history").returncode == 1


@pytest.mark.parametrize("separator", ["\x0b", "\x0c", "\x1c", "\x85", "\u2028"])
def test_history_scans_a_message_after_a_unicode_line_separator(repo, hashes_file, separator):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    commit(repo, f"feat: ok{separator}{TERM}")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_message_containing_old_in_band_markers_is_still_scanned(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    commit(repo, f"feat: ok\x01\x02 {TERM}")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_line_numbers_count_only_newlines(repo, hashes_file):
    (repo / "a.txt").write_text(f"a\x0c\n{TERM}\n", newline="")
    assert "a.txt:2: banned-term" in run_script(repo, hashes_file, "a.txt").stderr


# Messages, tags and refs ==============================================================================================


def test_message_mode_scans_hash_lines_too(repo, hashes_file):
    (repo / "msg").write_text(f"feat: x\n\n# {TERM}\n")
    result = run_script(repo, hashes_file, "--message", "msg")
    assert result.returncode == 1
    assert "msg:3: banned-term" in result.stderr


SCISSORS = "# " + "-" * 24 + " >8 " + "-" * 24


def test_message_mode_scans_below_gits_scissors_line_too(repo, hashes_file, tmp_path):
    message = tmp_path / "msg"
    message.write_text(f"feat: x\n{SCISSORS}\ndiff --git a/{TERM} b/{TERM}\n+{TERM}\n")
    assert run_script(repo, hashes_file, "--message", str(message)).returncode == 1


def test_message_mode_scans_comment_lines_above_the_scissors(repo, hashes_file, tmp_path):
    message = tmp_path / "msg"
    message.write_text(f"feat: x\n# {TERM}\n{SCISSORS}\n")
    assert run_script(repo, hashes_file, "--message", str(message)).returncode == 1


def test_message_mode_tells_the_committer_how_to_get_past_a_template_match(repo, hashes_file, tmp_path):
    message = tmp_path / "msg"
    message.write_text(f"feat: x\n#\tnew file:   {TERM}.txt\n")
    stderr = run_script(repo, hashes_file, "--message", str(message)).stderr
    assert "commit template" in stderr and "commit with -m" in stderr and "-v" in stderr


def test_history_scans_an_annotated_tag_message(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    commit(repo)
    git(repo, "tag", "-a", "v1", "-m", f"release {TERM}")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_scans_a_tag_pointing_at_a_tag(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    commit(repo)
    git(repo, "tag", "-a", "inner", "-m", f"inner {TERM}")
    git(repo, "tag", "-a", "outer", "-m", "outer", "inner")
    git(repo, "tag", "-d", "inner")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_scans_path_names_of_every_copy_of_a_blob(repo, hashes_file):
    (repo / "a.txt").write_text("same\n")
    (repo / f"{TERM}.txt").write_text("same\n")
    git(repo, "add", ".")
    commit(repo)
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_scans_directory_names(repo, hashes_file):
    (repo / TERM).mkdir()
    (repo / TERM / "a.txt").write_text("clean\n")
    git(repo, "add", ".")
    commit(repo)
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_scans_ref_names(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    commit(repo)
    git(repo, "branch", f"feature/{TERM}")
    assert run_script(repo, hashes_file, "--history").returncode == 1


# The ban list and --hash ==============================================================================================


def test_an_empty_ban_list_is_an_error(repo, tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n\n")
    (repo / "a.txt").write_text(TEXT)
    result = run_script(repo, empty, "a.txt")
    assert result.returncode == 2
    assert "ban list unreadable" in result.stderr


@pytest.mark.parametrize("term", ["my-host", "a b", "", "a_b", "x.y", "é"])
def test_hash_rejects_terms_that_can_never_match(repo, hashes_file, term):
    result = run_script(repo, hashes_file, "--hash", term)
    assert result.returncode == 2
    assert result.stdout == ""


def test_hash_accepts_one_alphanumeric_token_in_any_case(repo, hashes_file):
    result = run_script(repo, hashes_file, "--hash", "MyHost2")
    assert result.stdout.strip() == f"7 {hashlib.sha256(b'myhost2').hexdigest()}"


# git failures and wiring ==============================================================================================


def test_a_git_failure_prints_gits_stderr(tmp_path, hashes_file):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    result = run_script(not_a_repo, hashes_file, "--tree")
    assert result.returncode != 0
    assert "not a git repository" in result.stderr


def hook(hook_id):
    config = tomllib.loads((REPO_ROOT / "prek.toml").read_text())
    (found, ) = [h for repo in config["repos"] for h in repo["hooks"] if h["id"] == hook_id]
    return found


def test_the_prek_file_hook_scans_the_index_at_pre_commit_only():
    found = hook("no-personal-artifacts")
    assert found["entry"].endswith("--staged")
    assert found["pass_filenames"] is False
    assert found["always_run"] is True
    assert found["stages"] == ["pre-commit"]


def test_the_prek_message_hook_runs_at_commit_msg():
    assert hook("no-personal-artifacts-message")["stages"] == ["commit-msg"]


def test_gitattributes_has_no_dead_vendored_rule():
    assert "linguist" not in (REPO_ROOT / ".gitattributes").read_text()
