"""History and index scans must see every object git can hide or alias."""

import subprocess

import pytest
from scanner_support import TERM, git, run_script


def seed(repo):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add")


# Tag objects ==========================================================================================================


def test_history_scans_the_name_in_a_tag_object_whose_ref_was_renamed(repo, hashes_file):
    seed(repo)
    git(repo, "tag", "-a", TERM, "-m", "clean")
    git(repo, "update-ref", "refs/tags/v1", git(repo, "rev-parse", TERM).strip())
    git(repo, "tag", "-d", TERM)
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1
    assert TERM not in result.stdout + result.stderr


def test_history_scans_the_name_in_a_nested_tag_object(repo, hashes_file):
    seed(repo)
    git(repo, "tag", "-a", TERM, "-m", "clean")
    git(repo, "tag", "-a", "outer", "-m", "clean", TERM)
    git(repo, "tag", "-d", TERM)
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_clean_tag_object_passes(repo, hashes_file):
    seed(repo)
    git(repo, "tag", "-a", "v1", "-m", "release")
    assert run_script(repo, hashes_file, "--history").returncode == 0


# Replacement refs =====================================================================================================


def replace_with_clean(repo, path):
    dirty = git(repo, "rev-parse", f":{path}").strip()
    result = subprocess.run(["git", "hash-object", "-w", "--stdin"],
                            cwd=repo,
                            input="clean\n",
                            text=True,
                            capture_output=True,
                            check=True)
    git(repo, "replace", dirty, result.stdout.strip())


@pytest.mark.parametrize("mode", ["--staged", "--tree"])
def test_a_replace_ref_cannot_hide_an_indexed_blob(repo, hashes_file, mode):
    (repo / "a.txt").write_text(f"host = {TERM}\n")
    git(repo, "add", "a.txt")
    replace_with_clean(repo, "a.txt")
    assert run_script(repo, hashes_file, mode).returncode == 1


def test_a_replace_ref_cannot_hide_a_blob_in_history(repo, hashes_file):
    (repo / "a.txt").write_text(f"host = {TERM}\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add")
    replace_with_clean(repo, "a.txt")
    assert run_script(repo, hashes_file, "--history").returncode == 1


# Notes ================================================================================================================


def test_history_scans_git_notes(repo, hashes_file):
    seed(repo)
    git(repo, "notes", "add", "-m", f"note {TERM}", "HEAD")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_scans_a_note_that_was_later_removed(repo, hashes_file):
    seed(repo)
    git(repo, "notes", "add", "-m", f"note {TERM}", "HEAD")
    git(repo, "notes", "remove", "HEAD")
    assert run_script(repo, hashes_file, "--history").returncode == 1
