import hashlib
import re

import pytest
from scanner_support import SCRIPT, TERM, TRACKED_HASHES, git, kinds, load_script, run_script

# Detection ============================================================================================================


@pytest.mark.parametrize(
    "text",
    [f"host = {TERM}", f"host = {TERM.upper()}", f"a.{TERM}.example", f"{TERM}_rsync", f"x-{TERM}-y", f"{TERM}"],
)
def test_a_banned_token_is_found_however_it_is_cased_or_delimited(text, hashes_file):
    assert kinds(text, hashes_file) == ["banned-term"]


@pytest.mark.parametrize(
    "text",
    [f"{TERM}Host", f"{TERM}2", f"my{TERM}", f"my{TERM}box9", f"{TERM}{TERM}", f"{TERM[:3]}{TERM[:3].upper()}{TERM}"],
)
def test_a_banned_name_embedded_in_a_longer_token_is_found(text, hashes_file):
    assert kinds(text, hashes_file) == ["banned-term"]


@pytest.mark.parametrize("text", [f"{TERM[:3]}-{TERM[3:]}", f"{TERM[:-1]}", "example.com", "nothing to see", ""])
def test_a_partial_or_split_name_and_a_clean_text_are_not_flagged(text, hashes_file):
    assert kinds(text, hashes_file) == []


def path(*parts: str, sep: str) -> str:
    return sep.join(parts)


# Assembled from pieces so this file does not itself trip the scanner.
@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("SHA256" + ":" + "A" * 43, "ssh-fingerprint"),
        ("MD5" + ":" + ":".join(["ab"] * 16), "ssh-fingerprint"),
        ("-----BEGIN OPENSSH " + "PRIVATE KEY-----", "private-key"),
        ("ssh-" + "ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghijklmnopqrstuvwx", "ssh-public-key"),
        ("alice" + "@" + "corp.invalid", "email"),
        (path("", "Users", "alice", "src", sep="/"), "home-path"),
        (path("", "home", "alice", "src", sep="/"), "home-path"),
        (path("C:", "Users", "alice", "src", sep="\\"), "home-path"),
        (path("C:", "Users", "alice", "src", sep="\\\\"), "home-path"),
        (path("C:", "Users", "alice", "src", sep="/"), "home-path"),
        (path("x" + "C:", "Users", "alice", "src", sep="\\"), "home-path"),
        (path("HOMEPATH=", "Users", "alice", sep="\\"), "home-path"),
        ('{"p":"' + path("", "Users", "alice", "x", sep="\\/") + '"}', "home-path"),
        ("alice" + "@" + "github.com", "email"),
        ("file://" + path("", "Users", "alice", "x", sep="/"), "home-path"),
        ("cd " + path("", "home", "alice", sep="/"), "home-path"),
        ("(" + path("", "home", "alice", sep="/") + ")", "home-path"),
    ],
)
def test_structural_artifacts_are_found(text, kind, hashes_file):
    assert kinds(text, hashes_file) == [kind]


@pytest.mark.parametrize(
    "text",
    [
        "git@github.com:org/repo.git",
        "Co-authored-by: GitHub <" + "noreply@github.com>",
        "alice@example.com",
        "1234+x@users.noreply.github.com",
        "ssh user@host",
        "@pytest.mark.parametrize",
        "/home/runner/work",
        "/home/<user>/rt",
        "/Users/user/rt",
        "src/home/index.html",
        "docs/Users/guide.md",
        "./home/notes.txt",
        "../home/notes.txt",
        "my_home/notes.txt",
    ],
)
def test_placeholders_are_not_flagged(text, hashes_file):
    assert kinds(text, hashes_file) == []


def test_findings_carry_the_line_but_never_the_matched_text(hashes_file):
    module = load_script()
    (finding, ) = module.scan_text(f"ok\nhost = {TERM}\n", module.load_hashes(hashes_file))
    assert finding.line == 2
    assert TERM not in repr(finding)


def test_the_cli_does_not_echo_the_matched_text(repo, hashes_file):
    (repo / "a.txt").write_text(f"host = {TERM}\n")
    result = run_script(repo, hashes_file, "a.txt")
    assert result.returncode == 1
    assert "a.txt:1: banned-term" in result.stderr
    assert TERM not in result.stdout + result.stderr


def test_a_banned_token_in_a_path_is_found(repo, hashes_file):
    (repo / f"{TERM}.plist").write_text("clean\n")
    result = run_script(repo, hashes_file, f"{TERM}.plist")
    assert result.returncode == 1
    assert "banned-term" in result.stderr


def test_clean_files_pass(repo, hashes_file):
    (repo / "a.txt").write_text("hello\n")
    assert run_script(repo, hashes_file, "a.txt").returncode == 0


# Modes ================================================================================================================


def test_staged_mode_reads_the_index_not_the_working_tree(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    (repo / "a.txt").write_text(f"{TERM}\n")
    assert run_script(repo, hashes_file, "--staged").returncode == 0


def test_staged_mode_flags_staged_content(repo, hashes_file):
    (repo / "a.txt").write_text(f"{TERM}\n")
    git(repo, "add", "a.txt")
    result = run_script(repo, hashes_file, "--staged")
    assert result.returncode == 1
    assert "a.txt:1: banned-term" in result.stderr


def test_staged_mode_is_the_default(repo, hashes_file):
    (repo / "a.txt").write_text(f"{TERM}\n")
    git(repo, "add", "a.txt")
    assert run_script(repo, hashes_file).returncode == 1


def test_staged_mode_flags_a_staged_path(repo, hashes_file):
    (repo / f"{TERM}.txt").write_text("clean\n")
    git(repo, "add", ".")
    assert run_script(repo, hashes_file, "--staged").returncode == 1


def test_staged_mode_ignores_a_deleted_file(repo, hashes_file):
    (repo / "a.txt").write_text(f"{TERM}\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add")
    git(repo, "rm", "-q", "a.txt")
    assert run_script(repo, hashes_file, "--staged").returncode == 0


def test_message_mode_flags_the_commit_message(repo, hashes_file, tmp_path):
    message = tmp_path / "msg"
    message.write_text(f"feat: add {TERM}\n")
    result = run_script(repo, hashes_file, "--message", str(message))
    assert result.returncode == 1
    assert "msg:1: banned-term" in result.stderr
    message.write_text("feat: add thing\n")
    assert run_script(repo, hashes_file, "--message", str(message)).returncode == 0


def test_history_mode_finds_content_removed_in_a_later_commit(repo, hashes_file):
    (repo / "a.txt").write_text(f"{TERM}\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add")
    (repo / "a.txt").write_text("clean\n")
    git(repo, "commit", "-q", "-am", "fix: clean")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1
    assert "banned-term" in result.stderr
    assert TERM not in result.stdout + result.stderr


def test_history_mode_finds_a_commit_message(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", f"feat: add {TERM}")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_mode_passes_a_clean_history(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add")
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_hash_flag_prints_the_digest_to_add_to_the_list(repo, hashes_file):
    result = run_script(repo, hashes_file, "--hash", TERM.upper())
    assert result.stdout.strip() == f"{len(TERM)} {hashlib.sha256(TERM.encode()).hexdigest()}"


# The tracked ban list =================================================================================================


def test_the_tracked_ban_list_is_nonempty_and_holds_only_lengths_and_digests():
    lines = [row.strip() for row in TRACKED_HASHES.read_text().splitlines() if row.strip() and not row.startswith("#")]
    assert lines
    assert all(re.fullmatch(r"[0-9]+ [0-9a-f]{64}", line) for line in lines)


def test_history_mode_does_not_mistake_the_diff_marker_for_an_email_local_part(repo, hashes_file):
    (repo / "a.py").write_text("@pytest.mark.parametrize\n")
    git(repo, "add", "a.py")
    git(repo, "commit", "-q", "-m", "feat: add")
    assert run_script(repo, hashes_file, "--history").returncode == 0
