"""Errors reach public logs too: they get the same redaction as findings, and never a traceback."""

import pathlib

from scanner_support import TERM, git, load_script, run_script

NAMED = f"{TERM}-box.txt"


def everything(result):
    return result.stdout + result.stderr


def test_a_missing_banned_path_is_an_exit_2_without_the_name(repo, hashes_file):
    result = run_script(repo, hashes_file, NAMED)
    assert result.returncode == 2
    assert TERM not in everything(result) and "Traceback" not in result.stderr


def test_a_missing_banned_message_file_is_an_exit_2_without_the_name(repo, hashes_file, tmp_path):
    result = run_script(repo, hashes_file, "--message", str(tmp_path / f"{TERM}.msg"))
    assert result.returncode == 2
    assert TERM not in everything(result) and "Traceback" not in result.stderr


def test_a_missing_clean_message_file_is_named_in_the_error(repo, hashes_file, tmp_path):
    result = run_script(repo, hashes_file, "--message", str(tmp_path / "absent.msg"))
    assert result.returncode == 2 and "absent.msg" in result.stderr


def test_an_unreadable_file_is_an_exit_2_without_a_traceback(repo, hashes_file, monkeypatch, capsys):
    (repo / NAMED).write_text("clean\n")
    monkeypatch.chdir(repo)

    def refuse(self):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(pathlib.Path, "read_bytes", refuse)
    code = load_script().main(["--hashes", str(hashes_file), NAMED])
    captured = capsys.readouterr()
    assert code == 2
    assert TERM not in captured.out + captured.err and "Traceback" not in captured.err
    assert "Permission denied" in captured.err


def test_gits_stderr_is_redacted(repo, hashes_file):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add")
    ref = repo / ".git" / "refs" / "heads" / "feature" / TERM
    ref.parent.mkdir(parents=True)
    ref.write_text("0123456789012345678901234567890123456789\n")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 2
    assert TERM not in everything(result) and "Traceback" not in result.stderr


def test_a_git_failure_still_says_what_failed(tmp_path, hashes_file):
    plain = tmp_path / "plain"
    plain.mkdir()
    result = run_script(plain, hashes_file, "--tree")
    assert result.returncode == 2 and "not a git repository" in result.stderr


def test_redact_text_replaces_banned_tokens_and_structural_lines(hashes_file):
    module = load_script()
    hashes = module.load_hashes(hashes_file)
    redacted = module.redact_text(
        f"fatal: bad object refs/heads/feature/{TERM}\nmail " + "a" + "@" + "corp.invalid", hashes
    )
    assert TERM not in redacted and "corp.invalid" not in redacted
    assert redacted.startswith("fatal: bad object refs/heads/feature/")


def test_redact_text_leaves_clean_text_alone(hashes_file):
    module = load_script()
    assert module.redact_text(
        "fatal: not a git repository", module.load_hashes(hashes_file)
    ) == "fatal: not a git repository"


def test_argparse_errors_do_not_echo_a_banned_argument(repo, hashes_file):
    result = run_script(repo, hashes_file, "--tree", f"-{TERM}.txt")
    assert result.returncode == 2
    assert TERM not in result.stdout + result.stderr and "Traceback" not in result.stderr


def test_argparse_errors_still_say_what_was_wrong(repo, hashes_file):
    result = run_script(repo, hashes_file, "--bogus-option")
    assert result.returncode == 2 and "--bogus-option" in result.stderr


def test_a_usage_error_is_withheld_when_the_ban_list_cannot_be_read(repo, tmp_path):
    result = run_script(repo, tmp_path / "missing.txt", f"-{TERM}.txt")
    assert result.returncode == 2 and TERM not in result.stdout + result.stderr


def test_an_unreadable_ban_list_error_does_not_print_its_path(repo, tmp_path):
    result = run_script(repo, tmp_path / f"{TERM}.txt", "a.txt")
    assert result.returncode == 2 and "ban list unreadable" in result.stderr
    assert TERM not in result.stdout + result.stderr and "FileNotFoundError" in result.stderr


def test_a_malformed_ban_list_error_does_not_print_its_path(repo, tmp_path):
    bad = tmp_path / f"{TERM}.txt"
    bad.write_text("not an entry\n")
    result = run_script(repo, bad, "a.txt")
    assert result.returncode == 2 and "ban list unreadable" in result.stderr
    assert TERM not in result.stdout + result.stderr
