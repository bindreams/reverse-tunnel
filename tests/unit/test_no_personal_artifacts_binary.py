"""Anything that is not decodable text is a finding, and decodable text is scanned however it is framed."""

import gzip

import pytest
from scanner_support import TERM, git, load_script, run_script

ASCII = f"host = {TERM}".encode()
BINARY_MESSAGE = "binary content not allowed"

# Each case is raw file content that hides a banned name from a naive decoder.
FRAMED = {
    "bogus-le-bom-then-ascii": b"\xff\xfe" + ASCII,
    "bogus-be-bom-then-ascii": b"\xfe\xff" + ASCII,
    "utf16-starting-with-nul": ("\x00" + f"host = {TERM}").encode("utf-16"),
    "bogus-utf32-bom-then-ascii": b"\xff\xfe\x00\x00" + ASCII,
}


def run_in_every_mode(repo, hashes, content):
    (repo / "a.txt").write_bytes(content)
    results = {"positional": run_script(repo, hashes, "a.txt")}
    git(repo, "add", "a.txt")
    results["staged"] = run_script(repo, hashes, "--staged")
    results["tree"] = run_script(repo, hashes, "--tree")
    git(repo, "commit", "-q", "-m", "feat: add")
    (repo / "a.txt").write_text("clean\n")
    git(repo, "commit", "-q", "-am", "fix: clean")
    results["history"] = run_script(repo, hashes, "--history")
    return results


@pytest.mark.parametrize("name", FRAMED)
def test_framing_tricks_do_not_hide_a_name_in_any_mode(repo, hashes_file, name):
    results = run_in_every_mode(repo, hashes_file, FRAMED[name])
    assert {mode: r.returncode for mode, r in results.items()} == dict.fromkeys(results, 1)
    assert all(TERM not in r.stdout + r.stderr for r in results.values())


@pytest.mark.parametrize("name", FRAMED)
def test_framing_tricks_still_report_the_name(repo, hashes_file, name):
    (repo / "a.txt").write_bytes(FRAMED[name])
    assert "banned-term" in run_script(repo, hashes_file, "a.txt").stderr


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_bom_marked_text_is_decoded_and_scanned(repo, hashes_file, encoding):
    (repo / "a.txt").write_bytes(f"host = {TERM}\n".encode(encoding))
    result = run_script(repo, hashes_file, "a.txt")
    assert "a.txt:1: banned-term" in result.stderr
    assert BINARY_MESSAGE not in result.stderr


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_wide_text_without_a_bom_is_binary_content(repo, hashes_file, encoding):
    (repo / "a.txt").write_bytes(f"host = {TERM}\n".encode(encoding))
    result = run_script(repo, hashes_file, "a.txt")
    assert result.returncode == 1
    assert BINARY_MESSAGE in result.stderr


@pytest.mark.parametrize(
    "content",
    [b"\x00\x01\x02", b"plain\x00text", b"\xff\xfe\xfd", b"\x89PNG\r\n\x1a\n\x00", b"\xff\xfe" + b"\x00"],
    ids=["control-bytes", "nul-in-ascii", "invalid-utf8", "png-header", "odd-length-bom"],
)
def test_content_that_is_not_text_is_a_finding(repo, hashes_file, content):
    (repo / "b.bin").write_bytes(content)
    result = run_script(repo, hashes_file, "b.bin")
    assert result.returncode == 1
    assert f"b.bin: {BINARY_MESSAGE}" in result.stderr


def test_a_name_inside_a_binary_is_still_reported_as_a_name(repo, hashes_file):
    (repo / "b.bin").write_bytes(b"\x00\x01" + TERM.encode() + b"\x00")
    stderr = run_script(repo, hashes_file, "b.bin").stderr
    assert "banned-term" in stderr and BINARY_MESSAGE in stderr


def test_compressed_content_is_rejected(repo, hashes_file):
    (repo / "a.gz").write_bytes(gzip.compress(ASCII))
    git(repo, "add", "a.gz")
    result = run_script(repo, hashes_file, "--staged")
    assert result.returncode == 1 and BINARY_MESSAGE in result.stderr


def test_a_binary_in_history_is_rejected(repo, hashes_file):
    (repo / "b.bin").write_bytes(b"\x00\x01\x02")
    git(repo, "add", "b.bin")
    git(repo, "commit", "-q", "-m", "feat: add")
    (repo / "b.bin").unlink()
    git(repo, "commit", "-q", "-am", "fix: remove")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and BINARY_MESSAGE in result.stderr


def test_the_binary_allowlist_is_an_explicit_and_empty_path_set():
    assert load_script().BINARY_ALLOWED == frozenset()


def test_an_allowlisted_path_may_hold_binary_content(hashes_file):
    module = load_script()
    hashes = module.load_hashes(hashes_file)
    module.BINARY_ALLOWED = frozenset({"logo.png"})
    assert module.scan_blob("logo.png", b"\x89PNG\x00", hashes) == []
    assert module.scan_blob("other.png", b"\x89PNG\x00", hashes) != []
