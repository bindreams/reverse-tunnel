"""Every header of every commit and tag object is content: identities, mergetag, encodings."""

import pytest
from scanner_support import REPO_ROOT, TERM, git, hash_raw_object, run_script

CLEAN_IDENTITY = {"GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "1+dev@users.noreply.github.com"}


def seed(repo, **kwargs):
    (repo / "a.txt").write_text("clean\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "feat: add", **kwargs)


def raw_commit(repo, headers: bytes = b"", body: bytes = b"feat: raw\n") -> None:
    seed(repo)
    write_raw_commit(repo, headers, body)


def write_raw_commit(repo, headers: bytes, body: bytes = b"feat: raw\n") -> None:
    tree = git(repo, "write-tree").strip()
    fixed = f"tree {tree}\nauthor t <t@example.com> 0 +0000\ncommitter t <t@example.com> 0 +0000\n".encode()
    git(repo, "update-ref", "refs/heads/raw", hash_raw_object(repo, "commit", fixed + headers + b"\n" + body))


# mergetag =============================================================================================================


def merge_a_tag(repo, tag_name, tag_message):
    """A commit whose `mergetag` header embeds a tag, in git's own folded format."""
    seed(repo)
    head = git(repo, "rev-parse", "HEAD").strip()
    embedded = (
        f"mergetag object {head}\n type commit\n tag {tag_name}\n tagger t <t@example.com> 0 +0000\n \n"
        f" {tag_message}\n"
    )
    write_raw_commit(repo, embedded.encode())


def test_the_mergetag_header_carries_the_tag_name_into_the_scan(repo, hashes_file):
    merge_a_tag(repo, TERM, "clean")
    assert "mergetag" in git(repo, "cat-file", "-p", "refs/heads/raw")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and TERM not in result.stdout + result.stderr


def test_the_mergetag_message_is_scanned(repo, hashes_file):
    merge_a_tag(repo, "v1", f"release {TERM}")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_clean_mergetag_passes(repo, hashes_file):
    merge_a_tag(repo, "v1", "release")
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_a_continuation_line_that_imitates_an_opaque_header_is_still_scanned(repo, hashes_file):
    raw_commit(repo, f"x-note a\n tree {TERM}\n".encode())
    assert run_script(repo, hashes_file, "--history").returncode == 1


# Identities ===========================================================================================================


@pytest.mark.parametrize("variable", ["GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"])
def test_a_banned_name_in_a_commit_identity_is_found(repo, hashes_file, variable):
    seed(repo, env={variable: TERM})
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and TERM not in result.stdout + result.stderr


def test_a_banned_name_in_an_identity_email_is_found(repo, hashes_file):
    seed(repo, env={"GIT_AUTHOR_EMAIL": f"dev@{TERM}.example.org"})
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_hostname_email_is_found(repo, hashes_file):
    seed(repo, env={"GIT_COMMITTER_EMAIL": "dev" + "@" + "workstation.local"})
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_banned_name_in_a_tagger_is_found(repo, hashes_file):
    seed(repo)
    git(repo, "tag", "-a", "v1", "-m", "release", env={"GIT_COMMITTER_NAME": TERM})
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_noreply_identity_passes(repo, hashes_file):
    seed(repo, env=CLEAN_IDENTITY)
    assert run_script(repo, hashes_file, "--history").returncode == 0


# Encodings ============================================================================================================


@pytest.mark.parametrize("encoding", ["ISO-8859-1", "latin1", "Shift_JIS"])
def test_a_non_utf8_commit_encoding_is_a_finding(repo, hashes_file, encoding):
    raw_commit(repo, f"encoding {encoding}\n".encode())
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "non-UTF-8 commit encoding" in result.stderr


@pytest.mark.parametrize("encoding", ["UTF-8", "utf-8", "UTF8", "utf8"])
def test_a_utf8_encoding_header_is_fine(repo, hashes_file, encoding):
    raw_commit(repo, f"encoding {encoding}\n".encode())
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_a_message_that_is_not_valid_utf8_is_a_finding(repo, hashes_file):
    raw_commit(repo, body=b"caf\xe9\n")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "invalid UTF-8 in message" in result.stderr


def test_a_header_that_is_not_valid_utf8_is_a_finding(repo, hashes_file):
    raw_commit(repo, b"x-note caf\xe9\n")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_banned_name_in_a_non_utf8_message_is_still_reported_by_name(repo, hashes_file):
    raw_commit(repo, body=b"caf\xe9 " + TERM.encode() + b"\n")
    assert "banned-term" in run_script(repo, hashes_file, "--history").stderr


# Every ref ============================================================================================================


def test_history_walks_refs_outside_heads_and_tags(repo, hashes_file):
    seed(repo)
    (repo / "b.txt").write_text(f"host = {TERM}\n")
    git(repo, "add", "b.txt")
    git(repo, "commit", "-q", "-m", "feat: leak")
    git(repo, "update-ref", "refs/pull/1/head", "HEAD")
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_history_walks_the_target_of_a_replace_ref(repo, hashes_file):
    seed(repo)
    old = git(repo, "rev-parse", "HEAD:a.txt").strip()
    new = hash_raw_object(repo, "blob", f"host = {TERM}\n".encode())
    git(repo, "replace", old, new)
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_ci_fetches_every_advertised_ref_before_the_history_scan():
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yaml").read_text()
    assert "+refs/*:refs/fetched/*" in workflow
    assert workflow.index("refs/fetched") < workflow.index("--history")


# Signatures ===========================================================================================================

BODY = "A" * 20 + TERM + "B" * 40  # 66 base64 characters, as long as an armour line


def pgp(*armour_headers, body=BODY):
    return "-----BEGIN PGP SIGNATURE-----\n" + "".join(
        f"{h}\n" for h in armour_headers
    ) + f"\n{body}\n=abcd\n-----END PGP SIGNATURE-----\n"


def folded(key, block):
    first, *rest = block.rstrip("\n").split("\n")
    return (f"{key} {first}\n" + "".join(f" {line}\n" for line in rest)).encode()


def raw_tag(repo, message: str) -> None:
    seed(repo)
    head = git(repo, "rev-parse", "HEAD").strip()
    content = f"object {head}\ntype commit\ntag v1\ntagger t <t@example.com> 0 +0000\n\n{message}".encode()
    git(repo, "update-ref", "refs/tags/v1", hash_raw_object(repo, "tag", content))


@pytest.mark.parametrize("key", ["gpgsig", "gpgsig-sha256"])
def test_a_signature_body_in_a_commit_header_is_not_scanned(repo, hashes_file, key):
    raw_commit(repo, folded(key, pgp()))
    assert run_script(repo, hashes_file, "--history").returncode == 0


@pytest.mark.parametrize("key", ["gpgsig", "gpgsig-sha256"])
def test_an_armour_header_in_a_commit_signature_is_scanned(repo, hashes_file, key):
    raw_commit(repo, folded(key, pgp(f"Comment: {TERM}")))
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and TERM not in result.stdout + result.stderr


def test_an_ssh_signature_body_is_not_scanned(repo, hashes_file):
    block = "-----BEGIN SSH SIGNATURE-----\n" + BODY + "\n-----END SSH SIGNATURE-----\n"
    raw_commit(repo, folded("gpgsig", block))
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_a_short_line_inside_a_signature_block_is_still_scanned(repo, hashes_file):
    raw_commit(repo, folded("gpgsig", pgp(body=TERM)))
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_the_signature_of_a_mergetag_is_not_scanned(repo, hashes_file):
    embedded = b"mergetag object " + b"0" * 40 + b"\n type commit\n tag v1\n tagger t <t@example.com> 0 +0000\n \n"
    raw_commit(repo, embedded + b"".join(f" {line}\n".encode() for line in pgp().rstrip("\n").split("\n")))
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_a_signature_body_in_a_tag_message_is_not_scanned(repo, hashes_file):
    raw_tag(repo, "release\n" + pgp())
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_an_armour_header_in_a_tag_signature_is_scanned(repo, hashes_file):
    raw_tag(repo, "release\n" + pgp(f"Comment: {TERM}"))
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_text_around_a_tag_signature_is_scanned(repo, hashes_file):
    raw_tag(repo, f"release {TERM}\n" + pgp())
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_signature_block_in_a_commit_message_is_not_exempt(repo, hashes_file):
    raw_commit(repo, body=("feat: x\n\n" + pgp()).encode())
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_a_long_base64_line_outside_a_signature_block_is_scanned(repo, hashes_file):
    raw_commit(repo, folded("x-note", BODY + "\n"))
    assert run_script(repo, hashes_file, "--history").returncode == 1
