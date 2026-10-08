"""Every header of every commit and tag object is content: identities, mergetag, encodings."""

import re
import shlex

import pytest
from scanner_support import REPO_ROOT, TERM, git, git_bytes, hash_raw_object, run_script

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


def test_identities_are_checked_for_banned_terms_only(repo, hashes_file):
    seed(repo, env={"GIT_AUTHOR_EMAIL": "dev" + "@" + "contributor.invalid", "GIT_COMMITTER_NAME": "Real Name"})
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_a_github_committer_passes(repo, hashes_file):
    seed(repo, env={"GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "noreply" + "@" + "github.com"})
    assert run_script(repo, hashes_file, "--history").returncode == 0


def test_a_banned_name_in_an_author_email_domain_still_fails(repo, hashes_file):
    seed(repo, env={"GIT_AUTHOR_EMAIL": "anna" + "@" + f"{TERM}.local"})
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


def ci_fetch_command() -> list[str]:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yaml").read_text()
    (command, ) = re.findall(r"- run: (git fetch .*)", workflow)
    assert workflow.index(command) < workflow.index("--history")
    return shlex.split(command)


def test_ci_fetches_every_ref_but_pull_refs_into_the_history_scan(tmp_path):
    remote = tmp_path / "remote"
    remote.mkdir()
    git(remote, "init", "-q", "-b", "main")
    git(remote, "commit", "-q", "--allow-empty", "-m", "feat: x")
    for ref in ("refs/pull/1/head", "refs/custom/x", "refs/notes/commits", "refs/replace/abc"):
        git(remote, "update-ref", ref, "HEAD")
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", str(remote), str(clone))
    git(clone, *ci_fetch_command()[1:])
    fetched = set(git(clone, "for-each-ref", "--format=%(refname)", "refs/fetched/").split())
    assert fetched == {
        "refs/fetched/heads/main", "refs/fetched/custom/x", "refs/fetched/notes/commits", "refs/fetched/replace/abc"
    }


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


# NUL bytes ============================================================================================================


def test_a_nul_in_a_tag_message_is_a_finding_and_the_text_is_still_scanned(repo, hashes_file):
    raw_tag(repo, "host zzquux\n".encode("utf-16-le").decode("latin-1"))
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "NUL byte in message" in result.stderr
    assert "banned-term" in result.stderr and TERM not in result.stdout + result.stderr


def test_a_nul_in_a_commit_message_is_a_finding(repo, hashes_file):
    raw_commit(repo, body=f"host {TERM}\n".encode("utf-16-le"))
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "NUL byte in message" in result.stderr


def test_a_nul_in_a_header_is_a_finding(repo, hashes_file):
    raw_commit(repo, b"x-note a\x00b\n")
    assert "NUL byte in header" in run_script(repo, hashes_file, "--history").stderr


# Where a signature block may open =====================================================================================


def test_a_signature_block_opened_in_an_ordinary_header_is_not_exempt(repo, hashes_file):
    raw_commit(repo, folded("x-note", pgp()))
    assert run_script(repo, hashes_file, "--history").returncode == 1


def test_an_unterminated_signature_block_is_a_finding(repo, hashes_file):
    raw_commit(repo, folded("gpgsig", pgp().replace("-----END PGP SIGNATURE-----\n", "")))
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "unterminated signature block" in result.stderr


def test_an_unterminated_block_in_a_tag_message_is_a_finding(repo, hashes_file):
    raw_tag(repo, "release\n" + pgp().replace("-----END PGP SIGNATURE-----\n", ""))
    assert "unterminated signature block" in run_script(repo, hashes_file, "--history").stderr


def test_a_block_cannot_run_on_into_the_next_header(repo, hashes_file):
    opened = folded("gpgsig", "-----BEGIN PGP SIGNATURE-----\n")
    raw_commit(repo, opened + folded("x-note", BODY + "\n"))
    result = run_script(repo, hashes_file, "--history")
    assert "unterminated signature block" in result.stderr and "banned-term" in result.stderr


# Non-UTF-8 paths ======================================================================================================

BAD_NAME = b"caf\xe9.txt"


def index_a_bad_path(repo):
    blob = hash_raw_object(repo, "blob", b"clean\n")
    git_bytes(
        repo, "update-index", "--add", "--index-info", stdin=b"100644 " + blob.encode() + b"\t" + BAD_NAME + b"\n"
    )
    return blob


@pytest.mark.parametrize("mode", ["--staged", "--tree"])
def test_a_non_utf8_index_path_is_a_finding_not_a_traceback(repo, hashes_file, mode):
    index_a_bad_path(repo)
    result = run_script(repo, hashes_file, mode)
    assert result.returncode == 1 and "invalid UTF-8 in path" in result.stderr
    assert "Traceback" not in result.stderr


def test_a_non_utf8_path_in_history_is_a_finding(repo, hashes_file):
    blob = hash_raw_object(repo, "blob", b"clean\n")
    tree = git_bytes(repo, "mktree", stdin=b"100644 blob " + blob.encode() + b"\t" + BAD_NAME + b"\n")
    commit = git(repo, "commit-tree", tree, "-m", "feat: x").strip()
    git(repo, "update-ref", "refs/heads/main", commit)
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "invalid UTF-8 in path" in result.stderr


def test_a_banned_name_in_a_non_utf8_path_is_not_printed(repo, hashes_file):
    blob = hash_raw_object(repo, "blob", b"clean\n")
    git_bytes(
        repo,
        "update-index",
        "--add",
        "--index-info",
        stdin=b"100644 " + blob.encode() + b"\t" + TERM.encode() + b"\xe9.txt\n"
    )
    result = run_script(repo, hashes_file, "--staged")
    assert result.returncode == 1 and TERM not in result.stdout + result.stderr


def test_a_non_utf8_ref_name_is_a_finding(repo, hashes_file):
    seed(repo)
    head = git(repo, "rev-parse", "HEAD").strip()
    packed = repo / ".git" / "packed-refs"  # a loose ref would need a file system that stores non-UTF-8 names
    packed.write_bytes(b"# pack-refs with: peeled fully-peeled sorted \n" + head.encode() + b" refs/heads/caf\xe9\n")
    result = run_script(repo, hashes_file, "--history")
    assert result.returncode == 1 and "invalid UTF-8 in ref name" in result.stderr and "Traceback" not in result.stderr
