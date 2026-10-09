"""`fetch`: digests before extraction, hostile archives, the three archive shapes, and goetia's mandatory attestation."""

import dataclasses
import hashlib
import json
import tarfile
from pathlib import Path

import pytest
from archive_support import other, write_archive, zip_link
from binaries_support import (
    BUNDLE_ASSET,
    REPOS,
    VERSIONS,
    Upstream,
    member_content,
    sha256,
    tool_assets,
)

from ctl import download
from ctl.archive import ArchiveFormat
from ctl.binaries import Pin, bundle_for, load_lock, pins_for, refresh
from sigstore.verify import Verifier

from ctl.download import Fetcher, TrustLevel, fetch, read_digests, record_digests
from ctl.errors import AttestationError, BinariesError, UpstreamUnavailable

SHAPES = [("frp", "linux-x86_64"), ("goetia", "linux-x86_64"), ("frp", "windows-x86_64"), ("goetia", "windows-x86_64")]


class Attestations:
    """Stands in for Sigstore, recording what it was asked to vouch for; `reject` makes it refuse."""

    def __init__(self, reject: bool = False) -> None:
        self.reject = reject
        self.calls: list[tuple[str, bytes, download.IdentityPolicy]] = []

    def __call__(self, artifact: Path, bundle: Path, policy: download.IdentityPolicy) -> None:
        self.calls.append((hashlib.sha256(artifact.read_bytes()).hexdigest(), bundle.read_bytes(), policy))
        if self.reject:
            raise AttestationError("refused by the test")


@pytest.fixture
def lock(generated_lock_path):
    return load_lock(generated_lock_path)


@pytest.fixture
def served(published, lock):
    """The requests the asset host and the API have received since the lock was generated."""
    mark = len(published.requests)
    return lambda: published.requests[mark:]


@pytest.fixture
def dest(tmp_path) -> Path:
    path = tmp_path / "bin"
    path.mkdir()
    return path


@pytest.fixture
def attest() -> Attestations:
    return Attestations()


@pytest.fixture
def extractions(monkeypatch) -> list[Path]:
    """The target of every extraction, recorded as it happens."""
    seen: list[Path] = []
    real = download.extract_member

    def spy(path, fmt, member, target):
        seen.append(target)
        return real(path, fmt, member, target)

    monkeypatch.setattr(download, "extract_member", spy)
    return seen


def the_pin(lock, tool: str, platform: str, binary: str | None = None) -> Pin:
    pins = pins_for(lock, tool, platform)
    return next(p for p in pins if binary is None or p.install_name.removesuffix(".exe") == binary)


def the_bundle(lock) -> Pin:
    bundle = bundle_for(lock, "goetia")
    assert bundle is not None
    return bundle


def tampered() -> Upstream:
    """Every asset served at its usual URL with different bytes."""
    upstream = Upstream()
    for tool, version in VERSIONS.items():
        upstream.add_tool(tool, version, generation="b")
    return upstream


def serve(upstream: Upstream, name: str, body: bytes, tool: str = "frp") -> str:
    upstream.add_release(REPOS[tool], f"v{VERSIONS[tool]}", {name: body})
    return upstream.asset_url(REPOS[tool], f"v{VERSIONS[tool]}", name)


def hostile_pin(upstream: Upstream, name: str, body: bytes, fmt: ArchiveFormat, member: str) -> Pin:
    url = serve(upstream, name, body)
    return Pin("frp", VERSIONS["frp"], url, sha256(body), "0" * 64, fmt, member, "frpc")


# Digests ==============================================================================================================


def test_fetch_verifies_the_asset_digest_before_extracting(lock, dest, extractions):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with pytest.raises(BinariesError, match="sha256"):
        fetch(pin, dest, transport=tampered().transport)
    assert list(dest.iterdir()) == []
    assert extractions == []


def test_fetch_verifies_the_member_digest_after_extracting(published, lock, dest, extractions):
    pin = dataclasses.replace(the_pin(lock, "frp", "linux-x86_64", "frpc"), member_sha256="0" * 64)
    with pytest.raises(BinariesError, match="member"):
        fetch(pin, dest, transport=published.transport)
    assert extractions
    assert list(dest.iterdir()) == []


def test_a_bare_binary_with_a_wrong_digest_leaves_no_partial_file(lock, dest):
    pin = the_pin(lock, "websocat", "linux-x86_64")
    with pytest.raises(BinariesError, match="sha256"):
        fetch(pin, dest, transport=tampered().transport)
    assert list(dest.iterdir()) == []


def test_a_failed_download_leaves_the_destination_untouched(lock, dest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with pytest.raises(UpstreamUnavailable):
        fetch(pin, dest, transport=Upstream().transport)  # serves nothing: every asset is a 404
    assert list(dest.iterdir()) == []


def test_fetch_replaces_an_existing_binary_and_touches_nothing_else(published, lock, dest):
    (dest / "frpc").write_bytes(b"old")
    (dest / "frps").write_bytes(b"neighbour")
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    path = fetch(pin, dest, transport=published.transport).path
    assert path == dest / "frpc"
    assert path.read_bytes() == member_content("frp", VERSIONS["frp"], "linux-x86_64", "frpc")
    assert (dest / "frps").read_bytes() == b"neighbour"
    assert sorted(p.name for p in dest.iterdir()) == ["frpc", "frps"]


def test_fetch_needs_an_existing_destination_directory(published, lock, tmp_path):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with pytest.raises(BinariesError, match="directory"):
        fetch(pin, tmp_path / "missing", transport=published.transport)


@pytest.mark.parametrize("install_name", ["../frpc", "sub/frpc", "", ".."])
def test_fetch_refuses_an_install_name_that_is_not_a_bare_file_name(published, lock, dest, install_name):
    pin = dataclasses.replace(the_pin(lock, "frp", "linux-x86_64", "frpc"), install_name=install_name)
    with pytest.raises(BinariesError, match="install name"):
        fetch(pin, dest, transport=published.transport)
    assert list(dest.iterdir()) == []


# The three archive shapes =============================================================================================


@pytest.mark.parametrize(("tool", "platform"), SHAPES)
def test_fetch_extracts_the_named_member_from_each_archive_format(published, lock, dest, attest, tool, platform):
    for pin in pins_for(lock, tool, platform):
        path = fetch(pin, dest, bundle=bundle_for(lock, tool), transport=published.transport, attest=attest).path
        binary = pin.install_name.removesuffix(".exe")
        assert path == dest / pin.install_name
        assert path.read_bytes() == member_content(tool, VERSIONS[tool], platform, binary)


def test_fetch_extracts_a_member_from_under_a_top_level_directory(published, lock, dest, attest):
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    assert pin.archive_member == "goetia-x86_64-unknown-linux-musl/goetia"
    path = fetch(pin, dest, bundle=the_bundle(lock), transport=published.transport, attest=attest).path
    assert path.read_bytes() == member_content("goetia", VERSIONS["goetia"], "linux-x86_64", "goetia")
    assert [p.name for p in dest.iterdir()] == ["goetia"]


@pytest.mark.parametrize(
    ("fmt", "served_as"),
    [(ArchiveFormat.ZIP, "frp.tar.gz"), (ArchiveFormat.TAR_GZ, "frp.zip"), (ArchiveFormat.TAR_XZ, "frp.tar.gz")],
)
def test_fetch_dispatches_on_the_recorded_format_and_not_the_url_extension(tmp_path, dest, fmt, served_as):
    body = write_archive(tmp_path / "source", fmt, [("top/frpc", b"payload")]).read_bytes()
    upstream = Upstream()
    url = serve(upstream, served_as, body)
    pin = Pin("frp", VERSIONS["frp"], url, sha256(body), sha256(b"payload"), fmt, "top/frpc", "frpc")
    assert fetch(pin, dest, transport=upstream.transport).path.read_bytes() == b"payload"


def test_a_bare_binary_needs_no_extraction(published, lock, dest, extractions):
    pin = the_pin(lock, "websocat", "linux-x86_64")
    path = fetch(pin, dest, transport=published.transport).path
    assert path.read_bytes() == member_content("websocat", VERSIONS["websocat"], "linux-x86_64", "websocat")
    assert extractions == []


def test_one_archive_is_downloaded_once_for_both_of_its_binaries(published, lock, dest, served):
    with Fetcher(transport=published.transport) as fetcher:
        for pin in pins_for(lock, "frp", "linux-x86_64"):
            fetcher.fetch(pin, dest)
    downloads = [r for r in served() if r.path.endswith(".tar.gz")]
    assert len(downloads) == 1
    assert sorted(p.name for p in dest.iterdir()) == ["frpc", "frps"]


# Hostile archives =====================================================================================================

ARCHIVES = [ArchiveFormat.TAR_GZ, ArchiveFormat.TAR_XZ, ArchiveFormat.ZIP]


@pytest.mark.parametrize("fmt", ARCHIVES)
@pytest.mark.parametrize("where", ["entry", "member"])
def test_archive_member_traversal_is_rejected(tmp_path, dest, fmt, where):
    entries = [("top/frpc", b"payload"), ("../../evil", b"escaped")]
    body = write_archive(tmp_path / "evil-archive", fmt, entries).read_bytes()
    upstream = Upstream()
    member = "../../evil" if where == "member" else "top/frpc"
    pin = hostile_pin(upstream, "frp.bin", body, fmt, member)
    with pytest.raises(BinariesError, match="unsafe"):
        fetch(pin, dest, transport=upstream.transport)
    assert list(dest.iterdir()) == []
    assert not (tmp_path / "evil").exists()
    assert not (tmp_path.parent / "evil").exists()


@pytest.mark.parametrize("fmt", ARCHIVES)
def test_archive_symlink_member_is_rejected(tmp_path, dest, fmt):
    """`bin -> <dir>` then `bin/passwd`: no `..` anywhere, so a lexical containment check passes it."""
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    link = zip_link("bin", str(sentinel)) if fmt is ArchiveFormat.ZIP else other("bin", tarfile.SYMTYPE, str(sentinel))
    body = write_archive(tmp_path / "evil-archive", fmt, [link, ("bin/passwd", b"escaped")]).read_bytes()
    upstream = Upstream()
    pin = hostile_pin(upstream, "frp.bin", body, fmt, "bin/passwd")
    with pytest.raises(BinariesError, match="link"):
        fetch(pin, dest, transport=upstream.transport)
    assert list(dest.iterdir()) == []
    assert list(sentinel.iterdir()) == []


def test_the_extraction_target_is_a_freshly_created_directory(published, lock, dest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    parents = []
    real = download.extract_member

    def inspect(path, fmt, member, target):
        parent = target.parent
        parents.append((parent, parent.is_dir() and not parent.is_symlink(), list(parent.iterdir())))
        return real(path, fmt, member, target)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(download, "extract_member", inspect)
        fetch(pin, dest, transport=published.transport)
        fetch(pin, dest, transport=published.transport)
    assert len(parents) == 2
    for parent, is_real_directory, contents in parents:
        assert is_real_directory
        assert contents == []
        assert parent != dest and dest not in parent.parents
    assert parents[0][0] != parents[1][0]


# Attestation ==========================================================================================================


def test_the_bundle_is_pinned_in_the_lock_and_fetch_makes_no_live_api_call(published, lock, dest, attest, served):
    for repo in REPOS.values():
        published.fail(repo, 500)  # the releases API is down; only the asset host answers
    bundle = the_bundle(lock)
    for pin in pins_for(lock, "goetia", "linux-x86_64"):
        fetch(pin, dest, bundle=bundle, transport=published.transport, attest=attest)
    assert served()
    assert not [r for r in served() if r.path.startswith("/repos/")]
    assert attest.calls


def test_goetia_without_a_bundle_is_an_error(published, lock, dest, served):
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    with pytest.raises(BinariesError, match="attestation"):
        fetch(pin, dest, transport=published.transport)
    assert list(dest.iterdir()) == []
    assert served() == []


def test_a_tool_that_publishes_no_attestation_refuses_a_bundle(published, lock, dest, attest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with pytest.raises(BinariesError, match="publishes no attestation"):
        fetch(pin, dest, bundle=the_bundle(lock), transport=published.transport, attest=attest)
    assert attest.calls == []


def test_a_bundle_from_another_release_is_refused(published, lock, dest, attest):
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    bundle = dataclasses.replace(the_bundle(lock), version="9.9.9")
    with pytest.raises(BinariesError, match="9.9.9"):
        fetch(pin, dest, bundle=bundle, transport=published.transport, attest=attest)
    assert list(dest.iterdir()) == []


def test_one_bundle_is_downloaded_once_and_vouches_for_every_goetia_archive(published, lock, dest, attest, served):
    bundle = the_bundle(lock)
    with Fetcher(transport=published.transport, attest=attest) as fetcher:
        for platform in ("linux-x86_64", "macos-aarch64"):
            for pin in pins_for(lock, "goetia", platform):
                fetcher.fetch(pin, dest, bundle)
    assert len([r for r in served() if r.path.endswith(BUNDLE_ASSET)]) == 1
    expected = {pins_for(lock, "goetia", p)[0].asset_sha256 for p in ("linux-x86_64", "macos-aarch64")}
    assert {digest for digest, _, _ in attest.calls} == expected
    assert len(attest.calls) == 2  # once per archive, not once per binary
    assert {raw for _, raw, _ in attest.calls} == {tool_assets("goetia", VERSIONS["goetia"])[BUNDLE_ASSET]}
    assert {policy for _, _, policy in attest.calls} == {download.GOETIA_IDENTITY}


def test_a_refused_attestation_installs_nothing_and_extracts_nothing(published, lock, dest, extractions):
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    with pytest.raises(AttestationError):
        fetch(pin, dest, bundle=the_bundle(lock), transport=published.transport, attest=Attestations(True))
    assert list(dest.iterdir()) == []
    assert extractions == []


def test_the_default_attestation_is_a_real_verification(published, lock, dest, extractions, verifier):
    """The fixture bundle is not a Sigstore bundle at all, so only a real verifier can be the one refusing it."""
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    with pytest.raises(AttestationError, match="bundle"):
        fetch(pin, dest, bundle=the_bundle(lock), transport=published.transport, verifier=verifier)
    assert list(dest.iterdir()) == []
    assert extractions == []


def test_a_default_fetcher_verifies_against_the_production_trust_root(published, lock, dest, verifier, monkeypatch):
    asked = []
    monkeypatch.setattr(Verifier, "production", classmethod(lambda cls: asked.append(cls) or verifier))
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    with pytest.raises(AttestationError):
        fetch(pin, dest, bundle=the_bundle(lock), transport=published.transport)
    assert asked == [Verifier]


def test_the_production_trust_root_is_obtained_once_per_fetcher(published, lock, dest, verifier, monkeypatch):
    asked = []
    monkeypatch.setattr(Verifier, "production", classmethod(lambda cls: asked.append(cls) or verifier))
    with Fetcher(transport=published.transport) as fetcher:
        for pin in pins_for(lock, "goetia", "linux-x86_64"):
            with pytest.raises(AttestationError):
                fetcher.fetch(pin, dest, the_bundle(lock))
    assert len(asked) == 1


def test_a_tool_with_a_bundle_but_no_identity_policy_is_an_error(published, lock, dest, attest, monkeypatch):
    monkeypatch.setattr(download, "POLICIES", {})
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    with pytest.raises(BinariesError, match="identity policy"):
        fetch(pin, dest, bundle=the_bundle(lock), transport=published.transport, attest=attest)
    assert list(dest.iterdir()) == []


def test_a_bundle_whose_digest_is_wrong_is_refused_before_it_is_read(published, lock, dest, attest):
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    bundle = dataclasses.replace(the_bundle(lock), asset_sha256="0" * 64, member_sha256="0" * 64)
    with pytest.raises(BinariesError, match="sha256"):
        fetch(pin, dest, bundle=bundle, transport=published.transport, attest=attest)
    assert attest.calls == []
    assert list(dest.iterdir()) == []


# Trust levels =========================================================================================================


def test_a_digest_pinned_tool_is_reported_digest_only(published, lock, dest):
    for tool, platform in [("frp", "linux-x86_64"), ("websocat", "linux-x86_64")]:
        for pin in pins_for(lock, tool, platform):
            assert fetch(pin, dest, transport=published.transport).trust is TrustLevel.DIGEST_ONLY


def test_goetia_is_reported_attested_for_every_binary_even_when_the_attestation_was_cached(
    published, lock, dest, attest
):
    with Fetcher(transport=published.transport, attest=attest) as fetcher:
        levels = [fetcher.fetch(pin, dest, the_bundle(lock)).trust for pin in pins_for(lock, "goetia", "linux-x86_64")]
    assert levels == [TrustLevel.ATTESTED, TrustLevel.ATTESTED]
    assert len(attest.calls) == 1


def test_trust_levels_print_as_words():
    assert [str(TrustLevel.DIGEST_ONLY), str(TrustLevel.ATTESTED)] == ["digest-only", "attested"]


# The fetcher and its destination ======================================================================================


def test_a_fetcher_used_without_with_says_so(published, lock, dest):
    fetcher = Fetcher(transport=published.transport)
    with pytest.raises(RuntimeError, match="with"):
        fetcher.fetch(the_pin(lock, "frp", "linux-x86_64", "frpc"), dest)


def test_a_cached_download_is_keyed_by_its_pinned_digest_as_well_as_its_url(published, lock, dest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with Fetcher(transport=published.transport) as fetcher:
        fetcher.fetch(pin, dest)
        with pytest.raises(BinariesError, match="sha256"):
            fetcher.fetch(dataclasses.replace(pin, asset_sha256="0" * 64), dest)


# Asset selection ======================================================================================================


def test_release_assets_are_selected_by_name(generated_lock_path, dest, attest):
    """A release with extra and reordered assets yields the same lock, and its pins fetch the same files."""
    reordered = Upstream()
    for tool, version in VERSIONS.items():
        assets = tool_assets(tool, version)
        decoys = {
            "SOURCE.tar.gz": b"source", f"{next(iter(assets))}.sha256": b"decoy", "goetia.sigstore.json.bak": b"decoy"
        }
        reordered.add_release(REPOS[tool], f"v{version}", {**decoys, **dict(reversed(list(assets.items())))})
    before = generated_lock_path.read_text()
    refresh(generated_lock_path, None, transport=reordered.transport)
    assert generated_lock_path.read_text() == before
    lock = load_lock(generated_lock_path)
    pin = the_pin(lock, "goetia", "linux-x86_64", "goetia")
    fetched = fetch(pin, dest, bundle=the_bundle(lock), transport=reordered.transport, attest=attest).path
    assert fetched.read_bytes() == member_content("goetia", VERSIONS["goetia"], "linux-x86_64", "goetia")


# Recorded digests =====================================================================================================


def test_record_digests_writes_member_hashes_and_read_digests_round_trips(lock, dest):
    pins = [*pins_for(lock, "frp", "linux-x86_64"), *pins_for(lock, "websocat", "linux-x86_64")]
    record_digests(dest, pins)
    expected = {p.install_name: p.member_sha256 for p in pins}
    assert read_digests(dest) == expected
    assert json.loads((dest / ".digests.json").read_text()) == expected
    assert list(p.name for p in dest.iterdir()) == [".digests.json"]


def test_recorded_digests_are_member_hashes_and_never_asset_hashes(lock, dest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    record_digests(dest, [pin])
    assert pin.asset_sha256 != pin.member_sha256
    assert read_digests(dest) == {"frpc": pin.member_sha256}


def test_record_digests_replaces_the_previous_record(lock, dest):
    record_digests(dest, pins_for(lock, "frp", "linux-x86_64"))
    record_digests(dest, [the_pin(lock, "websocat", "linux-x86_64")])
    assert set(read_digests(dest)) == {"websocat"}


def test_two_pins_for_one_name_with_different_digests_are_refused(lock, dest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with pytest.raises(BinariesError, match="frpc"):
        record_digests(dest, [pin, dataclasses.replace(pin, member_sha256="1" * 64)])
    assert list(dest.iterdir()) == []


def test_reading_digests_from_a_bin_with_no_record_is_empty(dest):
    assert read_digests(dest) == {}


@pytest.mark.parametrize(
    "text",
    [
        "", "{", "[]", '{"frpc": 1}', '{"frpc": "nothex"}', '{"frpc": "' + "A" * 64 + '"}',
        '{"a/b": "' + "a" * 64 + '"}', '{".": "' + "a" * 64 + '"}', '{"..": "' + "a" * 64 + '"}',
        '{"": "' + "a" * 64 + '"}', '{"frpc": "' + "a" * 64 + '", "frpc": "' + "b" * 64 + '"}'
    ],
)
def test_a_malformed_digest_record_is_an_error_and_never_empty(dest, text):
    (dest / ".digests.json").write_text(text)
    with pytest.raises(BinariesError, match="digests"):
        read_digests(dest)


def test_record_digests_records_the_inputs_beside_the_binaries(lock, dest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    record_digests(dest, [pin], {"token": "a" * 64, "frpc.toml": "b" * 64})
    assert read_digests(dest) == {"frpc": pin.member_sha256, "token": "a" * 64, "frpc.toml": "b" * 64}


@pytest.mark.parametrize(("name", "digest"), [("frpc", "a" * 64), ("secrets/token", "a" * 64), ("..", "a" * 64),
                                              ("token", "not-hex")])
def test_an_input_that_collides_with_a_binary_or_is_malformed_is_refused(lock, dest, name, digest):
    pin = the_pin(lock, "frp", "linux-x86_64", "frpc")
    with pytest.raises(BinariesError, match="plain name"):
        record_digests(dest, [pin], {name: digest})
    assert list(dest.iterdir()) == []
