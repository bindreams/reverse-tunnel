import io
import tarfile
import tomllib
import zipfile
from pathlib import Path

import binaries_support
import pytest
from binaries_support import (
    BINARIES,
    BUNDLE_ASSET,
    DOWNLOADS,
    PLATFORMS,
    REPOS,
    SEED_LOCK,
    VERSIONS,
    Upstream,
    archive_format,
    asset_name,
    build_archive,
    member_content,
    member_path,
    sha256,
    tool_assets,
)

from ctl.binaries import PinDrift, bundle_for, compare_to_upstream, load_lock, pins_for, refresh
from ctl.errors import BinariesError, UpstreamUnavailable


def raw(lock_path: Path) -> dict:
    """The lock as plain TOML, for when a single-tool refresh leaves it incomplete."""
    return tomllib.loads(lock_path.read_text())


def run(lock_path: Path, upstream: Upstream, only=None, **kwargs) -> None:
    refresh(lock_path, only, transport=upstream.transport, **kwargs)


def tag_paths(tool: str) -> list[str]:
    """The two release lookups made for `tool` at its seed version, in order."""
    version = VERSIONS[tool]
    return [f"/repos/{REPOS[tool]}/releases/tags/v{version}", f"/repos/{REPOS[tool]}/releases/tags/{version}"]


def section(text: str, tool: str) -> str:
    """The lines of `text` belonging to `tool`: its `[tool]` header up to the next other tool."""
    lines = text.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.rstrip() == f"[{tool}]")
    end = next(
        (
            i for i in range(start + 1, len(lines)) if lines[i].startswith("[")
            and not lines[i].startswith(f"[[{tool}.") and not lines[i].startswith(f"[{tool}.")
        ),
        len(lines),
    )
    return "".join(lines[start:end])


def tar_with(entries: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        for info, data in entries:
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def file_entry(name: str, data: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def link_entry(name: str, target: str) -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info, None


def goetia_release_with(upstream: Upstream, name: str, body: bytes, **kwargs) -> None:
    """Publish goetia 0.1.0 with `name` replaced by `body`."""
    assets = tool_assets("goetia", "0.1.0")
    assets[name] = body
    upstream.add_release(REPOS["goetia"], "v0.1.0", assets, **kwargs)


# What gets pinned =====================================================================================================


def test_refresh_pins_every_tool_at_the_version_the_lock_names(published, lock_path):
    run(lock_path, published)
    lock = load_lock(lock_path)
    for tool, version in VERSIONS.items():
        for platform in PLATFORMS:
            name = asset_name(tool, version, platform)
            for pin, binary in zip(pins_for(lock, tool, platform), BINARIES[tool], strict=True):
                assert pin.version == version
                assert pin.url == published.asset_url(REPOS[tool], f"v{version}", name)
                assert pin.asset_sha256 == sha256(tool_assets(tool, version)[name])
                assert pin.archive_format == archive_format(tool, platform)
                assert pin.archive_member == (
                    None if tool == "websocat" else member_path(tool, version, platform, binary)
                )


def test_refresh_pins_the_bundle_as_a_platform_independent_asset(published, lock_path):
    run(lock_path, published)
    bundle = bundle_for(load_lock(lock_path), "goetia")
    assert bundle is not None
    assert bundle.url == published.asset_url(REPOS["goetia"], "v0.1.0", BUNDLE_ASSET)
    assert bundle.asset_sha256 == sha256(tool_assets("goetia", "0.1.0")[BUNDLE_ASSET])
    assert bundle.member_sha256 == bundle.asset_sha256


def test_refresh_records_the_extracted_member_digest(published, lock_path):
    run(lock_path, published)
    lock = load_lock(lock_path)
    for tool in ("frp", "goetia"):
        for platform in PLATFORMS:
            for pin, binary in zip(pins_for(lock, tool, platform), BINARIES[tool], strict=True):
                assert pin.member_sha256 == sha256(member_content(tool, pin.version, platform, binary))
                assert pin.member_sha256 != pin.asset_sha256
    (bare, ) = pins_for(lock, "websocat", "linux-x86_64")
    assert bare.member_sha256 == bare.asset_sha256 == sha256(
        member_content("websocat", "1.14.1", "linux-x86_64", "websocat")
    )


def test_refresh_is_idempotent(published, lock_path):
    run(lock_path, published)
    first = lock_path.read_bytes()
    run(lock_path, published)
    assert lock_path.read_bytes() == first


def test_refresh_downloads_each_asset_once(published, lock_path):
    run(lock_path, published)
    downloads = [r.path for r in published.requests if DOWNLOADS in r.path]
    assert len(downloads) == len(set(downloads)) == 5 + 5 + 5 + 1


def test_refresh_never_downloads_the_assets_it_does_not_pin(published, lock_path):
    run(lock_path, published)
    fetched = {r.path.rsplit("/", 1)[1] for r in published.requests if DOWNLOADS in r.path}
    assert "SHA256SUMS" not in fetched


# Preserving the file ==================================================================================================


def test_refresh_preserves_renovate_comments(published, lock_path):
    run(lock_path, published)
    text = lock_path.read_text()
    for tool in REPOS:
        assert f"# renovate: datasource=github-releases depName={REPOS[tool]}\nversion = " in text
    assert text.startswith(SEED_LOCK.split("\n\n")[0])


def test_refresh_only_touches_named_tools(published, lock_path):
    run(lock_path, published)
    before = lock_path.read_text()
    published.clear()
    for tool, version in VERSIONS.items():
        published.add_tool(tool, version, generation="b")
    run(lock_path, published, only=["websocat"])
    after = lock_path.read_text()
    assert section(after, "frp") == section(before, "frp")
    assert section(after, "goetia") == section(before, "goetia")
    assert section(after, "websocat") != section(before, "websocat")
    lock = load_lock(lock_path)
    assert pins_for(lock, "websocat", "linux-x86_64")[0].member_sha256 == sha256(
        member_content("websocat", "1.14.1", "linux-x86_64", "websocat", "b")
    )


def test_refresh_downloads_only_the_named_tools_assets(published, lock_path):
    run(lock_path, published)
    seen = len(published.requests)
    run(lock_path, published, only=["frp"])
    downloaded = {r.path.rsplit("/", 1)[1] for r in published.requests[seen:] if DOWNLOADS in r.path}
    assert downloaded == {asset_name("frp", "0.71.0", platform) for platform in PLATFORMS}
    looked_up = [r.path for r in published.requests[seen:] if r.path.startswith("/repos/")]
    assert looked_up == tag_paths("frp")


def test_refresh_replaces_stale_pins_instead_of_accumulating(published, lock_path):
    run(lock_path, published)
    published.clear()
    for tool, version in VERSIONS.items():
        published.add_tool(tool, version, generation="b")
    run(lock_path, published)
    lock = load_lock(lock_path)
    assert pins_for(lock, "frp", "linux-x86_64")[0].member_sha256 == sha256(
        member_content("frp", "0.71.0", "linux-x86_64", "frpc", "b")
    )
    assert lock_path.read_text().count("[[frp.linux-x86_64]]") == 2


def test_refresh_rewrites_nothing_when_it_fails(published, lock_path):
    run(lock_path, published)
    before = lock_path.read_bytes()
    published.clear()
    published.add_tool("frp", "0.71.0", generation="b")
    published.add_tool(
        "websocat", "1.14.1", generation="b", digests={asset_name("websocat", "1.14.1", "linux-x86_64"): None}
    )
    published.add_tool("goetia", "0.1.0", generation="b")
    with pytest.raises(BinariesError):
        run(lock_path, published)
    assert lock_path.read_bytes() == before


# Choosing the release =================================================================================================


def test_refresh_ignores_draft_releases(upstream, lock_path):
    upstream.add_release(REPOS["goetia"], "v0.2.0", tool_assets("goetia", "0.2.0"), draft=True)
    upstream.add_tool("goetia", "0.1.0")
    upstream.add_tool("frp", "0.71.0")
    upstream.add_tool("websocat", "1.14.1")
    run(lock_path, upstream)
    pin = pins_for(load_lock(lock_path), "goetia", "linux-x86_64")[0]
    assert pin.version == "0.1.0"
    assert "0.2.0" not in pin.url
    assert all("/v0.2.0" not in line for line in lock_path.read_text().splitlines())


def test_refresh_refuses_a_version_that_is_only_a_draft(upstream, lock_path):
    lock_path.write_text(SEED_LOCK.replace('version = "0.1.0"', 'version = "0.2.0"'))
    upstream.add_release(REPOS["goetia"], "v0.2.0", tool_assets("goetia", "0.2.0"), draft=True)
    upstream.add_tool("goetia", "0.1.0")
    upstream.add_tool("frp", "0.71.0")
    upstream.add_tool("websocat", "1.14.1")
    before = lock_path.read_bytes()
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream)
    assert "goetia" in str(raised.value)
    assert "0.2.0" in str(raised.value)
    assert lock_path.read_bytes() == before


def test_refresh_looks_the_release_up_by_tag_and_never_lists_releases(published, lock_path):
    published.add_release(REPOS["goetia"], "v0.3.0", tool_assets("goetia", "0.3.0"), draft=True)
    run(lock_path, published, only=["goetia"])
    paths = [r.path for r in published.requests if r.path.startswith("/repos/")]
    assert paths == tag_paths("goetia")
    assert all(not path.endswith("/releases") for path in paths)
    assert all(r.query == {} for r in published.requests if r.path.startswith("/repos/"))


def test_refresh_says_when_neither_tag_exists(upstream, lock_path):
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    assert "goetia" in str(raised.value)
    assert "0.1.0" in str(raised.value)
    assert [r.path for r in upstream.requests] == tag_paths("goetia")


def test_refresh_refuses_a_prerelease(upstream, lock_path):
    upstream.add_release(REPOS["goetia"], "v0.1.0", tool_assets("goetia", "0.1.0"), prerelease=True)
    before = lock_path.read_bytes()
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    assert "prerelease" in str(raised.value)
    assert "v0.1.0" in str(raised.value)
    assert lock_path.read_bytes() == before


def test_refresh_reports_an_unavailable_lookup_even_when_the_other_tag_is_absent(published, lock_path):
    published.fail(REPOS["websocat"], 503)
    with pytest.raises(UpstreamUnavailable, match="503"):
        run(lock_path, published, only=["websocat"])


def test_refresh_accepts_a_tag_without_the_v_prefix(upstream, lock_path):
    upstream.add_release(REPOS["websocat"], "1.14.1", tool_assets("websocat", "1.14.1"))
    run(lock_path, upstream, only=["websocat"])
    assert raw(lock_path)["websocat"]["linux-x86_64"][0]["url"].endswith(
        asset_name("websocat", "1.14.1", "linux-x86_64")
    )


def test_refresh_refuses_two_releases_for_one_version(upstream, lock_path):
    upstream.add_release(REPOS["websocat"], "v1.14.1", tool_assets("websocat", "1.14.1"))
    upstream.add_release(REPOS["websocat"], "1.14.1", tool_assets("websocat", "1.14.1"))
    with pytest.raises(BinariesError, match="more than one"):
        run(lock_path, upstream, only=["websocat"])


def test_refresh_rejects_an_unknown_tool(published, lock_path):
    with pytest.raises(BinariesError, match="nosuch"):
        run(lock_path, published, only=["nosuch"])


def test_refresh_needs_a_version_for_the_tool(published, lock_path):
    lock_path.write_text("[frp]\n")
    with pytest.raises(BinariesError, match="version"):
        run(lock_path, published, only=["frp"])


# Digests ==============================================================================================================


def test_refresh_takes_the_asset_digest_from_the_api_not_from_the_download(upstream, lock_path):
    name = asset_name("frp", "0.71.0", "linux-x86_64")
    upstream.add_tool("frp", "0.71.0", served={name: b"swapped in transit"})
    upstream.add_tool("websocat", "1.14.1")
    upstream.add_tool("goetia", "0.1.0")
    before = lock_path.read_bytes()
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream)
    message = str(raised.value)
    assert name in message
    assert sha256(b"swapped in transit") in message
    assert sha256(tool_assets("frp", "0.71.0")[name]) in message
    assert lock_path.read_bytes() == before


@pytest.mark.parametrize("digest", [None, "", "sha1:" + "a" * 40, "sha256:xyz", "sha256:" + "A" * 64])
def test_refresh_rejects_an_asset_without_a_usable_digest(upstream, lock_path, digest):
    name = asset_name("goetia", "0.1.0", "macos-aarch64")
    upstream.add_tool("goetia", "0.1.0", digests={name: digest})
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    message = str(raised.value)
    assert "goetia" in message
    assert "0.1.0" in message
    assert name in message


def test_refresh_rejects_a_bundle_without_a_digest(upstream, lock_path):
    upstream.add_tool("goetia", "0.1.0", digests={BUNDLE_ASSET: None})
    with pytest.raises(BinariesError, match=BUNDLE_ASSET):
        run(lock_path, upstream, only=["goetia"])


# Selecting assets =====================================================================================================


def test_refresh_selects_assets_by_name_not_position_or_count(published, lock_path):
    run(lock_path, published)
    expected = lock_path.read_text()
    published.clear()
    for tool, version in VERSIONS.items():
        assets = tool_assets(tool, version)
        reordered = dict(reversed(assets.items()))
        extra = {f"{name}.sha256": b"x"
                 for name in assets
                 } | {"source.tar.gz": b"src", "build-manifest.json": b"{}", "unrelated.tar.xz": b"x"}
        published.add_release(REPOS[tool], f"v{version}", extra | reordered)
    lock_path.write_text(SEED_LOCK)
    run(lock_path, published)
    urls_only = lambda text: [line for line in text.splitlines() if not line.startswith("url")]
    assert urls_only(lock_path.read_text()) == urls_only(expected)


def test_refresh_names_an_asset_the_release_lacks(upstream, lock_path):
    name = asset_name("goetia", "0.1.0", "windows-x86_64")
    assets = tool_assets("goetia", "0.1.0")
    del assets[name]
    upstream.add_release(REPOS["goetia"], "v0.1.0", assets)
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    assert name in str(raised.value)


def test_refresh_names_a_missing_bundle(upstream, lock_path):
    assets = tool_assets("goetia", "0.1.0")
    del assets[BUNDLE_ASSET]
    upstream.add_release(REPOS["goetia"], "v0.1.0", assets)
    with pytest.raises(BinariesError, match=BUNDLE_ASSET):
        run(lock_path, upstream, only=["goetia"])


def test_refresh_refuses_two_assets_with_one_name(upstream, lock_path):
    release_assets = tool_assets("websocat", "1.14.1")
    upstream.add_release(REPOS["websocat"], "v1.14.1", release_assets)
    upstream.duplicate_asset(REPOS["websocat"], asset_name("websocat", "1.14.1", "linux-x86_64"))
    with pytest.raises(BinariesError, match="more than one"):
        run(lock_path, upstream, only=["websocat"])


# Archive contents =====================================================================================================


def test_refresh_derives_the_member_from_the_archive_not_from_a_template(upstream, lock_path):
    name = asset_name("goetia", "0.1.0", "linux-x86_64")
    body = build_archive(
        "tar.xz", {
            "renamed-top/goetia": b"G",
            "renamed-top/goetia-shim": b"S",
            "renamed-top/README.md": b"r",
        }
    )
    goetia_release_with(upstream, name, body)
    run(lock_path, upstream, only=["goetia"])
    binary, shim = raw(lock_path)["goetia"]["linux-x86_64"]
    assert (binary["archive_member"], shim["archive_member"]) == ("renamed-top/goetia", "renamed-top/goetia-shim")
    assert binary["member_sha256"] == sha256(b"G")


@pytest.mark.parametrize(
    "members",
    [
        {"top/goetia": b"G"},
        {"top/goetia": b"G", "top/goetia-shim": b"S", "other/goetia": b"G2"},
        {"top/goetia": b"G", "top/goetia-shim/inner": b"S"},
    ],
    ids=["missing-shim", "ambiguous", "name-is-a-directory"],
)
def test_refresh_refuses_an_archive_without_exactly_one_regular_member_per_binary(upstream, lock_path, members):
    goetia_release_with(upstream, asset_name("goetia", "0.1.0", "linux-x86_64"), build_archive("tar.xz", members))
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    assert "goetia" in str(raised.value)


@pytest.mark.parametrize("fmt", ["tar.xz", "zip"])
def test_refresh_never_records_a_symlink_as_the_member(upstream, lock_path, fmt):
    name = asset_name("goetia", "0.1.0", "linux-x86_64")
    if fmt == "tar.xz":
        body = tar_with([link_entry("top/goetia", "/bin/sh"), file_entry("top/goetia-shim", b"S")])
    else:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            link = zipfile.ZipInfo("top/goetia")
            link.external_attr = (0o120777 << 16)
            archive.writestr(link, "/bin/sh")
            archive.writestr("top/goetia-shim", b"S")
        body = buffer.getvalue()
    goetia_release_with(upstream, name, body)
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    assert name in str(raised.value)


def test_refresh_refuses_an_archive_that_is_not_the_recorded_format(upstream, lock_path):
    name = asset_name("goetia", "0.1.0", "linux-x86_64")
    goetia_release_with(upstream, name, build_archive("tar.gz", {"top/goetia": b"G", "top/goetia-shim": b"S"}))
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["goetia"])
    assert name in str(raised.value)
    assert "tar.xz" in str(raised.value)


def test_refresh_refuses_an_unsafe_member_path(upstream, lock_path):
    name = asset_name("goetia", "0.1.0", "linux-x86_64")
    body = tar_with([file_entry("../../goetia", b"G"), file_entry("top/goetia-shim", b"S")])
    goetia_release_with(upstream, name, body)
    with pytest.raises(BinariesError, match="unsafe"):
        run(lock_path, upstream, only=["goetia"])


# Network ==============================================================================================================


def test_refresh_sends_the_token_to_the_api_and_never_to_an_asset_host(published, lock_path):
    run(lock_path, published, token="s3cret-token")
    for request in published.requests:
        if request.path.startswith("/repos/"):
            assert request.headers["authorization"] == "Bearer s3cret-token"
        else:
            assert "authorization" not in request.headers


def test_refresh_without_a_token_sends_no_credentials(published, lock_path):
    run(lock_path, published)
    assert all("authorization" not in r.headers for r in published.requests)


@pytest.mark.parametrize("status", [403, 429, 500, 502])
def test_refresh_reports_an_unavailable_api_with_its_status(upstream, lock_path, status):
    upstream.fail(REPOS["frp"], status, {"x-ratelimit-remaining": "0"})
    with pytest.raises(BinariesError, match=str(status)):
        run(lock_path, upstream, only=["frp"])


def test_the_token_is_not_in_any_error(upstream, lock_path):
    upstream.fail(REPOS["frp"], 500)
    with pytest.raises(BinariesError) as raised:
        run(lock_path, upstream, only=["frp"], token="s3cret-token")
    assert "s3cret-token" not in str(raised.value)
    assert "s3cret-token" not in repr(raised.value)


# Comparing to upstream ================================================================================================


def outcomes(results):
    return {(pin.tool, pin.install_name, pin.url.rsplit("/", 1)[1]): (drift, detail) for pin, drift, detail in results}


def test_compare_matches_a_freshly_refreshed_lock(published, generated_lock_path):
    results = compare_to_upstream(load_lock(generated_lock_path), transport=published.transport)
    assert {drift for _, drift, _ in results} == {PinDrift.MATCH}
    assert len(results) == (5 * 2) + 5 + (5 * 2) + 1


def test_compare_reports_match_mismatch_and_unavailable_distinctly(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    changed = asset_name("frp", "0.71.0", "linux-x86_64")
    published.clear()
    published.add_tool("frp", "0.71.0", digests={changed: "sha256:" + "0" * 64})
    published.add_tool("goetia", "0.1.0")
    published.fail(REPOS["websocat"], 503)
    results = compare_to_upstream(lock, transport=published.transport)
    by_tool: dict[str, set[PinDrift]] = {}
    for pin, drift, _ in results:
        by_tool.setdefault(pin.tool, set()).add(drift)
    assert by_tool["websocat"] == {PinDrift.UNAVAILABLE}
    assert by_tool["goetia"] == {PinDrift.MATCH}
    assert by_tool["frp"] == {PinDrift.MATCH, PinDrift.MISMATCH}
    for pin, drift, detail in results:
        if drift is PinDrift.MISMATCH:
            assert pin.url.endswith(changed)
            assert changed in detail
            assert "0" * 64 in detail
            assert pin.asset_sha256 in detail
        if drift is PinDrift.UNAVAILABLE:
            assert "503" in detail


@pytest.mark.parametrize("status", [403, 429, 500, 502])
def test_compare_never_reports_an_api_failure_as_a_mismatch(published, generated_lock_path, status):
    published.fail(REPOS["frp"], status)
    results = compare_to_upstream(load_lock(generated_lock_path), transport=published.transport)
    frp = [drift for pin, drift, _ in results if pin.tool == "frp"]
    assert frp and set(frp) == {PinDrift.UNAVAILABLE}
    assert PinDrift.MISMATCH not in {drift for _, drift, _ in results}


def test_compare_reports_a_dropped_connection_as_unavailable(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    for repo in REPOS.values():
        published.hang_up(repo)
    results = compare_to_upstream(lock, transport=published.transport)
    assert {drift for _, drift, _ in results} == {PinDrift.UNAVAILABLE}


def test_compare_reports_a_vanished_asset_digest_as_a_mismatch(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    name = asset_name("websocat", "1.14.1", "macos-x86_64")
    published.clear()
    published.add_tool("frp", "0.71.0")
    published.add_tool("goetia", "0.1.0")
    published.add_tool("websocat", "1.14.1", digests={name: None})
    results = outcomes(compare_to_upstream(lock, transport=published.transport))
    drift, detail = results[("websocat", "websocat", name)]
    assert drift is PinDrift.MISMATCH
    assert "digest" in detail


def test_compare_reports_a_withdrawn_asset_as_a_mismatch(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    name = asset_name("goetia", "0.1.0", "linux-x86_64")
    assets = tool_assets("goetia", "0.1.0")
    del assets[name]
    published.clear()
    published.add_tool("frp", "0.71.0")
    published.add_tool("websocat", "1.14.1")
    published.add_release(REPOS["goetia"], "v0.1.0", assets)
    drift, detail = outcomes(compare_to_upstream(lock, transport=published.transport))[("goetia", "goetia", name)]
    assert drift is PinDrift.MISMATCH
    assert name in detail


def test_compare_ignores_draft_releases(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    published.clear()
    published.add_tool("frp", "0.71.0")
    published.add_tool("websocat", "1.14.1")
    published.add_tool("goetia", "0.1.0", draft=True)
    results = compare_to_upstream(lock, transport=published.transport)
    goetia = {drift for pin, drift, _ in results if pin.tool == "goetia"}
    assert goetia == {PinDrift.MISMATCH}


def test_compare_checks_the_bundle(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    published.clear()
    published.add_tool("frp", "0.71.0")
    published.add_tool("websocat", "1.14.1")
    published.add_tool("goetia", "0.1.0", digests={BUNDLE_ASSET: "sha256:" + "1" * 64})
    results = outcomes(compare_to_upstream(lock, transport=published.transport))
    bundle = bundle_for(lock, "goetia")
    assert bundle is not None
    drift, _ = results[("goetia", bundle.install_name, BUNDLE_ASSET)]
    assert drift is PinDrift.MISMATCH


def test_compare_never_downloads_an_asset(published, generated_lock_path):
    before = len([r for r in published.requests if DOWNLOADS in r.path])
    compare_to_upstream(load_lock(generated_lock_path), transport=published.transport)
    assert len([r for r in published.requests if DOWNLOADS in r.path]) == before


def test_compare_looks_each_release_up_once_per_tool_by_tag(published, generated_lock_path):
    before = len(published.requests)
    compare_to_upstream(load_lock(generated_lock_path), transport=published.transport)
    paths = [r.path for r in published.requests[before:]]
    assert sorted(paths) == sorted(path for tool in REPOS for path in tag_paths(tool))


def test_compare_reports_a_release_missing_under_both_tags_as_a_mismatch(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    published.clear()
    published.add_tool("frp", "0.71.0")
    published.add_tool("websocat", "1.14.1")
    results = compare_to_upstream(lock, transport=published.transport)
    goetia = {(drift, detail) for pin, drift, detail in results if pin.tool == "goetia"}
    assert {drift for drift, _ in goetia} == {PinDrift.MISMATCH}
    assert all("no published release" in detail for _, detail in goetia)


def test_compare_does_not_call_a_half_answered_lookup_a_mismatch(published, generated_lock_path):
    published.fail(REPOS["goetia"], 500)
    results = compare_to_upstream(load_lock(generated_lock_path), transport=published.transport)
    assert {drift for pin, drift, _ in results if pin.tool == "goetia"} == {PinDrift.UNAVAILABLE}


def test_compare_reports_a_prerelease_as_a_mismatch(published, generated_lock_path):
    lock = load_lock(generated_lock_path)
    published.clear()
    published.add_tool("frp", "0.71.0")
    published.add_tool("websocat", "1.14.1")
    published.add_tool("goetia", "0.1.0", prerelease=True)
    results = compare_to_upstream(lock, transport=published.transport)
    goetia = [(drift, detail) for pin, drift, detail in results if pin.tool == "goetia"]
    assert {drift for drift, _ in goetia} == {PinDrift.MISMATCH}
    assert all("prerelease" in detail for _, detail in goetia)


def test_refresh_refuses_an_asset_the_api_places_on_another_host(lock_path, monkeypatch):
    monkeypatch.setattr(binaries_support, "ASSET_HOST", "https://evil.example.test")
    upstream = Upstream()
    upstream.add_tool("websocat", VERSIONS["websocat"])
    before = lock_path.read_text()
    with pytest.raises(BinariesError, match="https://github.com"):
        refresh(lock_path, ["websocat"], transport=upstream.transport)
    assert lock_path.read_text() == before
