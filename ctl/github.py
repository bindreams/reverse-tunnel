# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Read-only access to GitHub release metadata and public asset downloads."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

import httpx

from ctl.errors import BinariesError, UpstreamUnavailable

GITHUB_API = "https://api.github.com"
SHA256_DIGEST = re.compile(r"sha256:([0-9a-f]{64})", re.ASCII)
# external-bound: GitHub, or the host serving a release asset, answering a request. Per socket operation, not total.
NETWORK_TIMEOUT = httpx.Timeout(60.0)


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    digest: str | None


@dataclass(frozen=True)
class Release:
    tag: str
    assets: tuple[Asset, ...]
    prerelease: bool


def api_client(token: str | None, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """A client for the releases API; the only one that ever carries `token`."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(
        base_url=GITHUB_API,
        headers=headers,
        timeout=NETWORK_TIMEOUT,
        follow_redirects=True,
        transport=transport,
    )


def download_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    """A client for asset downloads. Credential-free: assets are public and their host is not the API."""
    return httpx.Client(timeout=NETWORK_TIMEOUT, follow_redirects=True, transport=transport)


def release_by_tag(client: httpx.Client, repo: str, tag: str) -> Release | None:
    """The published release tagged `tag`, or `None` if there is none (a 404, or a draft).

    One request returns one release, so a release published or deleted meanwhile cannot make a listing skip or repeat it.
    """
    what = f"GET {repo} release {tag}"
    try:
        response = client.get(f"/repos/{repo}/releases/tags/{quote(tag, safe='')}")
    except httpx.HTTPError as exc:
        raise UpstreamUnavailable(f"{what}: {type(exc).__name__}: {exc}") from exc
    if response.status_code == 404:
        return None
    if response.is_error:
        raise UpstreamUnavailable(f"{what}: HTTP {response.status_code}{_rate_limit_hint(response)}")
    try:
        entry = response.json()
    except ValueError as exc:
        raise UpstreamUnavailable(f"{what}: body is not JSON") from exc
    if not isinstance(entry, dict):
        raise UpstreamUnavailable(f"{what}: unexpected response shape")
    draft, prerelease = entry.get("draft"), entry.get("prerelease")
    if not isinstance(draft, bool) or not isinstance(prerelease, bool):
        raise UpstreamUnavailable(f"{what}: the release has no boolean `draft` and `prerelease` fields")
    return None if draft else _parse_release(entry, prerelease, what)


def _rate_limit_hint(response: httpx.Response) -> str:
    limited = response.status_code == 429 or response.headers.get("x-ratelimit-remaining") == "0"
    return " (rate limited; set GITHUB_TOKEN to authenticate)" if limited else ""


def _parse_release(entry: dict, prerelease: bool, what: str) -> Release:
    tag, assets = entry.get("tag_name"), entry.get("assets")
    if not isinstance(tag, str) or not isinstance(assets, list):
        raise UpstreamUnavailable(f"{what}: the release lacks `tag_name` or `assets`")
    parsed = []
    for asset in assets:
        name, url = (asset.get("name"), asset.get("browser_download_url")) if isinstance(asset, dict) else (None, None)
        if not isinstance(name, str) or not isinstance(url, str):
            raise UpstreamUnavailable(f"{what}: an asset has no `name` or download url")
        digest = asset.get("digest")
        parsed.append(Asset(name, url, digest if isinstance(digest, str) else None))
    return Release(tag, tuple(parsed), prerelease)


def find_release(client: httpx.Client, repo: str, version: str) -> Release | None:
    """The published, non-prerelease release for `version`, tagged `v<version>` or `<version>`; `None` if neither exists."""
    found = [r for tag in dict.fromkeys((f"v{version}", version)) if (r := release_by_tag(client, repo, tag))]
    if len(found) > 1:
        raise BinariesError(f"{repo}: more than one published release matches {version}: {[r.tag for r in found]}")
    if found and found[0].prerelease:
        raise BinariesError(f"{repo}: release {found[0].tag} is a prerelease; refusing to pin it")
    return found[0] if found else None


def asset_named(release: Release, name: str, context: str) -> Asset:
    """The one asset called exactly `name`; never chosen by position, count or extension."""
    matches = [a for a in release.assets if a.name == name]
    if not matches:
        raise BinariesError(f"{context}: release {release.tag} has no asset named {name}")
    if len(matches) > 1:
        raise BinariesError(f"{context}: release {release.tag} lists more than one asset named {name}")
    return matches[0]


def sha256_of(asset: Asset, context: str) -> str:
    """The digest GitHub advertises for `asset`. A missing or unusable one is an error, never an empty pin."""
    match = SHA256_DIGEST.fullmatch(asset.digest or "")
    if match is None:
        raise BinariesError(
            f"{context}: asset {asset.name} has no usable sha256 digest (GitHub reports {asset.digest!r})"
        )
    return match.group(1)


def download(client: httpx.Client, url: str, dest: Path) -> str:
    """Stream `url` to `dest` and return the sha256 of what arrived."""
    digest = hashlib.sha256()
    try:
        with client.stream("GET", url) as response, dest.open("wb") as out:
            if response.is_error:
                raise UpstreamUnavailable(f"GET {url}: HTTP {response.status_code}")
            for chunk in response.iter_bytes():
                digest.update(chunk)
                out.write(chunk)
    except httpx.HTTPError as exc:
        raise UpstreamUnavailable(f"GET {url}: {type(exc).__name__}: {exc}") from exc
    return digest.hexdigest()
