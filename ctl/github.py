# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Read-only access to GitHub release metadata and public asset downloads."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import httpx

from ctl.errors import BinariesError, UpstreamUnavailable

GITHUB_API = "https://api.github.com"
PAGE_SIZE = 100  # GitHub's maximum; a page size is not a limit on how many pages are read.
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


def api_client(base_url: str, token: str | None) -> httpx.Client:
    """A client for the releases API; the only one that ever carries `token`."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=base_url, headers=headers, timeout=NETWORK_TIMEOUT, follow_redirects=True)


def download_client() -> httpx.Client:
    """A client for asset downloads. Credential-free: assets are public and their host is not the API."""
    return httpx.Client(timeout=NETWORK_TIMEOUT, follow_redirects=True)


def published_releases(client: httpx.Client, repo: str) -> list[Release]:
    """Every release of `repo` that is not a draft, following `Link: rel="next"` until the pages are exhausted."""
    releases: list[Release] = []
    url: str | None = f"/repos/{repo}/releases"
    params: dict[str, int] | None = {"per_page": PAGE_SIZE}
    while url is not None:
        try:
            response = client.get(url, params=params)
        except httpx.HTTPError as exc:
            raise UpstreamUnavailable(f"GET {repo} releases: {type(exc).__name__}: {exc}") from exc
        if response.is_error:
            raise UpstreamUnavailable(f"GET {repo} releases: HTTP {response.status_code}{_rate_limit_hint(response)}")
        releases.extend(_parse_page(response, repo))
        url = response.links.get("next", {}).get("url")
        params = None
    return releases


def _rate_limit_hint(response: httpx.Response) -> str:
    limited = response.status_code == 429 or response.headers.get("x-ratelimit-remaining") == "0"
    return " (rate limited; set GITHUB_TOKEN to authenticate)" if limited else ""


def _parse_page(response: httpx.Response, repo: str) -> list[Release]:
    try:
        page = response.json()
    except ValueError as exc:
        raise UpstreamUnavailable(f"GET {repo} releases: body is not JSON") from exc
    if not isinstance(page, list) or not all(isinstance(r, dict) for r in page):
        raise UpstreamUnavailable(f"GET {repo} releases: unexpected response shape")
    releases = []
    for entry in page:
        draft = entry.get("draft")
        if not isinstance(draft, bool):
            raise UpstreamUnavailable(f"GET {repo} releases: a release has no boolean `draft` field")
        if not draft:
            releases.append(_parse_release(entry, repo))
    return releases


def _parse_release(entry: dict, repo: str) -> Release:
    tag, assets = entry.get("tag_name"), entry.get("assets")
    if not isinstance(tag, str) or not isinstance(assets, list):
        raise UpstreamUnavailable(f"GET {repo} releases: a release lacks `tag_name` or `assets`")
    parsed = []
    for asset in assets:
        name, url = (asset.get("name"), asset.get("browser_download_url")) if isinstance(asset, dict) else (None, None)
        if not isinstance(name, str) or not isinstance(url, str):
            raise UpstreamUnavailable(f"GET {repo} releases: release {tag} has an asset without `name` or url")
        digest = asset.get("digest")
        parsed.append(Asset(name, url, digest if isinstance(digest, str) else None))
    return Release(tag, tuple(parsed))


def find_release(releases: list[Release], repo: str, version: str) -> Release | None:
    """The published release for `version`, tagged either `v<version>` or `<version>`."""
    matches = [r for r in releases if r.tag in (version, f"v{version}")]
    if len(matches) > 1:
        raise BinariesError(f"{repo}: more than one published release matches {version}: {[r.tag for r in matches]}")
    return matches[0] if matches else None


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
