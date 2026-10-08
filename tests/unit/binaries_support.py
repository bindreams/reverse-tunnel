"""A local stand-in for the GitHub releases API and its asset host, plus release content built to the measured shapes.

Asset names and archive layouts are written out here independently of `ctl.binaries`, so a wrong assumption in the
implementation fails against this oracle rather than agreeing with itself.
"""

import gzip
import hashlib
import io
import json
import tarfile
import zipfile

import httpx
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qs

PLATFORMS = ("linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64", "windows-x86_64")
REPOS = {"frp": "fatedier/frp", "websocat": "vi/websocat", "goetia": "bindreams/goetia"}
VERSIONS = {"frp": "0.71.0", "websocat": "1.14.1", "goetia": "0.1.0"}
BINARIES = {"frp": ("frpc", "frps"), "websocat": ("websocat", ), "goetia": ("goetia", "goetia-shim")}
BUNDLE_ASSET = "goetia.sigstore.json"

FRP_TARGETS = {
    "linux-x86_64": "linux_amd64",
    "linux-aarch64": "linux_arm64",
    "macos-x86_64": "darwin_amd64",
    "macos-aarch64": "darwin_arm64",
    "windows-x86_64": "windows_amd64",
}
GOETIA_TRIPLES = {
    "linux-x86_64": "x86_64-unknown-linux-musl",
    "linux-aarch64": "aarch64-unknown-linux-musl",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-aarch64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
}
WEBSOCAT_TRIPLES = {
    "linux-x86_64": "x86_64-unknown-linux-musl",
    "linux-aarch64": "aarch64-unknown-linux-musl",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-aarch64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-gnu",
}

SEED_LOCK = """\
# Pinned third-party binaries. Regenerate digests with `uv run -m ctl pin --update`.

[frp]
# renovate: datasource=github-releases depName=fatedier/frp
version = "0.71.0"

[websocat]
# renovate: datasource=github-releases depName=vi/websocat
version = "1.14.1"

[goetia]
# renovate: datasource=github-releases depName=bindreams/goetia
version = "0.1.0"
"""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Release content ======================================================================================================


def is_windows(platform: str) -> bool:
    return platform.startswith("windows")


def archive_format(tool: str, platform: str) -> str:
    if tool == "websocat":
        return "bare"
    if is_windows(platform):
        return "zip"
    return "tar.gz" if tool == "frp" else "tar.xz"


def asset_name(tool: str, version: str, platform: str) -> str:
    if tool == "frp":
        return f"frp_{version}_{FRP_TARGETS[platform]}.{archive_format(tool, platform)}"
    if tool == "goetia":
        return f"goetia-{GOETIA_TRIPLES[platform]}.{archive_format(tool, platform)}"
    return f"websocat.{WEBSOCAT_TRIPLES[platform]}" + (".exe" if is_windows(platform) else "")


def top_directory(tool: str, version: str, platform: str) -> str | None:
    if tool == "frp":
        return f"frp_{version}_{FRP_TARGETS[platform]}"
    if tool == "goetia":
        return f"goetia-{GOETIA_TRIPLES[platform]}"
    return None


def install_name(binary: str, platform: str) -> str:
    return binary + (".exe" if is_windows(platform) else "")


def member_path(tool: str, version: str, platform: str, binary: str) -> str:
    top = top_directory(tool, version, platform)
    name = install_name(binary, platform)
    return name if top is None else f"{top}/{name}"


def member_content(tool: str, version: str, platform: str, binary: str, generation: str = "a") -> bytes:
    return f"{tool} {version} {platform} {binary} generation {generation}\n".encode() * 8


def build_archive(fmt: str, members: Mapping[str, bytes], *, executable: bool = True) -> bytes:
    """An archive holding `members` (full in-archive path -> content); directories are implied, as in a zip.

    Byte-for-byte reproducible: no clock value reaches the archive, so equal inputs always hash equal.
    """
    buffer = io.BytesIO()
    if fmt == "zip":
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0)), data)
    else:
        mode: Literal["w:xz", "w"] = "w:xz" if fmt == "tar.xz" else "w"
        compressed = gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) if fmt == "tar.gz" else None
        with tarfile.open(fileobj=compressed or buffer, mode=mode) as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if executable else 0o644
                archive.addfile(info, io.BytesIO(data))
        if compressed:
            compressed.close()
    return buffer.getvalue()


def tool_assets(tool: str, version: str, generation: str = "a") -> dict[str, bytes]:
    """Every release asset the real release carries for `tool`, keyed by name."""
    assets: dict[str, bytes] = {}
    for platform in PLATFORMS:
        name = asset_name(tool, version, platform)
        members = {
            member_path(tool, version, platform, binary): member_content(tool, version, platform, binary, generation)
            for binary in BINARIES[tool]
        }
        if tool == "frp":
            top = top_directory(tool, version, platform)
            members[f"{top}/frpc.toml"] = b"# example config\n"
            members[f"{top}/LICENSE"] = b"license\n"
        if tool == "goetia":
            top = top_directory(tool, version, platform)
            members[f"{top}/README.md"] = b"readme\n"
            members[f"{top}/LICENSE.md"] = b"license\n"
        if tool == "websocat":
            assets[name] = member_content(tool, version, platform, "websocat", generation)
        else:
            assets[name] = build_archive(archive_format(tool, platform), members)
    if tool == "goetia":
        assets[BUNDLE_ASSET] = f'{{"bundle": "{version} {generation}"}}'.encode()
        assets["SHA256SUMS"] = b"unused\n"
    return assets


# Transport ============================================================================================================

API = "https://api.github.com"
ASSET_HOST = "https://assets.example.test"
DOWNLOADS = "/releases/download/"


@dataclass(frozen=True)
class Request:
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]


class Upstream:
    """An in-process stand-in for the releases API and the asset host, served through `httpx.MockTransport`.

    Answers `/repos/<owner>/<repo>/releases/tags/<tag>` and `/<owner>/<repo>/releases/download/<tag>/<name>` asset bodies. There is deliberately no
    release listing: a client that enumerates releases gets a 404. Unlike GitHub, the tag endpoint also serves drafts,
    so the client's own draft check is what the tests exercise. No sockets.
    """

    def __init__(self) -> None:
        self.transport = httpx.MockTransport(self._handle)
        self._releases: dict[str, list[dict]] = {}
        self._bodies: dict[str, bytes] = {}
        self._failures: dict[str, tuple[int, dict[str, str]]] = {}
        self._hangups: set[str] = set()
        self._requests: list[Request] = []

    # Content ----------------------------------------------------------------------------------------------------------

    def add_release(
        self,
        repo: str,
        tag: str,
        assets: Mapping[str, bytes],
        *,
        draft: bool = False,
        prerelease: bool = False,
        digests: Mapping[str, str | None] | None = None,
        served: Mapping[str, bytes] | None = None,
    ) -> None:
        """Add a release of `repo`.

        `digests` overrides the advertised digest of an asset (`None` omits it); `served` overrides the body.
        """
        digests = digests or {}
        served = served or {}
        listed = []
        for name, body in assets.items():
            path = f"/{repo}{DOWNLOADS}{tag}/{name}"
            self._bodies[path] = served.get(name, body)
            digest = digests[name] if name in digests else f"sha256:{sha256(body)}"
            listed.append({"name": name, "browser_download_url": ASSET_HOST + path, "digest": digest})
        self._releases.setdefault(repo, []).append({
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "assets": listed,
        })

    def add_tool(self, tool: str, version: str, generation: str = "a", **kwargs) -> None:
        self.add_release(REPOS[tool], f"v{version}", tool_assets(tool, version, generation), **kwargs)

    def duplicate_asset(self, repo: str, name: str) -> None:
        """List the asset `name` of the newest release of `repo` twice."""
        assets = self._releases[repo][0]["assets"]
        assets.append(next(a for a in assets if a["name"] == name))

    def fail(self, repo: str, status: int, headers: Mapping[str, str] | None = None) -> None:
        self._failures[repo] = (status, dict(headers or {}))

    def hang_up(self, repo: str) -> None:
        """Drop the connection without answering any request for the releases of `repo`."""
        self._hangups.add(repo)

    def clear(self) -> None:
        self._hangups.clear()
        self._releases.clear()
        self._bodies.clear()
        self._failures.clear()

    def asset_url(self, repo: str, tag: str, name: str) -> str:
        (release, ) = [r for r in self._releases[repo] if r["tag_name"] == tag and not r["draft"]]
        (asset, ) = [a for a in release["assets"] if a["name"] == name]
        return asset["browser_download_url"]

    @property
    def requests(self) -> list[Request]:
        return list(self._requests)

    # Handler ----------------------------------------------------------------------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        query = parse_qs(request.url.query.decode())
        self._requests.append(Request(path, query, {k.lower(): v for k, v in request.headers.items()}))
        parts = path.strip("/").split("/")
        if len(parts) == 6 and parts[0] == "repos" and parts[3:5] == ["releases", "tags"]:
            return self._release_by_tag(f"{parts[1]}/{parts[2]}", parts[5], request)
        if path in self._bodies:
            return httpx.Response(200, content=self._bodies[path])
        return httpx.Response(404, content=b"not found")

    def _release_by_tag(self, repo: str, tag: str, request: httpx.Request) -> httpx.Response:
        if repo in self._hangups:
            raise httpx.RemoteProtocolError("server disconnected without sending a response", request=request)
        if repo in self._failures:
            status, headers = self._failures[repo]
            return httpx.Response(status, headers=headers, json={"message": "failure"})
        tagged = [r for r in self._releases.get(repo, []) if r["tag_name"] == tag]
        if not tagged:
            return httpx.Response(404, json={"message": "Not Found"})
        # A published release wins over a draft that happens to share its tag.
        return httpx.Response(200, json=sorted(tagged, key=lambda r: r["draft"])[0])
