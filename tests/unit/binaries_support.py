"""A local stand-in for the GitHub releases API and its asset host, plus release content built to the measured shapes.

Asset names and archive layouts are written out here independently of `ctl.binaries`, so a wrong assumption in the
implementation fails against this oracle rather than agreeing with itself.
"""

import hashlib
import http.server
import io
import json
import tarfile
import threading
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qs, urlsplit

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
    """An archive holding `members` (full in-archive path -> content); directories are implied, as in a zip."""
    buffer = io.BytesIO()
    if fmt == "zip":
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in members.items():
                archive.writestr(name, data)
    else:
        mode: Literal["w:gz", "w:xz"] = "w:gz" if fmt == "tar.gz" else "w:xz"
        with tarfile.open(fileobj=buffer, mode=mode) as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755 if executable else 0o644
                archive.addfile(info, io.BytesIO(data))
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


# Server ===============================================================================================================


@dataclass(frozen=True)
class Request:
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]


class Upstream:
    """Serves `/repos/<owner>/<repo>/releases` (paginated, newest first) and `/dl/<id>/<name>` asset bodies."""

    def __init__(self, page_size: int = 100) -> None:
        self.page_size = page_size
        self._lock = threading.Lock()
        self._releases: dict[str, list[dict]] = {}
        self._bodies: dict[str, bytes] = {}
        self._failures: dict[str, tuple[int, dict[str, str]]] = {}
        self._hangups: set[str] = set()
        self._requests: list[Request] = []
        self._next_id = 0
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        # The interval only bounds how long `shutdown` takes to be noticed; it synchronises nothing.
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> "Upstream":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    # Content ----------------------------------------------------------------------------------------------------------

    def add_release(
        self,
        repo: str,
        tag: str,
        assets: Mapping[str, bytes],
        *,
        draft: bool = False,
        digests: Mapping[str, str | None] | None = None,
        served: Mapping[str, bytes] | None = None,
    ) -> None:
        """Append a release behind the ones already added, so call newest first.

        `digests` overrides the advertised digest of an asset (`None` omits it); `served` overrides the body.
        """
        digests = digests or {}
        served = served or {}
        with self._lock:
            self._next_id += 1
            release_id = self._next_id
            listed = []
            for name, body in assets.items():
                path = f"/dl/{release_id}/{name}"
                self._bodies[path] = served.get(name, body)
                digest = digests[name] if name in digests else f"sha256:{sha256(body)}"
                listed.append({"name": name, "browser_download_url": self.base_url + path, "digest": digest})
            self._releases.setdefault(repo, []).append({
                "tag_name": tag,
                "draft": draft,
                "prerelease": False,
                "assets": listed,
            })

    def add_tool(self, tool: str, version: str, generation: str = "a", **kwargs) -> None:
        self.add_release(REPOS[tool], f"v{version}", tool_assets(tool, version, generation), **kwargs)

    def duplicate_asset(self, repo: str, name: str) -> None:
        """List the asset `name` of the newest release of `repo` twice."""
        with self._lock:
            assets = self._releases[repo][0]["assets"]
            assets.append(next(a for a in assets if a["name"] == name))

    def fail(self, repo: str, status: int, headers: Mapping[str, str] | None = None) -> None:
        with self._lock:
            self._failures[repo] = (status, dict(headers or {}))

    def hang_up(self, repo: str) -> None:
        """Close the connection without answering any request for the releases of `repo`."""
        with self._lock:
            self._hangups.add(repo)

    def clear(self) -> None:
        with self._lock:
            self._hangups.clear()
            self._releases.clear()
            self._bodies.clear()
            self._failures.clear()

    def asset_url(self, repo: str, tag: str, name: str) -> str:
        with self._lock:
            (release, ) = [r for r in self._releases[repo] if r["tag_name"] == tag and not r["draft"]]
            (asset, ) = [a for a in release["assets"] if a["name"] == name]
            return asset["browser_download_url"]

    @property
    def requests(self) -> list[Request]:
        with self._lock:
            return list(self._requests)

    # Handler ----------------------------------------------------------------------------------------------------------

    def _handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        upstream = self

        class Handler(http.server.BaseHTTPRequestHandler):

            def do_GET(self) -> None:
                split = urlsplit(self.path)
                query = parse_qs(split.query)
                with upstream._lock:
                    upstream._requests.append(
                        Request(split.path, query, {k.lower(): v
                                                    for k, v in self.headers.items()})
                    )
                    reply = upstream._respond(split.path, query)
                if reply is None:
                    self.close_connection = True
                    return
                status, headers, body = reply
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        return Handler

    def _respond(self, path: str, query: dict[str, list[str]]) -> tuple[int, dict[str, str], bytes] | None:
        """Called with the lock held; `None` means hang up."""
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "repos" and parts[3] == "releases":
            repo = f"{parts[1]}/{parts[2]}"
            if repo in self._hangups:
                return None
            if repo in self._failures:
                status, headers = self._failures[repo]
                return status, headers, b'{"message": "failure"}'
            releases = self._releases.get(repo)
            if releases is None:
                return 404, {}, b'{"message": "Not Found"}'
            page = int(query.get("page", ["1"])[0])
            start = (page - 1) * self.page_size
            headers = {"Content-Type": "application/json"}
            if start + self.page_size < len(releases):
                headers["Link"] = f'<{self.base_url}/repos/{repo}/releases?per_page=100&page={page + 1}>; rel="next"'
            return 200, headers, json.dumps(releases[start:start + self.page_size]).encode()
        if path in self._bodies:
            return 200, {"Content-Type": "application/octet-stream"}, self._bodies[path]
        return 404, {}, b"not found"
