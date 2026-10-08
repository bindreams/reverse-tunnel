# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The pinned third-party binaries: reading `binaries.lock.toml`, choosing a platform's pins, and refreshing them.

Each pin records the release asset's digest and the extracted binary's own digest, because a released archive and the
`frpc` inside it never share a hash. Asset digests come from GitHub's published `digest` field, never from hashing our
own download.
"""

import dataclasses
import enum
import os
import platform as host
import re
import stat
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import httpx
import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import Table

from ctl.archive import ArchiveFormat, hash_binary, is_safe_member
from ctl.config import Role
from ctl.errors import BinariesError, UpstreamUnavailable
from ctl.github import (
    api_client,
    asset_named,
    download,
    download_client,
    Release,
    find_release,
    sha256_of,
)

LOCK_PATH = Path(__file__).resolve().parent.parent / "binaries.lock.toml"
PLATFORMS = ("linux-x86_64", "linux-aarch64", "macos-x86_64", "macos-aarch64", "windows-x86_64")
# The platform-independent entry beside the five platforms; not a platform, so `pins_for` refuses it.
BUNDLE = "bundle"
HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)

# Tool table ===========================================================================================================


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    """Where a tool is published and what it installs. Everything per-release is read back from GitHub."""

    repo: str
    binaries: tuple[str, ...]
    asset: Callable[[str, str], str]  # (version, platform) -> exact release asset name
    format: Callable[[str], ArchiveFormat]  # platform -> how the asset is packaged
    bundle_asset: str | None = None  # a platform-independent Sigstore bundle published with the release


def _is_windows(platform: str) -> bool:
    return platform.startswith("windows")


FRP_TARGETS = {
    "linux-x86_64": "linux_amd64",
    "linux-aarch64": "linux_arm64",
    "macos-x86_64": "darwin_amd64",
    "macos-aarch64": "darwin_arm64",
    "windows-x86_64": "windows_amd64",
}
GOETIA_TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-musl",
    "linux-aarch64": "aarch64-unknown-linux-musl",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-aarch64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
}
WEBSOCAT_TARGETS = {
    "linux-x86_64": "x86_64-unknown-linux-musl",
    "linux-aarch64": "aarch64-unknown-linux-musl",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-aarch64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-gnu",
}


def _frp_format(platform: str) -> ArchiveFormat:
    return ArchiveFormat.ZIP if _is_windows(platform) else ArchiveFormat.TAR_GZ


def _goetia_format(platform: str) -> ArchiveFormat:
    return ArchiveFormat.ZIP if _is_windows(platform) else ArchiveFormat.TAR_XZ


TOOLS: Mapping[str, ToolSpec] = {
    "frp": ToolSpec(
        repo="fatedier/frp",
        binaries=("frpc", "frps"),
        asset=lambda version, platform: f"frp_{version}_{FRP_TARGETS[platform]}.{_frp_format(platform)}",
        format=_frp_format,
    ),
    "websocat": ToolSpec(
        repo="vi/websocat",
        binaries=("websocat", ),
        asset=lambda version, platform: f"websocat.{WEBSOCAT_TARGETS[platform]}" +
        (".exe" if _is_windows(platform) else ""),
        format=lambda platform: ArchiveFormat.BARE,
    ),
    "goetia": ToolSpec(
        repo="bindreams/goetia",
        binaries=("goetia", "goetia-shim"),
        asset=lambda version, platform: f"goetia-{GOETIA_TARGETS[platform]}.{_goetia_format(platform)}",
        format=_goetia_format,
        bundle_asset="goetia.sigstore.json",
    ),
}

ROLE_TOOLS: Mapping[Role, tuple[str, ...]] = {
    Role.HOST: ("frp", "websocat", "goetia"),
    Role.CLIENT: ("websocat", ),
    Role.BRIDGE: (),
}


def asset_name_of(url: str) -> str:
    """The release asset a download URL names: its last path segment."""
    return unquote(PurePosixPath(urlsplit(url).path).name)


def install_names(tool: str, platform: str) -> list[str]:
    suffix = ".exe" if _is_windows(platform) else ""
    return [binary + suffix for binary in TOOLS[tool].binaries]


# Pins =================================================================================================================


@dataclasses.dataclass(frozen=True)
class Pin:
    tool: str
    version: str
    url: str
    asset_sha256: str  # the release asset as published
    member_sha256: str  # the extracted binary itself
    archive_format: ArchiveFormat
    archive_member: str | None  # full path inside the archive, incl. any top-level dir
    install_name: str  # e.g. "frpc" / "frpc.exe"


class PinDrift(enum.StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNAVAILABLE = "unavailable"


Lock = dict[str, dict[str, list[Pin]]]


def current_platform(system: str | None = None, machine: str | None = None) -> str:
    """The lock key for this host, or for the given `platform.system()` and `platform.machine()` values."""
    system = system or host.system()
    machine = machine or host.machine()
    os_name = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(system)
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(machine.lower())
    key = f"{os_name}-{arch}"
    if key not in PLATFORMS:
        raise BinariesError(
            f"unsupported platform: machine {machine!r} on system {system!r}; supported: {', '.join(PLATFORMS)}"
        )
    return key


def tools_for_role(role: Role) -> tuple[str, ...]:
    return ROLE_TOOLS[role]


def _tool(lock: Lock, tool: str) -> dict[str, list[Pin]]:
    if tool not in lock:
        raise BinariesError(f"unknown tool {tool!r}; pinned tools: {', '.join(lock)}")
    return lock[tool]


def pins_for(lock: Lock, tool: str, platform: str) -> list[Pin]:
    """The binaries `tool` installs on `platform`, in install order."""
    by_platform = _tool(lock, tool)
    if platform not in PLATFORMS:
        raise BinariesError(f"unknown platform {platform!r}; expected one of {', '.join(PLATFORMS)}")
    return list(by_platform[platform])


def bundle_for(lock: Lock, tool: str) -> Pin | None:
    """The platform-independent Sigstore bundle pin for `tool`, if it publishes one."""
    bundle = _tool(lock, tool).get(BUNDLE)
    return bundle[0] if bundle else None


# Reading the lock =====================================================================================================


def load_lock(path: Path) -> Lock:
    """Parse and validate `path`. Anything short of a complete, well-formed lock is an error, never a partial one."""
    try:
        text = path.read_text(encoding="utf-8")
        document = tomllib.loads(text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BinariesError(f"{path.name}: {exc}") from exc
    source = path.name
    if set(document) != set(TOOLS):
        raise BinariesError(f"{source}: expected exactly the tools {sorted(TOOLS)}, found {sorted(document)}")
    return {tool: _parse_tool(tool, document[tool], source) for tool in TOOLS}


def _parse_tool(tool: str, table: object, source: str) -> dict[str, list[Pin]]:
    spec = TOOLS[tool]
    if not isinstance(table, dict):
        raise BinariesError(f"{source}: [{tool}] is not a table")
    allowed = {"version", *PLATFORMS, *([BUNDLE] if spec.bundle_asset else [])}
    if unknown := set(table) - allowed:
        raise BinariesError(f"{source}: [{tool}] has unknown keys {sorted(unknown)}")
    version = table.get("version")
    if not isinstance(version, str) or not version:
        raise BinariesError(f"{source}: [{tool}] needs a non-empty string `version`")
    parsed: dict[str, list[Pin]] = {}
    for platform in PLATFORMS:
        entries = table.get(platform)
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise BinariesError(f"{source}: [[{tool}.{platform}]] is missing")
        pins = [_parse_pin(tool, version, platform, e, source) for e in entries]
        if [p.install_name for p in pins] != install_names(tool, platform):
            raise BinariesError(
                f"{source}: {tool}.{platform} must pin {install_names(tool, platform)}, found {[p.install_name for p in pins]}"
            )
        parsed[platform] = pins
    if spec.bundle_asset:
        parsed[BUNDLE] = [_parse_bundle(tool, version, spec.bundle_asset, table.get(BUNDLE), source)]
    return parsed


def _field(entry: dict, key: str, where: str, source: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or value == "":
        raise BinariesError(f"{source}: {where}: missing or empty string `{key}`")
    return value


def _digest(entry: dict, key: str, where: str, source: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise BinariesError(f"{source}: {where}: `{key}` must be 64 lowercase hex characters (got {value!r})")
    return value


def _url(entry: dict, where: str, source: str) -> str:
    url = _field(entry, "url", where, source)
    if urlsplit(url).scheme not in ("http", "https"):
        raise BinariesError(f"{source}: {where}: `url` must be http(s) (got {url!r})")
    return url


def _check_asset(url: str, expected: str, version: str, repo: str, where: str, source: str) -> None:
    """A version bump that leaves the old URLs behind must fail here, not at first install.

    A GitHub download URL is `/<owner>/<repo>/releases/download/<tag>/<asset>`: the repository must be `repo` and both
    the asset and the tag must belong to `version`.
    """
    parts = PurePosixPath(unquote(urlsplit(url).path)).parts
    if len(parts) != 7 or parts[0] != "/" or parts[3:5] != ("releases", "download"):
        raise BinariesError(
            f"{source}: {where}: `url` must be /<owner>/<repo>/releases/download/<tag>/<asset> (got {url!r})"
        )
    if "/".join(parts[1:3]) != repo:
        raise BinariesError(f"{source}: {where}: `url` is from {'/'.join(parts[1:3])!r} but this tool is {repo!r}")
    tag, asset = parts[-2:]
    if asset != expected:
        raise BinariesError(f"{source}: {where}: `url` names {asset!r} but this pin's version needs {expected!r}")
    if tag not in (f"v{version}", version):
        raise BinariesError(f"{source}: {where}: `url` has release tag {tag!r} but the pinned version is {version!r}")


def _parse_pin(tool: str, version: str, platform: str, entry: dict, source: str) -> Pin:
    where = f"{tool}.{platform}"
    expected = {"url", "asset_sha256", "member_sha256", "archive_format", "archive_member", "install_name"}
    if unknown := set(entry) - expected:
        raise BinariesError(f"{source}: {where}: unknown keys {sorted(unknown)}")
    url = _url(entry, where, source)
    _check_asset(url, TOOLS[tool].asset(version, platform), version, TOOLS[tool].repo, where, source)
    asset_sha256 = _digest(entry, "asset_sha256", where, source)
    member_sha256 = _digest(entry, "member_sha256", where, source)
    try:
        fmt = ArchiveFormat(_field(entry, "archive_format", where, source))
    except ValueError:
        raise BinariesError(f"{source}: {where}: unknown archive_format {entry['archive_format']!r}") from None
    install_name = _field(entry, "install_name", where, source)
    member = entry.get("archive_member")
    if fmt is ArchiveFormat.BARE:
        if member is not None:
            raise BinariesError(f"{source}: {where}: a bare binary has no archive_member")
        if member_sha256 != asset_sha256:
            raise BinariesError(f"{source}: {where}: a bare binary's member_sha256 must equal its asset_sha256")
    else:
        if not isinstance(member, str) or not is_safe_member(member) or PurePosixPath(member).name != install_name:
            raise BinariesError(
                f"{source}: {where}: archive_member must be a safe path ending in {install_name!r}, found {member!r}"
            )
    return Pin(tool, version, url, asset_sha256, member_sha256, fmt, member, install_name)


def _parse_bundle(tool: str, version: str, asset: str, entry: object, source: str) -> Pin:
    where = f"{tool}.{BUNDLE}"
    if not isinstance(entry, dict) or set(entry) != {"url", "asset_sha256"}:
        raise BinariesError(f"{source}: [{where}] must hold exactly `url` and `asset_sha256`")
    digest = _digest(entry, "asset_sha256", where, source)
    url = _url(entry, where, source)
    _check_asset(url, asset, version, TOOLS[tool].repo, where, source)
    return Pin(tool, version, url, digest, digest, ArchiveFormat.BARE, None, asset)


# Refreshing the lock ==================================================================================================


def refresh(
    lock_path: Path,
    only: Iterable[str] | None,
    *,
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Re-pin `only` (every tool when `None`) at the versions the lock names; other tools are left byte-for-byte alone.

    The lock is rewritten once, after every named tool succeeded. This is the only code that downloads.
    """
    names = list(dict.fromkeys(TOOLS if only is None else only))
    if unknown := [n for n in names if n not in TOOLS]:
        raise BinariesError(f"unknown tool {unknown[0]!r}; pinned tools: {', '.join(TOOLS)}")
    try:
        document = tomlkit.parse(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, TOMLKitError) as exc:
        raise BinariesError(f"{lock_path.name}: {exc}") from exc
    with api_client(token, transport
                    ) as client, download_client(transport) as downloader, tempfile.TemporaryDirectory() as scratch:
        for name in names:
            version = _locked_version(document, name, lock_path.name)
            pinned = _pin_tool(name, version, client, downloader, Path(scratch))
            _write_tool(document, name, pinned)
    write_atomically(lock_path, tomlkit.dumps(document))


def _locked_version(document: tomlkit.TOMLDocument, tool: str, source: str) -> str:
    table = document.get(tool)
    version = table.get("version") if isinstance(table, Table) else None
    if not isinstance(version, str) or not version:
        raise BinariesError(f"{source}: [{tool}] needs a `version = \"...\"` line before it can be pinned")
    return str(version)


def _pin_tool(tool: str, version: str, client: httpx.Client, downloader: httpx.Client,
              scratch: Path) -> dict[str, list[Pin]]:
    spec = TOOLS[tool]
    context = f"{tool} {version}"
    release = find_release(client, spec.repo, version)
    if release is None:
        raise BinariesError(
            f"{context}: {spec.repo} has no published release v{version} or {version} (drafts are ignored)"
        )
    # Resolve every asset and its digest first, so a missing digest fails before any download starts.
    wanted = {platform: asset_named(release, spec.asset(version, platform), context) for platform in PLATFORMS}
    digests = {platform: sha256_of(asset, context) for platform, asset in wanted.items()}
    bundle = asset_named(release, spec.bundle_asset, context) if spec.bundle_asset else None
    bundle_digest = sha256_of(bundle, context) if bundle else None
    pinned: dict[str, list[Pin]] = {}
    for platform, asset in wanted.items():
        path = scratch / asset.name
        _download_verified(downloader, asset.url, path, digests[platform], context, asset.name)
        fmt = spec.format(platform)
        pins = []
        for install_name in install_names(tool, platform):
            if fmt is ArchiveFormat.BARE:
                member, member_sha256 = None, digests[platform]
            else:
                member, member_sha256 = hash_binary(path, fmt, install_name)
            pins.append(Pin(tool, version, asset.url, digests[platform], member_sha256, fmt, member, install_name))
        path.unlink()
        pinned[platform] = pins
    if bundle and bundle_digest and spec.bundle_asset:
        path = scratch / bundle.name
        _download_verified(downloader, bundle.url, path, bundle_digest, context, bundle.name)
        path.unlink()
        pinned[BUNDLE] = [
            Pin(tool, version, bundle.url, bundle_digest, bundle_digest, ArchiveFormat.BARE, None, spec.bundle_asset)
        ]
    return pinned


def _download_verified(downloader, url: str, path: Path, advertised: str, context: str, asset: str) -> None:
    got = download(downloader, url, path)
    if got != advertised:
        path.unlink(missing_ok=True)
        raise BinariesError(f"{context}: {asset} downloaded as sha256 {got} but GitHub advertises {advertised}")


def _write_tool(document: tomlkit.TOMLDocument, tool: str, pinned: dict[str, list[Pin]]) -> None:
    table = document[tool]
    assert isinstance(table, Table)
    for key in [k for k in table if k != "version"]:
        del table[key]
    for platform in PLATFORMS:
        entries = tomlkit.aot()
        for pin in pinned[platform]:
            entry = tomlkit.table()
            entry["url"] = pin.url
            entry["asset_sha256"] = pin.asset_sha256
            entry["member_sha256"] = pin.member_sha256
            entry["archive_format"] = pin.archive_format.value
            if pin.archive_member is not None:
                entry["archive_member"] = pin.archive_member
            entry["install_name"] = pin.install_name
            entries.append(entry)
        table[platform] = entries
    if BUNDLE in pinned:
        bundle = tomlkit.table()
        bundle["url"] = pinned[BUNDLE][0].url
        bundle["asset_sha256"] = pinned[BUNDLE][0].asset_sha256
        table[BUNDLE] = bundle


def write_atomically(path: Path, text: str) -> None:
    """Replace `path` whole, so a failed write never leaves a half-written lock; keeps the file's mode."""
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(text.encode("utf-8"))
        os.chmod(temp, mode)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


# Comparing to upstream ================================================================================================


def compare_to_upstream(lock: Lock,
                        *,
                        token: str | None = None,
                        transport: httpx.BaseTransport | None = None) -> list[tuple[Pin, PinDrift, str]]:
    """Check every pin's asset digest against the one GitHub advertises now, without downloading anything.

    `UNAVAILABLE` means GitHub could not answer; it is never folded into `MISMATCH`, which means the release changed.
    """
    results: list[tuple[Pin, PinDrift, str]] = []
    with api_client(token, transport) as client:
        for tool, by_platform in lock.items():
            pins = [pin for pins in by_platform.values() for pin in pins]
            version = pins[0].version
            try:
                release = find_release(client, TOOLS[tool].repo, version)
            except UpstreamUnavailable as exc:
                results += [(pin, PinDrift.UNAVAILABLE, str(exc)) for pin in pins]
                continue
            except BinariesError as exc:
                results += [(pin, PinDrift.MISMATCH, str(exc)) for pin in pins]
                continue
            if release is None:
                detail = f"{tool} {version}: no published release v{version} or {version} (drafts are ignored)"
                results += [(pin, PinDrift.MISMATCH, detail) for pin in pins]
                continue
            for pin in pins:
                drift, detail = _compare_pin(pin, release)
                results.append((pin, drift, detail))
    return results


def _compare_pin(pin: Pin, release: Release) -> tuple[PinDrift, str]:
    name = asset_name_of(pin.url)
    context = f"{pin.tool} {pin.version}"
    try:
        advertised = sha256_of(asset_named(release, name, context), context)
    except BinariesError as exc:
        return PinDrift.MISMATCH, str(exc)
    if advertised != pin.asset_sha256:
        return PinDrift.MISMATCH, f"{context}: {name}: lock has sha256 {pin.asset_sha256}, GitHub advertises {advertised}"
    return PinDrift.MATCH, f"{context}: {name}"
