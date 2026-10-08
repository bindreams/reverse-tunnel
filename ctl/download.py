# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Digest-verified downloads of the pinned binaries, with Sigstore attestation for the tools that publish one."""

import contextlib
import dataclasses
import enum
import functools
import json
import os
import stat
import tempfile
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Self

import httpx
from sigstore.dsse import Statement
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy
from sigstore_models.common.v1 import HashAlgorithm

from ctl.archive import ArchiveFormat, extract_member, hash_file, is_safe_member
from ctl.atomic import is_link, replace_file, require_directory
from ctl.binaries import HEX64, TOOLS, Pin, write_atomically
from ctl.errors import AttestationError, BinariesError, UpstreamUnavailable
from ctl.github import download, download_client

# Attestation ==========================================================================================================

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
IN_TOTO_PAYLOAD = "application/vnd.in-toto+json"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"

# Measured against the v0.1.0 release certificate: its SAN, its workflow name (OID 1.3.6.1.4.1.57264.1.4), and its
# trigger (.1.2). goetia releases by hand from `main`, so the certificate records a branch rather than a tag and
# none of the five values changes with the version.
GOETIA_CERT_IDENTITY = "https://github.com/bindreams/goetia/.github/workflows/draft-release.yaml@refs/heads/main"
GOETIA_WORKFLOW_NAME = "Draft Release"


@dataclasses.dataclass(frozen=True)
class IdentityPolicy:
    """The five exactly-matched certificate fields a release must be signed under. None is redundant with another."""

    repository: str  # workflow repository, e.g. `owner/name`
    cert_identity: str  # the certificate's SAN
    ref: str  # the git ref the workflow ran from
    name: str  # the workflow's name
    trigger: str  # the event that started it

    def checks(self) -> policy.VerificationPolicy:
        """Sigstore's form of this policy, which also pins the OIDC issuer to GitHub Actions."""
        return policy.AllOf([
            policy.OIDCIssuer(GITHUB_ACTIONS_ISSUER),
            policy.Identity(identity=self.cert_identity, issuer=None),
            policy.GitHubWorkflowRepository(self.repository),
            policy.GitHubWorkflowRef(self.ref),
            policy.GitHubWorkflowName(self.name),
            policy.GitHubWorkflowTrigger(self.trigger),
        ])


GOETIA_IDENTITY = IdentityPolicy(
    repository="bindreams/goetia",
    cert_identity=GOETIA_CERT_IDENTITY,
    ref="refs/heads/main",
    name=GOETIA_WORKFLOW_NAME,
    trigger="workflow_dispatch",
)


def production_verifier() -> Verifier:
    """A verifier rooted in Sigstore's public-good trusted root, refreshed from its TUF repository."""
    try:
        return Verifier.production()
    except Exception as exc:
        raise UpstreamUnavailable(f"cannot obtain Sigstore's trusted root (TUF): {type(exc).__name__}: {exc}") from exc


def verify_attestation(
    artifact: Path, bundle: Path, policy: IdentityPolicy, *, verifier: Verifier | None = None
) -> None:
    """Raise `AttestationError` unless `bundle` is a Sigstore attestation under `policy` that covers `artifact`'s bytes."""
    try:
        digest = hash_file(artifact)
        raw = bundle.read_bytes()
    except OSError as exc:
        raise AttestationError(f"{artifact.name}: cannot read the artifact or its Sigstore bundle: {exc}") from exc
    try:
        verify_attestation_digest(digest, raw, policy, verifier=verifier)
    except AttestationError as exc:
        raise AttestationError(f"{artifact.name}: {exc}") from exc


def verify_attestation_digest(
    digest: str, bundle: bytes, policy: IdentityPolicy, *, verifier: Verifier | None = None
) -> None:
    """As `verify_attestation`, for an artifact known only by its sha256 hex `digest`.

    The bundle must carry a DSSE in-toto statement of SLSA provenance, whose signature, certificate chain, transparency
    log entry and identity are all checked, and one of whose subjects must be `digest`. A bundle may cover many artifacts.
    Whatever goes wrong while checking, including an exception from a parser underneath, is an `AttestationError`.
    """
    try:
        parsed = Bundle.from_json(bundle)
    except Exception as exc:
        raise AttestationError(f"unreadable Sigstore bundle: {_describe(exc)}") from exc
    verifier = verifier or production_verifier()
    try:
        kind, payload = verifier.verify_dsse(parsed, policy.checks())
        if kind != IN_TOTO_PAYLOAD:
            raise AttestationError(f"the attestation's payload is {kind}, not an in-toto statement")
        statement = Statement(payload)  # schema-checked; its `_type` can only be in-toto v1
        if statement._inner.predicate_type != SLSA_PROVENANCE:
            raise AttestationError(f"the attestation is {statement._inner.predicate_type}, not SLSA provenance")
        if not statement._matches_digest(Hashed(algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(digest))):
            raise AttestationError(f"the attestation has no subject with sha256 {digest}")
    except AttestationError:
        raise
    except Exception as exc:
        raise AttestationError(f"attestation rejected: {_describe(exc)}") from exc


def _describe(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


POLICIES: Mapping[str, IdentityPolicy] = {"goetia": GOETIA_IDENTITY}
Attestor = Callable[[Path, Path, IdentityPolicy], None]
EXECUTABLE = 0o755

# Fetching =============================================================================================================


class TrustLevel(enum.StrEnum):
    """What vouches for an installed binary: its pinned digest alone, or a Sigstore attestation as well."""

    DIGEST_ONLY = "digest-only"
    ATTESTED = "attested"


@dataclasses.dataclass(frozen=True)
class Installed:
    path: Path
    trust: TrustLevel


class Fetcher:
    """Downloads pinned binaries into a directory, verifying everything before any byte reaches it.

    Each asset is downloaded and checked against its pinned digest once per fetcher, so the two binaries of one archive
    cost one download and goetia's single bundle costs one download however many archives it vouches for. Use it as a
    context manager: it owns a private scratch directory, removed on exit.
    """

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        verifier: Verifier | None = None,
        attest: Attestor | None = None,
    ) -> None:
        self._transport = transport
        self._verifier = verifier
        self._attest = attest
        self._stack = contextlib.ExitStack()
        self._client: httpx.Client | None = None
        self._scratch: Path | None = None
        self._assets: dict[tuple[str, str], Path] = {}
        self._attested: set[tuple[tuple[str, str], tuple[str, str]]] = set()

    def __enter__(self) -> Self:
        self._client = self._stack.enter_context(download_client(self._transport))
        self._scratch = Path(self._stack.enter_context(tempfile.TemporaryDirectory(prefix="rt-fetch-")))
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        self._stack.close()
        self._client = self._scratch = None

    def fetch(self, pin: Pin, dest_dir: Path, bundle: Pin | None = None) -> Installed:
        """Install `pin` as `dest_dir/<install_name>`, reporting how far it is trusted.

        Nothing is written to `dest_dir` until the asset's digest, its attestation (when the tool has one) and the
        extracted file's digest have all passed. `bundle` is the tool's pinned Sigstore bundle, required exactly when
        the tool publishes one.
        """
        if self._client is None or self._scratch is None:
            raise RuntimeError("a Fetcher must be used in a `with` block")
        context = f"{pin.tool} {pin.version}: {pin.install_name}"
        self._check(pin, dest_dir, bundle, context)
        archive = self._asset(pin, context)
        if bundle is not None:
            self._attest_once(pin, archive, bundle, context)
        if pin.archive_format is ArchiveFormat.BARE:
            source, digest = archive, pin.asset_sha256
        else:
            assert pin.archive_member is not None
            source = Path(tempfile.mkdtemp(dir=self._scratch, prefix="extract-")) / pin.install_name
            digest = extract_member(archive, pin.archive_format, pin.archive_member, source)
        if digest != pin.member_sha256:
            raise BinariesError(f"{context}: member sha256 is {digest} but the lock pins {pin.member_sha256}")
        with source.open("rb") as stream:
            path = replace_file(dest_dir, pin.install_name, stream, EXECUTABLE)
        return Installed(path, TrustLevel.DIGEST_ONLY if bundle is None else TrustLevel.ATTESTED)

    def _check(self, pin: Pin, dest_dir: Path, bundle: Pin | None, context: str) -> None:
        if pin.tool not in TOOLS:
            raise BinariesError(f"{context}: unknown tool {pin.tool!r}")
        require_directory(dest_dir)
        if not is_plain_name(pin.install_name):
            raise BinariesError(f"{context}: install name {pin.install_name!r} is not a plain file name")
        wanted = TOOLS[pin.tool].bundle_asset
        if wanted is None and bundle is not None:
            raise BinariesError(f"{context}: {pin.tool} publishes no attestation, so there is no bundle to check")
        if wanted is not None:
            if bundle is None:
                raise BinariesError(
                    f"{context}: {pin.tool} must pass Sigstore attestation and no bundle is pinned for it"
                )
            if (bundle.tool, bundle.version, bundle.install_name) != (pin.tool, pin.version, wanted):
                raise BinariesError(
                    f"{context}: the bundle is {bundle.tool} {bundle.version} {bundle.install_name}, "
                    f"not {pin.tool} {pin.version} {wanted}"
                )
            if pin.tool not in POLICIES:
                raise BinariesError(f"{context}: no identity policy is pinned for {pin.tool}")

    def _asset(self, pin: Pin, context: str) -> Path:
        """The release asset `pin` names, downloaded and checked against its pinned digest."""
        assert self._client is not None and self._scratch is not None
        key = (pin.url, pin.asset_sha256)
        if key not in self._assets:
            path = Path(tempfile.mkdtemp(dir=self._scratch, prefix="asset-")) / "asset"
            got = download(self._client, pin.url, path)
            if got != pin.asset_sha256:
                raise BinariesError(
                    f"{context}: {pin.url} downloaded as sha256 {got} but the lock pins {pin.asset_sha256}"
                )
            self._assets[key] = path
        return self._assets[key]

    def _attest_once(self, pin: Pin, archive: Path, bundle: Pin, context: str) -> None:
        key = ((pin.url, pin.asset_sha256), (bundle.url, bundle.asset_sha256))
        if key not in self._attested:
            bundle_path = self._asset(bundle, context)
            attest = self._attest or functools.partial(verify_attestation, verifier=self._production_verifier())
            attest(archive, bundle_path, POLICIES[pin.tool])
            self._attested.add(key)

    def _production_verifier(self) -> Verifier:
        if self._verifier is None:
            self._verifier = production_verifier()
        return self._verifier


def fetch(
    pin: Pin,
    dest_dir: Path,
    *,
    bundle: Pin | None = None,
    transport: httpx.BaseTransport | None = None,
    verifier: Verifier | None = None,
    attest: Attestor | None = None,
) -> Installed:
    """Download, verify and install one pinned binary; see `Fetcher.fetch`."""
    with Fetcher(transport=transport, verifier=verifier, attest=attest) as fetcher:
        return fetcher.fetch(pin, dest_dir, bundle)


# Recorded digests =====================================================================================================

DIGESTS = ".digests.json"


def is_plain_name(name: str) -> bool:
    """A single file name: nothing that could name another directory or the current one."""
    return is_safe_member(name) and PurePosixPath(name).name == name and name not in (".", "..")


def record_digests(bin_dir: Path, pins: Iterable[Pin]) -> None:
    """Replace `bin/.digests.json` with each pin's install name mapped to the `member_sha256` it was installed from."""
    recorded: dict[str, str] = {}
    for pin in pins:
        if recorded.setdefault(pin.install_name, pin.member_sha256) != pin.member_sha256:
            raise BinariesError(f"{pin.install_name}: two pins with different member digests")
    write_atomically(bin_dir / DIGESTS, json.dumps(recorded, indent=2, sort_keys=True) + "\n")


def read_digests(bin_dir: Path) -> dict[str, str]:
    """What `record_digests` wrote; `{}` when nothing was ever recorded, an error when the record cannot be trusted."""
    path = bin_dir / DIGESTS
    try:
        if is_link(os.lstat(path)):
            raise BinariesError(f"{path}: digests must be a regular file, not a link")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise BinariesError(f"{path}: digests must be a regular file")
            text = stream.read().decode("utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise BinariesError(f"{path}: digests unreadable: {exc}") from exc
    try:
        document = json.loads(text, object_pairs_hook=_unique_keys)
    except ValueError as exc:
        raise BinariesError(f"{path}: digests are not JSON: {exc}") from exc
    if not isinstance(document, dict) or not all(
        is_plain_name(name) and isinstance(digest, str) and HEX64.fullmatch(digest) for name, digest in document.items()
    ):
        raise BinariesError(f"{path}: digests must map plain file names to sha256 hex digests")
    return document


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("a name is recorded twice")
    return dict(pairs)
