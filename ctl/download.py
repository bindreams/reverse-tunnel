# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Digest-verified downloads of the pinned binaries, with Sigstore attestation for the tools that publish one."""

import contextlib
import dataclasses
import functools
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Self

import httpx
from sigstore.errors import Error, TUFError
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

from ctl.archive import CHUNK, ArchiveFormat, extract_member, hash_file, is_safe_member
from ctl.binaries import TOOLS, Pin, write_atomically
from ctl.errors import AttestationError, BinariesError, UpstreamUnavailable
from ctl.github import download, download_client

# Attestation ==========================================================================================================

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
IN_TOTO_PAYLOAD = "application/vnd.in-toto+json"

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
    except TUFError as exc:
        raise UpstreamUnavailable(f"cannot refresh Sigstore's trusted root over TUF: {exc}") from exc


def verify_attestation(
    artifact: Path, bundle: Path, policy: IdentityPolicy, *, verifier: Verifier | None = None
) -> None:
    """Raise `AttestationError` unless `bundle` is a Sigstore attestation under `policy` that covers `artifact`'s bytes."""
    try:
        raw = bundle.read_bytes()
    except OSError as exc:
        raise AttestationError(f"{artifact.name}: cannot read the Sigstore bundle: {exc}") from exc
    try:
        verify_attestation_digest(hash_file(artifact), raw, policy, verifier=verifier)
    except AttestationError as exc:
        raise AttestationError(f"{artifact.name}: {exc}") from exc


def verify_attestation_digest(
    digest: str, bundle: bytes, policy: IdentityPolicy, *, verifier: Verifier | None = None
) -> None:
    """As `verify_attestation`, for an artifact known only by its sha256 hex `digest`.

    The bundle must carry a DSSE in-toto statement, whose signature, certificate chain, transparency log entry and
    identity are all checked, and one of whose subjects must be `digest`. A bundle may cover many artifacts.
    """
    try:
        parsed = Bundle.from_json(bundle)
    except Error as exc:
        raise AttestationError(f"unreadable Sigstore bundle: {exc}") from exc
    verifier = verifier or production_verifier()
    try:
        kind, payload = verifier.verify_dsse(parsed, policy.checks())
    except Error as exc:
        raise AttestationError(f"attestation rejected: {exc}") from exc
    if kind != IN_TOTO_PAYLOAD or digest not in _subject_digests(payload):
        raise AttestationError(f"the attestation has no subject with sha256 {digest}")


def _subject_digests(payload: bytes) -> set[str]:
    try:
        statement = json.loads(payload)
        return {subject["digest"]["sha256"] for subject in statement["subject"]}
    except (ValueError, KeyError, TypeError) as exc:
        raise AttestationError(f"the attestation's statement is malformed: {exc!r}") from exc


POLICIES: Mapping[str, IdentityPolicy] = {"goetia": GOETIA_IDENTITY}
Attestor = Callable[[Path, Path, IdentityPolicy], None]
EXECUTABLE = 0o755

# Fetching =============================================================================================================


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
        self._assets: dict[str, Path] = {}
        self._attested: set[tuple[str, str]] = set()

    def __enter__(self) -> Self:
        self._client = self._stack.enter_context(download_client(self._transport))
        self._scratch = Path(self._stack.enter_context(tempfile.TemporaryDirectory(prefix="rt-fetch-")))
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        self._stack.close()

    def fetch(self, pin: Pin, dest_dir: Path, bundle: Pin | None = None) -> Path:
        """Install `pin` as `dest_dir/<install_name>` and return that path.

        Nothing is written to `dest_dir` until the asset's digest, its attestation (when the tool has one) and the
        extracted file's digest have all passed. `bundle` is the tool's pinned Sigstore bundle, required exactly when
        the tool publishes one.
        """
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
        return _install(source, dest_dir / pin.install_name)

    def _check(self, pin: Pin, dest_dir: Path, bundle: Pin | None, context: str) -> None:
        if pin.tool not in TOOLS:
            raise BinariesError(f"{context}: unknown tool {pin.tool!r}")
        if not dest_dir.is_dir():
            raise BinariesError(f"{context}: {dest_dir} is not an existing directory")
        name = pin.install_name
        if not is_safe_member(name) or PurePosixPath(name).name != name or name in (".", ".."):
            raise BinariesError(f"{context}: install name {name!r} is not a plain file name")
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

    def _asset(self, pin: Pin, context: str) -> Path:
        """The release asset `pin` names, downloaded and checked against its pinned digest."""
        if pin.url not in self._assets:
            path = Path(tempfile.mkdtemp(dir=self._scratch, prefix="asset-")) / "asset"
            got = download(self._client, pin.url, path)
            if got != pin.asset_sha256:
                raise BinariesError(
                    f"{context}: {pin.url} downloaded as sha256 {got} but the lock pins {pin.asset_sha256}"
                )
            self._assets[pin.url] = path
        return self._assets[pin.url]

    def _attest_once(self, pin: Pin, archive: Path, bundle: Pin, context: str) -> None:
        key = (pin.url, bundle.url)
        if key not in self._attested:
            bundle_path = self._asset(bundle, context)
            attest = self._attest or functools.partial(verify_attestation, verifier=self._production_verifier())
            attest(archive, bundle_path, POLICIES[pin.tool])
            self._attested.add(key)

    def _production_verifier(self) -> Verifier:
        if self._verifier is None:
            self._verifier = production_verifier()
        return self._verifier


def _install(source: Path, target: Path) -> Path:
    """Copy `source` to `target` as one atomic replacement, executable; nothing is left behind on failure."""
    handle, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(handle, "wb") as out, source.open("rb") as stream:
            shutil.copyfileobj(stream, out, CHUNK)
        os.chmod(temporary, EXECUTABLE)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return target


def fetch(
    pin: Pin,
    dest_dir: Path,
    *,
    bundle: Pin | None = None,
    transport: httpx.BaseTransport | None = None,
    verifier: Verifier | None = None,
    attest: Attestor | None = None,
) -> Path:
    """Download, verify and install one pinned binary; see `Fetcher.fetch`."""
    with Fetcher(transport=transport, verifier=verifier, attest=attest) as fetcher:
        return fetcher.fetch(pin, dest_dir, bundle)


# Recorded digests =====================================================================================================

DIGESTS = ".digests.json"
HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


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
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise BinariesError(f"{path}: digests unreadable: {exc}") from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise BinariesError(f"{path}: digests are not JSON: {exc}") from exc
    if not isinstance(document, dict) or not all(
        isinstance(name, str) and is_safe_member(name) and "/" not in name and isinstance(digest, str)
        and HEX64.fullmatch(digest) for name, digest in document.items()
    ):
        raise BinariesError(f"{path}: digests must map plain file names to sha256 hex digests")
    return document
