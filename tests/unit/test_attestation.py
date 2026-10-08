"""Sigstore verification of goetia's release, against the real v0.1.0 bundle and a snapshot of Sigstore's trusted root.

Everything here is offline and cryptographically real: the bundle is the one goetia published and the artifact is
named by the digest the lock pins, so no multi-megabyte archive is committed.
"""

import base64
import dataclasses
import datetime
import hashlib
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore.errors import TUFError
from sigstore.models import TrustedRoot
from sigstore.verify import Verifier

from ctl import binaries, download
from ctl.binaries import PLATFORMS, bundle_for, load_lock, pins_for
from ctl.download import (
    GOETIA_CERT_IDENTITY,
    GOETIA_IDENTITY,
    GOETIA_WORKFLOW_NAME,
    IdentityPolicy,
    verify_attestation,
    verify_attestation_digest,
)
from ctl.errors import AttestationError, UpstreamUnavailable

FIXTURES = Path(__file__).parent / "fixtures"
BUNDLE = FIXTURES / "goetia.sigstore.json"
TRUSTED_ROOT = FIXTURES / "sigstore-trusted-root.json"


@pytest.fixture(scope="module")
def lock():
    return load_lock(binaries.LOCK_PATH)


@pytest.fixture
def archive_digests(lock) -> dict[str, str]:
    """Each platform's goetia archive digest, as the committed lock pins it."""
    return {platform: pins_for(lock, "goetia", platform)[0].asset_sha256 for platform in PLATFORMS}


def edited_bundle(edit) -> bytes:
    document = json.loads(BUNDLE.read_text())
    edit(document)
    return json.dumps(document).encode()


# The real release =====================================================================================================


def test_the_committed_bundle_is_the_bundle_the_lock_pins(lock):
    pinned = bundle_for(lock, "goetia")
    assert pinned is not None
    assert hashlib.sha256(BUNDLE.read_bytes()).hexdigest() == pinned.asset_sha256


@pytest.mark.parametrize("platform", PLATFORMS)
def test_one_bundle_verifies_every_goetia_archive(verifier, archive_digests, platform):
    verify_attestation_digest(archive_digests[platform], BUNDLE.read_bytes(), GOETIA_IDENTITY, verifier=verifier)


def test_the_identity_policy_matches_the_values_the_release_publishes():
    assert GOETIA_CERT_IDENTITY == "https://github.com/bindreams/goetia/.github/workflows/draft-release.yaml@refs/heads/main"
    assert GOETIA_WORKFLOW_NAME == "Draft Release"
    assert GOETIA_IDENTITY == IdentityPolicy(
        repository="bindreams/goetia",
        cert_identity=GOETIA_CERT_IDENTITY,
        ref="refs/heads/main",
        name=GOETIA_WORKFLOW_NAME,
        trigger="workflow_dispatch",
    )


@pytest.mark.parametrize(
    ("field", "complaint"),
    [
        ("repository", "GitHubWorkflowRepository"),
        ("cert_identity", "SANs do not match"),
        ("ref", "GitHubWorkflowRef"),
        ("name", "GitHubWorkflowName"),
        ("trigger", "GitHubWorkflowTrigger"),
    ],
)
def test_each_identity_field_rejects_independently(verifier, archive_digests, field, complaint):
    digest, bundle = archive_digests["linux-x86_64"], BUNDLE.read_bytes()
    verify_attestation_digest(digest, bundle, GOETIA_IDENTITY, verifier=verifier)  # the unmodified policy passes
    wrong = dataclasses.replace(GOETIA_IDENTITY, **{field: "wrong"})
    with pytest.raises(AttestationError, match=complaint):
        verify_attestation_digest(digest, bundle, wrong, verifier=verifier)


def test_a_certificate_from_another_oidc_issuer_is_rejected(verifier, archive_digests, monkeypatch):
    monkeypatch.setattr(download, "GITHUB_ACTIONS_ISSUER", "https://issuer.example.test")
    with pytest.raises(AttestationError, match="OIDCIssuer"):
        verify_attestation_digest(
            archive_digests["linux-x86_64"], BUNDLE.read_bytes(), GOETIA_IDENTITY, verifier=verifier
        )


# Artifacts and bundles that must not verify ===========================================================================


def test_an_artifact_the_bundle_does_not_cover_is_rejected(verifier, tmp_path):
    artifact = tmp_path / "evil.tar.xz"
    artifact.write_bytes(b"a different artifact")
    with pytest.raises(AttestationError, match="no subject"):
        verify_attestation(artifact, BUNDLE, GOETIA_IDENTITY, verifier=verifier)


def test_a_bundle_made_for_other_bytes_with_the_right_identity_is_rejected(verifier, tmp_path):
    """The identity and the certificate are the real ones; only the signed statement now names our artifact."""
    artifact = tmp_path / "evil.tar.xz"
    artifact.write_bytes(b"a different artifact")

    def swap_subject(document):
        envelope = document["dsseEnvelope"]
        statement = json.loads(base64.b64decode(envelope["payload"]))
        statement["subject"][0]["digest"]["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()

    forged = tmp_path / "forged.sigstore.json"
    forged.write_bytes(edited_bundle(swap_subject))
    with pytest.raises(AttestationError, match="signature"):
        verify_attestation(artifact, forged, GOETIA_IDENTITY, verifier=verifier)


def test_a_bundle_with_a_corrupted_signature_is_rejected(verifier, archive_digests):

    def corrupt(document):
        signature = document["dsseEnvelope"]["signatures"][0]
        raw = bytearray(base64.b64decode(signature["sig"]))
        raw[-1] ^= 1
        signature["sig"] = base64.b64encode(bytes(raw)).decode()

    with pytest.raises(AttestationError):
        verify_attestation_digest(
            archive_digests["linux-x86_64"], edited_bundle(corrupt), GOETIA_IDENTITY, verifier=verifier
        )


def test_a_bundle_whose_certificate_chains_to_no_trusted_authority_is_rejected(tmp_path, archive_digests):
    """The same trusted root with each Fulcio chain replaced by an unrelated self-signed CA."""
    root = json.loads(TRUSTED_ROOT.read_text())
    for authority in root["certificateAuthorities"]:
        authority["certChain"] = {"certificates": [{"rawBytes": unrelated_ca()}]}
    other_root = tmp_path / "other-root.json"
    other_root.write_text(json.dumps(root))
    other = Verifier(trusted_root=TrustedRoot.from_file(str(other_root)))
    with pytest.raises(AttestationError, match="certificate chain"):
        verify_attestation_digest(archive_digests["linux-x86_64"], BUNDLE.read_bytes(), GOETIA_IDENTITY, verifier=other)


def unrelated_ca() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unrelated")])
    now = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(
            x509.random_serial_number()
        ).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=36500)).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(key, hashes.SHA256())
    )
    return base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b'{"mediaType": 1}', b"\xff\xfe"])
def test_a_malformed_bundle_is_rejected(verifier, archive_digests, raw):
    with pytest.raises(AttestationError, match="bundle"):
        verify_attestation_digest(archive_digests["linux-x86_64"], raw, GOETIA_IDENTITY, verifier=verifier)


# Plumbing =============================================================================================================


def test_verifying_a_file_verifies_the_digest_of_its_bytes(tmp_path, monkeypatch):
    artifact = tmp_path / "a.tar.xz"
    artifact.write_bytes(b"artifact bytes")
    seen = []
    monkeypatch.setattr(download, "verify_attestation_digest", lambda *args, **kwargs: seen.append((args, kwargs)))
    verify_attestation(artifact, BUNDLE, GOETIA_IDENTITY)
    ((args, _), ) = seen
    assert args == (hashlib.sha256(b"artifact bytes").hexdigest(), BUNDLE.read_bytes(), GOETIA_IDENTITY)


def test_an_unreachable_trust_root_is_an_upstream_failure_and_never_a_pass(tmp_path, archive_digests, monkeypatch):

    def unreachable(*args, **kwargs):
        raise TUFError("Failed to refresh TUF metadata")

    monkeypatch.setattr(Verifier, "production", classmethod(unreachable))
    with pytest.raises(UpstreamUnavailable, match="TUF"):
        verify_attestation_digest(archive_digests["linux-x86_64"], BUNDLE.read_bytes(), GOETIA_IDENTITY)


# Every failure is a taxonomy error ====================================================================================

DIGEST = "ab" * 32
STATEMENT = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "a", "digest": {"sha256": DIGEST}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {},
}


class Scripted:
    """A verifier that vouches for whatever statement it is given, so only our own statement checks are exercised."""

    def __init__(self, payload: bytes | Exception, kind: str = "application/vnd.in-toto+json") -> None:
        self.payload, self.kind = payload, kind

    def verify_dsse(self, bundle, policy):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.kind, self.payload


def check(verifier, digest: str = DIGEST) -> None:
    verify_attestation_digest(digest, BUNDLE.read_bytes(), GOETIA_IDENTITY, verifier=verifier)


def statement(**changes) -> bytes:
    return json.dumps({**STATEMENT, **changes}).encode()


def test_a_well_formed_statement_for_the_digest_passes_the_statement_checks():
    check(Scripted(statement()))


@pytest.mark.parametrize(
    "payload",
    [
        statement(_type="https://in-toto.io/Statement/v0.1"),
        statement(predicateType="https://example.test/other/v1"),
        statement(subject=[]),
        statement(subject=[{"name": "a", "digest": {"sha256": "cd" * 32}}]),
        statement(subject=[{"name": "a", "digest": {"sha512": DIGEST}}]),
        b"[]",
        b"not json",
    ],
    ids=["old-type", "other-predicate", "no-subjects", "other-digest", "other-algorithm", "array", "not-json"],
)
def test_a_statement_that_is_not_the_pinned_provenance_for_the_digest_is_rejected(payload):
    with pytest.raises(AttestationError):
        check(Scripted(payload))


def test_a_payload_of_another_type_is_rejected():
    with pytest.raises(AttestationError):
        check(Scripted(statement(), kind="text/plain"))


@pytest.mark.parametrize("exc", [ValueError("bad asn1"), KeyError("x"), TypeError("t"), RuntimeError("r")])
def test_any_failure_inside_verification_is_an_attestation_error(exc):
    with pytest.raises(AttestationError, match=type(exc).__name__):
        check(Scripted(exc))


def test_any_failure_parsing_the_bundle_is_an_attestation_error(monkeypatch):

    def explode(raw):
        raise ValueError("raw parser failure")

    monkeypatch.setattr(download.Bundle, "from_json", explode)
    with pytest.raises(AttestationError, match="raw parser failure"):
        check(Scripted(statement()))


@pytest.mark.parametrize("exc", [TUFError("tuf"), ValueError("v"), OSError("cache dir"), RuntimeError("r")])
def test_any_failure_obtaining_the_production_trust_root_is_an_upstream_failure(monkeypatch, exc):

    def failing(cls):
        raise exc

    monkeypatch.setattr(Verifier, "production", classmethod(failing))
    with pytest.raises(UpstreamUnavailable, match="trusted root"):
        check(None)
