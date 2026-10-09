"""The certificate checks' two halves: whose issuer a certificate names, and what the validating context trusts.

Both run on a certificate chain built here and handshaken in memory, so no socket is opened.
"""

import datetime
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ctl.doctor import tls

HOST = "front.example.com"


def name(common_name: str | None, organization: str | None = None) -> x509.Name:
    attributes = []
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if common_name:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def certificate(subject: x509.Name, issuer: x509.Name, key, signer, *, ca: bool, san: str | None = None):
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(
            x509.random_serial_number()
        ).not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30)).
        add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(signer, hashes.SHA256())


class Authority:
    """A throwaway CA that can issue a certificate for `HOST`."""

    def __init__(self, common_name: str | None = "Example Test CA", organization: str | None = None) -> None:
        self.name = name(common_name, organization)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.certificate = certificate(self.name, self.name, self.key, self.key, ca=True)

    def issue(self, host: str = HOST):
        key = ec.generate_private_key(ec.SECP256R1())
        return key, certificate(name(host), self.name, key, self.key, ca=False, san=host)

    def write(self, directory: Path, host: str = HOST) -> tuple[Path, Path, Path]:
        key, leaf = self.issue(host)
        ca_file, chain_file, key_file = directory / "ca.pem", directory / "chain.pem", directory / "key.pem"
        ca_file.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))
        chain_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        return ca_file, chain_file, key_file


def handshake(client: ssl.SSLContext, server: ssl.SSLContext, hostname: str) -> None:
    """Drive a TLS handshake between two contexts over memory buffers; raise whatever the client's verification raises."""
    from_client, from_server = ssl.MemoryBIO(), ssl.MemoryBIO()
    sides = {
        "client": client.wrap_bio(from_server, from_client, server_hostname=hostname),
        "server": server.wrap_bio(from_client, from_server, server_side=True),
    }
    finished: set[str] = set()
    while len(finished) < len(sides):
        before = (len(finished), from_client.pending, from_server.pending)
        for label, side in sides.items():
            if label in finished:
                continue
            try:
                side.do_handshake()
                finished.add(label)
            except ssl.SSLWantReadError:
                pass
        assert before != (len(finished), from_client.pending, from_server.pending), "the handshake made no progress"


def server_context(chain: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain, key)
    return context


# The issuer ===========================================================================================================


@pytest.mark.parametrize(
    "issuer",
    ["(STAGING) Ephemeral Elderberry R10", "Fake LE Intermediate X1", "Fake LE Root X1", "(STAGING) Pretend Pear X1"]
)
def test_known_staging_issuers_are_recognised(issuer):
    assert tls.is_staging(issuer)


@pytest.mark.parametrize("issuer", ["R10", "E5", "Example Trusted CA R3", "WE1", "Staging Area Services Ltd"])
def test_production_issuers_are_not_mistaken_for_staging(issuer):
    assert not tls.is_staging(issuer)


def test_the_issuer_common_name_is_read_from_a_der_certificate():
    authority = Authority("(STAGING) Ephemeral Elderberry R10")
    _, leaf = authority.issue()
    assert tls.issuer_common_name(leaf.public_bytes(serialization.Encoding.DER)) == "(STAGING) Ephemeral Elderberry R10"


def test_an_issuer_without_a_common_name_falls_back_to_the_whole_name_so_it_is_still_inspected():
    authority = Authority(None, "Fake Staging Organisation")
    _, leaf = authority.issue()
    issuer = tls.issuer_common_name(leaf.public_bytes(serialization.Encoding.DER))
    assert "Fake Staging Organisation" in issuer and tls.is_staging(issuer)


def test_bytes_that_are_not_a_certificate_are_a_probe_error():
    with pytest.raises(tls.TlsProbeError):
        tls.issuer_common_name(b"not a certificate")


# What the context trusts ==============================================================================================


def test_a_certificate_from_an_unknown_authority_does_not_validate_without_the_bundle(tmp_path):
    _, chain, key = Authority().write(tmp_path)
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(tls.build_context(None), server_context(chain, key), HOST)


def test_the_bundle_adds_its_authority_to_the_system_store(tmp_path):
    ca, chain, key = Authority().write(tmp_path)
    handshake(tls.build_context(str(ca)), server_context(chain, key), HOST)


def test_the_bundle_does_not_excuse_a_certificate_for_another_name(tmp_path):
    ca, chain, key = Authority().write(tmp_path, host="other.example.com")
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(tls.build_context(str(ca)), server_context(chain, key), HOST)


def test_a_bundle_that_cannot_be_read_is_a_probe_error_naming_the_file(tmp_path):
    with pytest.raises(tls.TlsProbeError, match="missing.pem"):
        tls.build_context(str(tmp_path / "missing.pem"))


def test_a_bundle_that_holds_no_certificate_is_a_probe_error(tmp_path):
    empty = tmp_path / "empty.pem"
    empty.write_text("nothing here\n")
    with pytest.raises(tls.TlsProbeError, match="empty.pem"):
        tls.build_context(str(empty))
