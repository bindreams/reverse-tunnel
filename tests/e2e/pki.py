"""A throwaway certificate authority, so the TLS fronts of the end-to-end tests serve certificates that really validate.

`Pki.root` is the CA a client trusts. `Pki.staging` is an intermediate under it whose common name contains `STAGING`,
the way Let's Encrypt's staging issuer is named: a leaf it signs validates against the root, and its issuer is the
thing `ctl doctor` refuses.
"""

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT_NAME = "Reverse Tunnel E2E Root CA"
STAGING_NAME = "(STAGING) Reverse Tunnel E2E Intermediate"
VALID_FOR = datetime.timedelta(days=2)
BACKDATE = datetime.timedelta(minutes=5)  # tolerance for a clock that disagrees with this machine's by a little


@dataclass(frozen=True)
class Authority:
    key: ec.EllipticCurvePrivateKey
    certificate: x509.Certificate


@dataclass(frozen=True)
class Leaf:
    names: tuple[str, ...]
    chain_pem: bytes  # the leaf, then any intermediate: what a server presents
    key_pem: bytes

    def write(self, directory: Path, stem: str) -> tuple[Path, Path]:
        """`<stem>.pem` and `<stem>.key`, readable by a container's root."""
        chain, key = directory / f"{stem}.pem", directory / f"{stem}.key"
        chain.write_bytes(self.chain_pem)
        key.write_bytes(self.key_pem)
        return chain, key


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _builder(subject: str, issuer: x509.Name, public_key) -> x509.CertificateBuilder:
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(issuer).public_key(public_key).serial_number(
            x509.random_serial_number()
        ).not_valid_before(now - BACKDATE).not_valid_after(now + VALID_FOR)
    )


def _authority(common_name: str, issuer: Authority | None, path_length: int) -> Authority:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = _builder(common_name, issuer.certificate.subject if issuer else _name(common_name), key.public_key())
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    signer = issuer.key if issuer else key
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    return Authority(key, builder.sign(signer, hashes.SHA256()))


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


class Pki:
    """A root CA and, under it, the `STAGING` intermediate."""

    def __init__(self) -> None:
        self.root = _authority(ROOT_NAME, None, path_length=1)
        self.staging = _authority(STAGING_NAME, self.root, path_length=0)

    @property
    def root_pem(self) -> bytes:
        return _pem(self.root.certificate)

    def issue(self, *names: str, staging: bool = False) -> Leaf:
        """A server certificate for `names` (DNS names, the first also its common name), from the root or `STAGING`."""
        issuer = self.staging if staging else self.root
        key = ec.generate_private_key(ec.SECP256R1())
        builder = _builder(names[0], issuer.certificate.subject, key.public_key())
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical=False
        )
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        leaf = builder.sign(issuer.key, hashes.SHA256())
        chain = _pem(leaf) + (_pem(self.staging.certificate) if staging else b"")
        key_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return Leaf(names, chain, key_pem)
