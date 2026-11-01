from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from ctl.registry import atomic_write

ROTATION = "follow the certificate rotation procedure in the README"


class CertError(ValueError):
    """The frps certificate files cannot be used as they are; the message is for the operator."""


def make_cert(domain: str) -> tuple[str, str]:
    """A self-signed ECDSA P-256 certificate for `domain` and its key, as PEM `(certificate, key)`.

    It expires at RFC 5280's "no well-defined expiration" date: hosts pin it, so an expiry would lock them out.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))  # a host's clock may run behind
        .not_valid_after(datetime(9999, 12, 31, 23, 59, 59))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode(), key_pem.decode()


def dns_names(cert_pem: bytes) -> list[str]:
    """The DNS names in the certificate's subject alternative name (none without one); ValueError on bad PEM."""
    try:
        san = x509.load_pem_x509_certificate(cert_pem).extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return san.value.get_values_for_type(x509.DNSName)


def matches(cert_pem: bytes, key_pem: bytes) -> bool:
    """Whether the key is the certificate's; ValueError or TypeError on bad or encrypted PEM."""
    return load_pem_private_key(key_pem, None).public_key() == x509.load_pem_x509_certificate(cert_pem).public_key()


def in_bundle(cert_pem: bytes, bundle_pem: bytes) -> bool:
    """Whether the certificate is one of those in the bundle; ValueError on bad PEM."""
    return x509.load_pem_x509_certificate(cert_pem) in x509.load_pem_x509_certificates(bundle_pem)


def _problem(crt: Path, key: Path, trust: Path) -> str | None:
    """Why the files are not a trusted pair, or None; bad PEM raises ValueError, TypeError or UnsupportedAlgorithm."""
    if not (crt.exists() and key.exists()):
        return f"{crt} or {key} is missing"
    if not matches(crt.read_bytes(), key.read_bytes()):
        return f"{crt} does not match {key}"
    if trust.exists() and not in_bundle(crt.read_bytes(), trust.read_bytes()):
        return f"{crt} is not in {trust}"
    return None


def ensure(domain: str, tls: Path) -> None:
    """Leave `tls/frps.crt` and `frps.key` a matching pair for `domain`; raise CertError where that needs the operator.

    Once `tls/trust.pem` exists hosts may trust it, so the certificate is never replaced: any problem is an error.
    Before that a missing or mismatched pair is regenerated, key first. The pair's certificate must be for `domain`.
    """
    crt = tls / "frps.crt"
    key = tls / "frps.key"
    trust = tls / "trust.pem"
    try:
        problem = _problem(crt, key, trust)
        names = None if problem else dns_names(crt.read_bytes())
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise CertError(f"unusable file in {tls}: {e}; {ROTATION}") from e
    if problem and trust.exists():
        raise CertError(f"{problem}; {ROTATION}")
    if names is not None and names != [domain]:
        raise CertError(f"{crt} is not for {domain}; {ROTATION}")
    if problem:
        cert_pem, key_pem = make_cert(domain)
        tls.mkdir(exist_ok=True)
        atomic_write(key, key_pem.encode(), 0o600)  # the key first: no certificate is ever published without it
        atomic_write(crt, cert_pem.encode(), 0o644)
