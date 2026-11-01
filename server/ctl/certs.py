from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


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
        .not_valid_before(datetime.now(UTC))
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
    """The DNS names in the certificate's subject alternative name."""
    san = x509.load_pem_x509_certificate(cert_pem).extensions.get_extension_for_class(x509.SubjectAlternativeName)
    return san.value.get_values_for_type(x509.DNSName)
