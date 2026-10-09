# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""What the public front's certificate says, asked two ways that must not be merged.

`validate` checks the chain against the system store plus an optional bundle. `issuer` fetches the certificate with no
validation at all and reads who issued it. One check cannot do both: a genuine staging chain fails validation before any
issuer branch runs, so a combined check passes for the wrong reason and keeps passing with the issuer inspection deleted.
"""

import socket
import ssl
from typing import Protocol

import truststore
from cryptography import x509
from cryptography.x509.oid import NameOID

# external-bound: the public front answering a TLS handshake; a human reads the failure.
TIMEOUT = 10.0
# Let's Encrypt's staging issuers are `(STAGING) …` and `Fake LE …`.
STAGING_MARKERS = ("STAGING", "Fake")


class TlsProbeError(Exception):
    """The certificate could not be fetched or the bundle could not be loaded; the message says why."""


class TlsProbe(Protocol):

    def validate(self, host: str, port: int, cafile: str | None) -> str | None:
        """None if the chain at `host:port` validates for `host`; otherwise why not, or why it could not be tried."""

    def issuer(self, host: str, port: int) -> str:
        """The issuer's common name of the certificate at `host:port`, fetched unverified; raise `TlsProbeError`."""


def verification_failure(exc: BaseException | None) -> ssl.SSLCertVerificationError | None:
    """The certificate-verification error `exc` was raised from, if any: httpx wraps it in a `ConnectError`."""
    while exc is not None:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return exc
        exc = exc.__cause__ or exc.__context__
    return None


# The issuer ===========================================================================================================


def is_staging(issuer: str) -> bool:
    return any(marker in issuer for marker in STAGING_MARKERS)


def issuer_common_name(der: bytes) -> str:
    """The issuer's common name; when it has none, the whole issuer name, so that it is inspected all the same."""
    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise TlsProbeError(f"the front sent something that is not a certificate: {exc}") from exc
    names = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if names:
        value = names[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")
    return certificate.issuer.rfc4514_string()


# The chain ============================================================================================================


def build_context(cafile: str | None) -> ssl.SSLContext:
    """A client context that trusts the operating system's store and, when given, the PEM bundle at `cafile` as well."""
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if cafile is not None:
        try:
            context.load_verify_locations(cafile=cafile)
        except (OSError, ssl.SSLError) as exc:
            raise TlsProbeError(f"RT_TLS_CA_BUNDLE {cafile}: {getattr(exc, 'strerror', None) or exc}") from exc
    return context


class SocketTls:
    """The real thing: a TCP connection and a TLS handshake. Exercised end to end by Task 11, not by unit tests."""

    def validate(self, host: str, port: int, cafile: str | None) -> str | None:
        try:
            context = build_context(cafile)
        except TlsProbeError as exc:
            return str(exc)
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return None
        except ssl.SSLCertVerificationError as exc:
            return exc.verify_message or str(exc)
        except ssl.SSLError as exc:
            return f"the TLS handshake with {host}:{port} failed: {exc}"
        except OSError as exc:
            return f"cannot connect to {host}:{port}: {exc.strerror or exc}"

    def issuer(self, host: str, port: int) -> str:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Unverified on purpose: this reads who issued a certificate that validation may already have refused.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secured:
                    der = secured.getpeercert(binary_form=True)
        except OSError as exc:  # ssl.SSLError is an OSError
            raise TlsProbeError(f"cannot fetch the certificate from {host}:{port}: {exc.strerror or exc}") from exc
        if der is None:
            raise TlsProbeError(f"{host}:{port} sent no certificate")
        return issuer_common_name(der)
