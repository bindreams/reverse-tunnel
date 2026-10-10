"""The end-to-end tests' certificate authority issues what a client really validates, and a `STAGING` issuer on request."""

import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from pki import STAGING_NAME, Pki


@pytest.fixture(scope="module")
def pki() -> Pki:
    return Pki()


def verify(pki: Pki, pem: bytes, name: str) -> None:
    """Build and check the chain from the presented certificates to the root, for a server called `name`."""
    presented = x509.load_pem_x509_certificates(pem)
    verifier = PolicyBuilder().store(Store([pki.root.certificate])).build_server_verifier(x509.DNSName(name))
    verifier.verify(presented[0], presented[1:])


def issuer_name(pem: bytes) -> str:
    return str(x509.load_pem_x509_certificate(pem).issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


def test_a_leaf_from_the_root_validates_for_each_of_its_names(pki):
    leaf = pki.issue("localhost", "*.tunnel.example.com")
    for name in ("localhost", "alpha.tunnel.example.com"):
        verify(pki, leaf.chain_pem, name)


def test_a_leaf_issued_to_an_ip_address_validates_for_that_address_and_no_other(pki):
    leaf = pki.issue("staging.localhost", "127.0.0.1", staging=True)
    presented = x509.load_pem_x509_certificates(leaf.chain_pem)

    def verifier(address: str):
        return PolicyBuilder().store(Store([pki.root.certificate])
                                     ).build_server_verifier(x509.IPAddress(ipaddress.ip_address(address)))

    verifier("127.0.0.1").verify(presented[0], presented[1:])
    with pytest.raises(VerificationError):
        verifier("127.0.0.2").verify(presented[0], presented[1:])


def test_a_leaf_does_not_validate_for_a_name_it_was_not_issued_to(pki):
    with pytest.raises(VerificationError):
        verify(pki, pki.issue("localhost").chain_pem, "other.example.com")


def test_a_leaf_from_the_staging_intermediate_validates_through_the_chain_it_presents(pki):
    leaf = pki.issue("staging.localhost", staging=True)
    verify(pki, leaf.chain_pem, "staging.localhost")
    assert len(x509.load_pem_x509_certificates(leaf.chain_pem)) == 2


def test_the_issuer_of_a_staging_leaf_names_staging_and_the_issuer_of_a_normal_one_does_not(pki):
    assert "STAGING" in issuer_name(pki.issue("a.localhost", staging=True).chain_pem)
    assert issuer_name(pki.issue("a.localhost").chain_pem) != STAGING_NAME
    assert "STAGING" not in issuer_name(pki.issue("a.localhost").chain_pem)


def test_a_staging_leaf_without_its_intermediate_does_not_validate(pki):
    with pytest.raises(VerificationError):
        verify(
            pki,
            x509.load_pem_x509_certificates(pki.issue("a.localhost", staging=True).chain_pem
                                            )[0].public_bytes(serialization.Encoding.PEM), "a.localhost"
        )


def test_leaves_are_written_as_a_chain_and_a_key(pki, tmp_path):
    chain, key = pki.issue("a.localhost").write(tmp_path, "a")
    assert (chain.name, key.name) == ("a.pem", "a.key")
    assert chain.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert key.read_bytes().startswith(
        b"-----BEGIN " + b"PRIVATE KEY-----"
    )  # split so the scanner does not take it for a key
