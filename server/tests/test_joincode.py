import base64
import json
from pathlib import Path

import pytest

from ctl.joincode import encode_join, is_token_hash, token_hash

TESTDATA = Path(__file__).parent.parent / "testdata"
DOMAIN = "tunnel.example.test"
TOKEN = "0" * 64


def test_token_hash_vector():
    assert token_hash("0" * 64) == "sha256:60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55"


def test_token_hash_accepts_non_ascii():
    digest = token_hash("é")
    assert digest.startswith("sha256:")
    assert digest != token_hash("0" * 64)


def test_token_hash_accepts_lone_surrogate():
    assert token_hash("\ud800").startswith("sha256:")


@pytest.mark.parametrize(
    ("pem", "code"),
    [("bridge.pem", "join-code.txt"), ("bridge-multi.pem", "join-code-multi.txt")],
)
def test_join_fixture(pem, code):
    cert = (TESTDATA / pem).read_text()
    assert encode_join(DOMAIN, TOKEN, cert) == (TESTDATA / code).read_text().strip()


def decode(code):
    assert code.startswith("rt1:")
    payload = code.removeprefix("rt1:")
    assert "=" not in payload
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def test_join_code_shape():
    assert decode(encode_join(DOMAIN, TOKEN, "pem")) == {"domain": DOMAIN, "token": TOKEN, "cert": "pem"}


def test_is_token_hash():
    assert is_token_hash(token_hash(TOKEN))
    good = "sha256:" + "1" * 64
    assert is_token_hash(good)
    for bad in ["", "sha256:", good[:-1], good + "1", good.replace("1", "A"), "1" * 64, good + "\n"]:
        assert not is_token_hash(bad)


@pytest.mark.parametrize(
    ("pem", "code"),
    [("bridge.pem", "join-code.txt"), ("bridge-multi.pem", "join-code-multi.txt")],
)
def test_join_fixture_decodes_independently(pem, code):
    cert = (TESTDATA / pem).read_text()
    assert decode((TESTDATA / code).read_text().strip()) == {"domain": DOMAIN, "token": TOKEN, "cert": cert}
