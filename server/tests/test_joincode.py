import base64
import json
from pathlib import Path

import pytest

from ctl.joincode import encode_join, token_hash

TESTDATA = Path(__file__).parent.parent / "testdata"
DOMAIN = "tunnel.example.test"
TOKEN = "0" * 64


def test_token_hash_vector():
    assert token_hash("0" * 64) == "sha256:60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55"


def test_token_hash_accepts_non_ascii():
    digest = token_hash("é")
    assert digest.startswith("sha256:")
    assert digest != token_hash("0" * 64)


@pytest.mark.parametrize(
    ("pem", "code"),
    [("bridge.pem", "join-code.txt"), ("bridge-multi.pem", "join-code-multi.txt")],
)
def test_join_fixture(pem, code):
    cert = (TESTDATA / pem).read_text()
    assert encode_join(DOMAIN, TOKEN, cert) == (TESTDATA / code).read_text().strip()


def test_join_code_shape():
    code = encode_join(DOMAIN, TOKEN, "pem")
    assert code.startswith("rt1:")
    payload = code.removeprefix("rt1:")
    assert "=" not in payload
    padded = payload + "=" * (-len(payload) % 4)
    assert json.loads(base64.urlsafe_b64decode(padded)) == {"domain": DOMAIN, "token": TOKEN, "cert": "pem"}
