import base64
import hashlib
import json


def token_hash(token_hex: str) -> str:
    """The registry form of a per-host token: `sha256:` and the hex digest of the token text."""
    return "sha256:" + hashlib.sha256(token_hex.encode()).hexdigest()


def encode_join(domain: str, token: str, cert_pem: str) -> str:
    """The join code: `rt1:` and the unpadded base64url of the JSON object a host needs to connect."""
    payload = json.dumps({"domain": domain, "token": token, "cert": cert_pem})
    return "rt1:" + base64.urlsafe_b64encode(payload.encode()).rstrip(b"=").decode()
