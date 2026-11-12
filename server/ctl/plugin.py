"""The frps HTTP plugin: decides which hosts may log in and which names they may claim."""

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from ctl.joincode import token_hash
from ctl.names import allowed_names, valid_domain
from ctl.registry import RegistryError, read_hosts

ACCEPT = {"reject": False, "unchange": True}
MAX_BODY = 2**20  # input bound; frps requests are a few hundred bytes


def _reject(reason: str, host: str | None = None) -> dict:
    # repr: host and names come from the client and must not forge log lines
    print(f"reject host={host!r} reason={reason!r}", file=sys.stderr)
    return {"reject": True, "reject_reason": reason}


def _unauthenticated(user: str, token: str, hosts: dict[str, str]) -> str | None:
    """Why `user` with `token` is not a registered host, or None."""
    if user not in hosts:
        return "host not registered"
    if not hmac.compare_digest(token_hash(token), hosts[user]):
        return "token mismatch"
    return None


def decide(op: str, content: dict, hosts: dict[str, str], domain: str) -> dict:
    """The reply to one frps plugin request, given the registered hosts' token hashes and the tunnel domain."""
    match op, content:
        case "Login", {"user": str(user), "metas": {"token": str(token)}}:
            if reason := _unauthenticated(user, token, hosts):
                return _reject(reason, user)
            print(f"login host={user!r}", file=sys.stderr)
        case "NewProxy", {"user": {"user": str(user), "metas": {"token": str(token)}}, "proxy_type": str(kind), **rest}:
            if reason := _unauthenticated(user, token, hosts):
                return _reject(reason, user)
            names, subdomain = rest.get("custom_domains", []), rest.get("subdomain", "")
            if not (isinstance(names, list) and all(isinstance(n, str) for n in names) and isinstance(subdomain, str)):
                return _reject("malformed request", user)
            if kind != "http":
                return _reject("proxy type must be http", user)
            if subdomain:
                return _reject("subdomain not allowed", user)
            if foreign := next((n for n in names if not allowed_names(user, domain)(n)), None):
                return _reject(f"name not allowed: {foreign}", user)
        case "Login" | "NewProxy", _:
            return _reject("malformed request")
        case _:
            return _reject("unsupported op")
    return ACCEPT


def make_server(state_dir: Path, domain: str, port: int) -> ThreadingHTTPServer:
    """A plugin server bound to `port` (0 picks a free one); the registry is read per request."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if urlsplit(self.path).path != "/handler":
                return self.send_error(404)
            try:
                length = self.headers.get("Content-Length", "0")
                digits = length.isascii() and length.isdigit()
                request = json.loads(self.rfile.read(int(length))) if digits and int(length) <= MAX_BODY else None
            except (ValueError, RecursionError):  # a body that is not JSON, or too deeply nested
                request = None
            try:
                hosts = read_hosts(state_dir / "hosts.yaml")
            except (RegistryError, OSError) as e:
                print(f"registry unreadable: {e}", file=sys.stderr)
                reply = _reject("registry unreadable")
            else:
                match request:
                    case {"op": str(op), "content": dict(content)}:
                        reply = decide(op, content, hosts, domain)
                    case _:
                        reply = _reject("malformed request")
            body = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("", port), Handler)


def serve(state_dir: Path, domain: str, port: int = 9000) -> None:
    make_server(state_dir, domain, port).serve_forever()


if __name__ == "__main__":
    domain = os.environ.get("TUNNEL_DOMAIN", "")
    if len(sys.argv) != 2 or not valid_domain(domain):
        sys.exit("usage: TUNNEL_DOMAIN=<a valid tunnel domain> python -m ctl.plugin <state_dir>")
    serve(Path(sys.argv[1]), domain)
