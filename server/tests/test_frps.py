import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ctl import frps

# What frps 0.71.1 answers on /api/clients: one entry per client, `user` being the frpc's `user`.
CLIENTS = [
    {"user": "a", "online": True, "firstConnectedAt": 100, "lastConnectedAt": 200},
    {"user": "b", "online": False, "firstConnectedAt": 100, "lastConnectedAt": 150},
    {"user": "c", "online": True, "firstConnectedAt": 10, "lastConnectedAt": 400},
    {"user": "c", "online": True, "firstConnectedAt": 10, "lastConnectedAt": 300},
]


def test_online_keeps_hosts_with_a_session_open_from_their_earliest():
    assert frps.online(CLIENTS) == {"a": 200, "c": 300}
    assert frps.online([]) == {}


@pytest.fixture
def api(monkeypatch):
    """A stand-in for frps's API on loopback: answers `answer` to a request with the right credentials."""
    seen = []
    state = {"answer": CLIENTS}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers["Authorization"]))
            want = "Basic " + base64.b64encode(b"u:p").decode()
            ok = self.headers["Authorization"] == want
            body = json.dumps(state["answer"] if ok else "no").encode()
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(frps, "API", f"http://127.0.0.1:{server.server_port}")
    yield seen, state
    server.shutdown()


def test_main_prints_who_is_online(api, monkeypatch, capsys):
    seen, _ = api
    monkeypatch.setenv("FRPS_API_USER", "u")
    monkeypatch.setenv("FRPS_API_PASSWORD", "p")
    assert frps.main() == 0
    assert json.loads(capsys.readouterr().out) == {"a": 200, "c": 300}
    assert seen == [("/api/clients", "Basic " + base64.b64encode(b"u:p").decode())]


def test_main_says_why_it_could_not_ask(api, monkeypatch, capsys):
    monkeypatch.setenv("FRPS_API_USER", "u")
    monkeypatch.setenv("FRPS_API_PASSWORD", "wrong")
    assert frps.main() == 1
    assert "401" in capsys.readouterr().err

    monkeypatch.delenv("FRPS_API_PASSWORD")
    assert frps.main() == 1
    assert "FRPS_API_PASSWORD is not set" in capsys.readouterr().err
