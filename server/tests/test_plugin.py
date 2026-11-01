import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ctl.joincode import token_hash
from ctl.plugin import make_server
from ctl.registry import write_hosts

SERVER = Path(__file__).parent.parent
T = "t.test"
ACCEPT = {"reject": False, "unchange": True}


def reject(reason):
    return {"reject": True, "reject_reason": reason}


def captured(name):
    """The query and body of a request frps 0.71.1 really sent."""
    query = (SERVER / "testdata" / f"frps-plugin-{name}.query.txt").read_text().strip()
    return query, json.loads((SERVER / "testdata" / f"frps-plugin-{name}.body.json").read_text())


def post(port, query, body, path="/handler"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}?{query}", data) as response:
        return json.load(response)


@pytest.fixture
def plugin(tmp_path):
    """The state directory and `ask(query, body)`, against a plugin where alice's token is `host-secret`."""
    write_hosts(tmp_path / "hosts", {"alice": token_hash("host-secret")})
    server = make_server(tmp_path, T, 0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    yield tmp_path, lambda query, body, **kw: post(server.server_address[1], query, body, **kw)
    server.shutdown()
    thread.join()
    server.server_close()


def test_login_accepts_registered_token(plugin):
    assert plugin[1](*captured("login")) == ACCEPT


def test_login_rejects_unknown_host(plugin):
    query, body = captured("login")
    body["content"]["user"] = "mallory"
    assert plugin[1](query, body) == reject("host not registered")


def test_login_rejects_wrong_token(plugin):
    query, body = captured("login")
    body["content"]["metas"]["token"] = "guess"
    assert plugin[1](query, body) == reject("token mismatch")


def test_new_proxy_rejects_tcp(plugin):
    assert plugin[1](*captured("newproxy-tcp")) == reject("proxy type must be http")


def test_new_proxy_rejects_foreign_name(plugin):
    ask = plugin[1]
    assert ask(*captured("newproxy-http-two-domains")) == ACCEPT
    query, body = captured("newproxy-http")
    body["content"]["custom_domains"].append("bob.t.test")
    assert ask(query, body) == reject("name not allowed: bob.t.test")


def test_new_proxy_rejects_subdomain(plugin):
    assert plugin[1](*captured("newproxy-http-subdomain")) == reject("subdomain not allowed")


def test_malformed_body_rejected(plugin):
    query, body = captured("login")
    no_metas = {**body, "content": {"user": "alice"}}
    wrong_type = {**body, "content": {"user": 5, "metas": {"token": "host-secret"}}}
    for bad in (b"not json", b"[]", no_metas, wrong_type):
        assert plugin[1](query, bad) == reject("malformed request")


def test_unknown_op_rejected(plugin):
    assert plugin[1]("op=Ping&version=0.1.0", {"version": "0.1.0", "op": "Ping", "content": {}}) == reject(
        "unsupported op"
    )


def test_other_path_is_404(plugin):
    with pytest.raises(urllib.error.HTTPError) as e:
        plugin[1](*captured("login"), path="/other")
    assert e.value.code == 404


def test_bad_registry_rejects_with_reason(plugin, capsys):
    state, ask = plugin
    request = captured("login")
    (state / "hosts").write_text(f"alice {token_hash('host-secret')}\nbroken\n")
    assert ask(*request) == reject("registry unreadable")
    assert "line 2" in capsys.readouterr().err
    (state / "hosts").unlink()
    assert ask(*request) == reject("registry unreadable")


def test_registry_reread_each_request(plugin):
    state, ask = plugin
    query, body = captured("login")
    body["content"]["user"] = "bob"
    assert ask(query, body) == reject("host not registered")
    write_hosts(state / "hosts", {"bob": token_hash("host-secret")})
    assert ask(query, body) == ACCEPT


def test_plugin_runs_stdlib_only(tmp_path):
    write_hosts(tmp_path / "hosts", {"alice": token_hash("host-secret")})
    # -I ignores PYTHONPATH and the cwd, so the bootstrap puts `server/` on the path itself.
    boot = (
        f"import sys; from pathlib import Path; sys.path.insert(0, {str(SERVER)!r}); from ctl.plugin import make_server;"
        f"s = make_server(Path({str(tmp_path)!r}), {T!r}, 0); print(s.server_address[1], flush=True); s.serve_forever()"
    )
    child = subprocess.Popen([sys.executable, "-I", "-S", "-c", boot], stdout=subprocess.PIPE, text=True)
    try:
        assert post(int(child.stdout.readline()), *captured("login")) == ACCEPT
    finally:
        child.terminate()
        child.wait()
