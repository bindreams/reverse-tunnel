"""End to end: the real bridge (`server/`) behind Traefik and Pebble in Docker, and a real host, installed as a service
on this machine with `reverse-tunnel install`, with sshd and an HTTP stub.

Runs only on CI's `e2e` job (`RT_E2E=1`), which installs a service, edits /etc/hosts and uses port 443 and 22: never
on a developer's machine. The tests are one scenario and run in file order: the host is registered by the second
test, and the last ones break it.

Waits re-check the real condition and have no cap; the job's own timeout bounds them.
"""

import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotenv import dotenv_values

from ctl.certs import make_cert
from ctl.generate import FRPS_VHOST_SERVICE, alias_key
from ctl.joincode import token_hash

if os.environ.get("RT_E2E") != "1":
    pytest.skip("installs a service and edits /etc/hosts: CI's e2e job only (RT_E2E=1)", allow_module_level=True)

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
BUILT = ROOT / "target/release/reverse-tunnel"
INSTALLED = Path("/usr/local/bin/reverse-tunnel")
BIN_DIR = Path("/usr/local/lib/reverse-tunnel")
FRPC_LOG = Path("/var/log/reverse-tunnel/frpc.log")

T = "tunnel.binarydreams.me"
HOST = "e2ehost"  # the real host
OTHER = "e2eother"  # a registered host that frpc, run by hand, stands in for
BACKEND = f"web.{HOST}.{T}"
ALIAS = "movies.binarydreams.me"
LOOKALIKE = "x.tunnelXbinarydreams.me"  # the frps router's unescaped dots match it
TOO_DEEP = f"a.b.{HOST}.{T}"
# /etc/hosts has no wildcards: every name the tests connect to.
NAMES = [T, f"rt-dns-check.rt-dns-check.{T}", f"{HOST}.{T}", f"ssh.{HOST}.{T}", BACKEND, ALIAS, LOOKALIKE, TOO_DEEP,
         "certs.invalid"]  # fmt: skip
MARK = "e2e-stub"


def client_template() -> str:
    """The README's `~/.ssh/config` block, for a host named `mothership`.

    The README does not have it yet (Task 14); until then it is the design's text. Task 14 moves the source here.
    """
    return "Host mothership\n    HostName mothership.tunnel.binarydreams.me\n    ProxyCommand websocat --binary wss://%h/\n"


def run(*args, cwd=None, env=None, check=True, input=None) -> subprocess.CompletedProcess:
    done = subprocess.run([str(a) for a in args], cwd=cwd, env=env, input=input, capture_output=True, text=True)
    if check and done.returncode:
        raise AssertionError(f"{args} ended with {done.returncode}\nstdout: {done.stdout}\nstderr: {done.stderr}")
    return done


def wait_until(condition):
    """The condition's first truthy value."""
    while not (value := condition()):
        time.sleep(0.5)
    return value


def _try(call, *args):
    try:
        return call(*args)
    except (ssl.SSLError, OSError):
        return None


def frpc_log() -> str:
    return run("sudo", "cat", FRPC_LOG).stdout


def wait_log(since: int, pattern: str) -> str:
    """The first match of `pattern` in what frpc logged after its first `since` characters."""
    return wait_until(lambda: (m := re.search(pattern, frpc_log()[since:])) and m.group())


class Frpc:
    """frpc run by hand with a config of its own, logging in as `user`; `proxies` maps proxy names to custom domains."""

    def __init__(self, stack, user, token, pem, proxies):
        config = stack.tmp / f"frpc-{secrets.token_hex(4)}.toml"
        config.write_text(
            f'serverAddr = "{T}"\nserverPort = 7000\nuser = "{user}"\nloginFailExit = false\n'
            f'transport.protocol = "quic"\ntransport.tls.trustedCaFile = "{pem}"\n'
            f'auth.token = "{stack.frps_token}"\nmetadatas.token = "{token}"\nlog.to = "console"\n'
            + "".join(
                f'[[proxies]]\nname = "{name}"\ntype = "http"\nlocalPort = 22\ncustomDomains = ["{domain}"]\n'
                for name, domain in proxies.items()
            )
        )
        frpc = next(BIN_DIR.glob("frpc-*"))
        self.proc = subprocess.Popen([frpc, "-c", config], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.lines: list[str] = []

    def wait(self, pattern: str) -> str:
        """The first line, from the start, that matches `pattern`."""
        found = re.compile(pattern)
        for line in self.lines:
            if found.search(line):
                return line
        for line in self.proc.stdout:
            self.lines.append(line)
            if found.search(line):
                return line
        raise AssertionError("frpc ended:\n" + "".join(self.lines))

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.terminate()
        self.proc.wait()
        self.proc.stdout.close()


class Stack:
    """The running bridge and host, and what a test needs to reach them."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.root = tmp / "pebble-root.pem"  # what verifies the certificates Traefik serves
        self.key = tmp / "id_ed25519"
        self.ssh_config = tmp / "ssh_config"

    def ctl(self, *args):
        return run("uv", "run", "--locked", "ctl", *args, cwd=SERVER).stdout

    def compose(self, *args):
        return run("docker", "compose", *args, cwd=SERVER)

    def ssh(self, command: str) -> subprocess.CompletedProcess:
        options = ["IdentitiesOnly=yes", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "BatchMode=yes"]
        flags = [f"-o{o}" for o in options]
        env = {**os.environ, "SSL_CERT_FILE": str(self.root)}  # websocat trusts Pebble's root
        cmd = ["ssh", "-F", self.ssh_config, "-i", self.key, "-l", getpass.getuser(), "-oLogLevel=ERROR", *flags]
        return run(*cmd, HOST, command, env=env, check=False)

    def ssh_works(self) -> bool:
        return self.ssh(f"echo {MARK}").stdout.strip() == MARK

    def https(self, name, path="/", *, method="GET", body=None, verified=True):
        """`(status, body)` of a request to `name`, which /etc/hosts sends to Traefik."""
        context = ssl.create_default_context(cafile=self.root if verified else None)
        if not verified:
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        connection = HTTPSConnection(name, 443, context=context)
        connection.request(method, path, body=body)
        response = connection.getresponse()
        return response.status, response.read().decode()

    def peer_cert(self, name) -> dict:
        """The certificate Traefik serves for `name`, verified against Pebble's root; raises if it is not."""
        context = ssl.create_default_context(cafile=self.root)
        with socket.create_connection(("127.0.0.1", 443)) as sock:
            return context.wrap_socket(sock, server_hostname=name).getpeercert()

    def api(self, path):
        connection = HTTPConnection("127.0.0.1", 8088)
        connection.request("GET", f"/api/{path}")
        response = connection.getresponse()
        text = response.read().decode()
        return response.status, json.loads(text) if response.status == 200 else text

    def status(self) -> str:
        return run(INSTALLED, "status").stdout  # no elevation

    def pid(self) -> int | None:
        found = re.search(r"service: running \(pid (\d+)\)", self.status())
        return found and int(found.group(1))

    def register(self, host, token_hash_):
        self.ctl("add", host, token_hash_)


class Stub(BaseHTTPRequestHandler):
    """The host's HTTP service: says what `Host` it was asked for."""

    def do_GET(self):
        body = json.dumps({"marker": MARK, "host": self.headers["Host"]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="session")
def stack(tmp_path_factory):
    stack = Stack(tmp_path_factory.mktemp("e2e"))
    hosts = "".join(f"127.0.0.1 {name}\n" for name in NAMES)
    run("sudo", "tee", "-a", "/etc/hosts", input=hosts)

    # The edge: Pebble and Traefik. Pebble's root changes at every start.
    run("docker", "compose", "-f", ROOT / "e2e/compose.yaml", "up", "-d")
    minica = ssl.create_default_context(cafile=ROOT / "e2e/pebble.minica.pem")
    roots = "https://localhost:15000/roots/0"
    stack.root.write_bytes(wait_until(lambda: _try(lambda: urllib.request.urlopen(roots, context=minica).read())))

    # The bridge, as its README brings it up.
    shutil.copy(SERVER / ".env.example", SERVER / ".env")
    joined = stack.ctl("init").split()
    code = next(word for word in joined if word.startswith("rt1:"))
    stack.compose("up", "-d", "--build")
    stack.frps_token = dotenv_values(SERVER / ".env")["FRPS_TOKEN"]

    # The host's side: an HTTP service, ssh, and the client config from the README's template.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", stack.key)
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    with open(ssh_dir / "authorized_keys", "a") as keys:
        keys.write(Path(f"{stack.key}.pub").read_text())
    stack.ssh_config.write_text(client_template().replace("mothership", HOST))

    # The real install, then the HTTP service added to the config it wrote.
    installed = run("sudo", BUILT, "install", "--host", HOST, "--join", code).stdout
    stack.registration = re.search(r"uv run ctl add (\S+) (sha256:[0-9a-f]{64})", installed).groups()
    port = server.server_address[1]
    run("sudo", "tee", "-a", "/etc/reverse-tunnel/config.yaml", input=f"  web:\n    port: {port}\n    type: http\n")
    run("sudo", INSTALLED, "stop")
    run("sudo", INSTALLED, "start")
    return stack


@pytest.fixture(scope="session")
def before_add(stack):
    """What the host does before the bridge knows it."""
    refusal = wait_log(0, r"host not registered")
    return SimpleNamespace(refusal=refusal, ssh=stack.ssh_works(), pid=stack.pid(), log=len(frpc_log()))


@pytest.fixture(scope="session")
def registered(stack, before_add):
    stack.register(*stack.registration)
    wait_log(before_add.log, r"login to server success")


@pytest.fixture(scope="session")
def other(stack):
    """A second registered host, for frpc run by hand."""
    token = secrets.token_hex(32)
    stack.register(OTHER, token_hash(token))
    return token


@pytest.fixture(scope="session")
def alias(stack, registered):
    stack.ctl("alias", ALIAS, BACKEND)


def _router(stack, name):
    """The router as Traefik holds it, once it does."""
    answer = _try(stack.api, f"http/routers/{name}@docker")
    return answer and answer[0] == 200 and answer[1]


def test_zero_hosts_orders_nothing(stack):
    """With no host registered the certificates router has no resolver, so Traefik orders no certificate."""
    router = wait_until(lambda: _router(stack, "reverse-tunnel-certs"))
    assert "certResolver" not in router.get("tls", {})
    assert run("docker", "exec", "traefik", "test", "!", "-e", "/acme/dns-exec.log", check=False).returncode == 0


def test_status_before_and_after_add(stack, before_add, registered):
    """The host logs why the bridge refuses it, and that it is in once registered."""
    assert "host not registered" in before_add.refusal
    assert "login to server success" in frpc_log()[before_add.log :]


def test_register_after_install(stack, before_add, registered):
    """No tunnel before `ctl add`; SSH after it, with no restart of the host."""
    assert not before_add.ssh
    wait_until(stack.ssh_works)
    assert stack.pid() == before_add.pid


def test_ssh_through_proxycommand(stack, registered):
    """The README's client template reaches sshd on the host: Host passes through Traefik, frps and frpc unchanged."""
    assert stack.ssh("whoami").stdout.strip() == getpass.getuser()


def test_per_host_cert_issued_on_add(stack, registered):
    """Pebble issued one certificate for `*.h.T` and `h.T`."""
    cert = wait_until(lambda: _try(stack.peer_cert, f"x.{HOST}.{T}"))
    names = {value for kind, value in cert["subjectAltName"] if kind == "DNS"}
    assert names == {f"*.{HOST}.{T}", f"{HOST}.{T}"}


def test_alias_reaches_http_service(stack, alias):
    """A public name reaches the host's HTTP service, with the backend address as its `Host`."""
    status, body = wait_until(lambda: _try(stack.https, ALIAS))
    assert status == 200
    assert json.loads(body) == {"marker": MARK, "host": BACKEND}


def test_alias_routes_through_frps_vhost(stack, alias):
    router = wait_until(lambda: _router(stack, alias_key(ALIAS)))
    assert router["service"] == f"{FRPS_VHOST_SERVICE}@docker"
    frps = run("docker", "inspect", "-f", "{{.NetworkSettings.Networks.gateway.IPAddress}}", "reverse-tunnel-frps")
    service = stack.api(f"http/services/{FRPS_VHOST_SERVICE}@docker")[1]
    assert [s["url"] for s in service["loadBalancer"]["servers"]] == [f"http://{frps.stdout.strip()}:8080"]


def test_lookalike_domain_gets_404(stack, registered):
    """Names the router matches by accident, or does not match, reach no service."""
    status, body = stack.https(LOOKALIKE, verified=False)
    assert status == 404 and "The page you requested was not found" in body  # frps's page
    assert stack.https(TOO_DEEP, verified=False)[0] == 404


def test_plugin_not_reachable_through_traefik(stack, registered):
    request = json.dumps({"op": "Login", "content": {"user": "nobody", "metas": {"token": "x"}}})
    # The control: on the internal network the plugin answers, and says so in the body.
    internal = run("docker", "exec", "reverse-tunnel-frps", "wget", "-qO-", f"--post-data={request}",
                   "http://reverse-tunnel-plugin:9000/handler")  # fmt: skip
    assert '"reject": true' in internal.stdout
    for name in ("certs.invalid", f"{HOST}.{T}"):
        status, body = stack.https(name, "/handler", method="POST", body=request, verified=False)
        assert "reject" not in body, (name, status, body)


def test_foreign_name_refused(stack, registered, other):
    """A registered host may claim its own names and no one else's."""
    pem = Path("/etc/reverse-tunnel/bridge.pem")
    with Frpc(stack, OTHER, other, pem, {"own": f"{OTHER}.{T}", "foreign": f"{HOST}.{T}"}) as frpc:
        frpc.wait(r"own\].*start proxy success")
        frpc.wait(r"foreign\].*name not allowed")


def test_wrong_bridge_cert_refused(stack, registered, other):
    """frpc logs in with the bridge's certificate and not with another for the same name."""
    wrong = stack.tmp / "wrong.pem"
    wrong.write_text(make_cert(T)[0])
    with Frpc(stack, OTHER, other, wrong, {"own": f"{OTHER}.{T}"}) as frpc:
        frpc.wait(r"x509")
        assert not any("login to server success" in line for line in frpc.lines)
    with Frpc(stack, OTHER, other, "/etc/reverse-tunnel/bridge.pem", {"own": f"{OTHER}.{T}"}) as frpc:
        frpc.wait(r"login to server success")


def test_status_stop_start(stack, registered):
    """`status`, `stop` and `start` do what their help says; SSH works again after `start`."""
    assert "service: running" in stack.status()
    run("sudo", INSTALLED, "stop")
    assert "service: stopped" in stack.status()
    wait_until(lambda: not stack.ssh_works())
    run("sudo", INSTALLED, "start")
    assert "service: running" in stack.status()
    wait_until(stack.ssh_works)


def test_upgrade_through_tunnel_keeps_access(stack, registered):
    """`upgrade --from` run over SSH through the tunnel: the session may drop, the next one works, on the new binary."""
    wait_until(stack.pid)
    old_pid = stack.pid()
    new = stack.tmp / "reverse-tunnel-new"
    new.write_bytes(BUILT.read_bytes() + b"\ne2e upgrade\n")  # a different build; ELF ignores what follows it
    new.chmod(0o755)
    want = hashlib.sha256(new.read_bytes()).hexdigest()
    stack.ssh(f"sudo {INSTALLED} upgrade --from {new}")  # the restart cuts it
    pid = wait_until(lambda: (p := stack.pid()) != old_pid and p)
    assert hashlib.sha256(INSTALLED.read_bytes()).hexdigest() == want
    assert run("sudo", "sha256sum", f"/proc/{pid}/exe").stdout.split()[0] == want
    wait_until(stack.ssh_works)


def test_plugin_down_refuses_login_keeps_tunnel(stack, registered, other):
    """With the plugin down a tunnel keeps carrying SSH and no new login is let in; back up, it is."""
    stack.compose("stop", "reverse-tunnel-plugin")
    try:
        assert stack.ssh_works()
        with Frpc(stack, OTHER, other, "/etc/reverse-tunnel/bridge.pem", {"own": f"{OTHER}.{T}"}) as frpc:
            frpc.wait(r"login to the server failed")
            assert not any("login to server success" in line for line in frpc.lines)
            stack.compose("up", "-d", "reverse-tunnel-plugin")
            frpc.wait(r"login to server success")
    finally:
        stack.compose("up", "-d", "reverse-tunnel-plugin")


def test_revoke_then_frps_restart_refuses(stack, registered):
    """A revoked host's session continues until it reconnects, and is then refused."""
    stack.ctl("revoke", HOST)
    assert stack.ssh_works()
    since = len(frpc_log())
    stack.compose("restart", "reverse-tunnel-frps")
    assert wait_log(since, r"host not registered|login to server success") == "host not registered"
    assert not stack.ssh_works()
