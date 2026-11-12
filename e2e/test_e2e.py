"""End to end: the real bridge (`server/`) behind Traefik and Pebble in Docker, and a real host, installed as a service
on this machine with `reverse-tunnel install`, with sshd and an HTTP stub.

Runs only on CI's `e2e` job (`RT_E2E=1`), which installs a service, edits /etc/hosts and uses port 443 and 22: never
on a developer's machine. The tests are one scenario and run in file order: the host is registered by the second
test, and the last ones break it.

A wait that never ends is stopped by the pytest step's 20-minute timeout.
"""

import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from http.client import HTTPConnection, HTTPException, HTTPSConnection
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
OTHER_NAME = f"{OTHER}.{T}"
BACKEND = f"web.{HOST}.{T}"
ADDED = f"blog.{HOST}.{T}"  # a second HTTP service, added to config.yaml after the host is running
ALIAS = "movies.binarydreams.me"
LOOKALIKE = "x.tunnelXbinarydreams.me"  # T with one character for its dot: the frps router must not match it
NOBODY = f"nobody.{T}"  # matches the frps router, and no host publishes it
TOO_DEEP = f"a.b.{HOST}.{T}"
# /etc/hosts has no wildcards: every name the tests connect to.
NAMES = [T, f"rt-dns-check.rt-dns-check.{T}", f"{HOST}.{T}", f"ssh.{HOST}.{T}", BACKEND, ADDED, ALIAS, LOOKALIKE,
         TOO_DEEP, NOBODY, OTHER_NAME, "certs.invalid"]  # fmt: skip
MARK = "e2e-stub"
FRPS_404 = "The page you requested was not found"  # frps's answer for a name no tunnel publishes


def http_service(name: str, port: int) -> str:
    """The `services:` entry of config.yaml for an HTTP service named `name`."""
    return f"  {name}:\n    port: {port}\n    type: http\n"


def client_template() -> str:
    """The README's `~/.ssh/config` block, for a host named `mothership`: its only `ssh-config` fenced block."""
    blocks = re.findall(r"^```ssh-config\n(.*?)^```$", (ROOT / "README.md").read_text(), re.DOTALL | re.MULTILINE)
    assert len(blocks) == 1, f"README.md must have exactly one ssh-config block, has {len(blocks)}"
    assert "mothership" in blocks[0], "README's ssh-config block lacks `mothership`: the template changed shape"
    return blocks[0]


def run(*args, cwd=None, env=None, check=True, input=None) -> subprocess.CompletedProcess:
    done = subprocess.run([str(a) for a in args], cwd=cwd, env=env, input=input, capture_output=True, text=True)
    if check and done.returncode:
        raise AssertionError(f"{args} ended with {done.returncode}\nstdout: {done.stdout}\nstderr: {done.stderr}")
    return done


def wait_until(condition):
    while not (value := condition()):
        time.sleep(0.5)
    return value


_retried: set[str] = set()


def _try(call, *args, **kwargs):
    """The call's result, or None when the request or connection failed in a way a retry may cure.

    Each distinct failure is printed once, so a persistent cause shows in the log.
    """
    try:
        return call(*args, **kwargs)
    except (ssl.SSLError, OSError, HTTPException) as error:
        if (message := f"{type(error).__name__}: {error}") not in _retried:
            _retried.add(message)
            print("retrying after", message, flush=True)
        return None


def frpc_log() -> str:
    """The log; empty while the supervisor has not created it."""
    done = run("sudo", "cat", FRPC_LOG, check=False)
    if done.returncode and "No such file" not in done.stderr:
        raise AssertionError(f"cat {FRPC_LOG} ended with {done.returncode}: {done.stderr}")
    return done.stdout


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
            print("frpc:", line, end="", flush=True)  # pytest -s: a hung wait leaves the log
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

    def ssh_command(self, command: str) -> tuple[list, dict]:
        options = ["IdentitiesOnly=yes", "StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "BatchMode=yes"]
        flags = [f"-o{o}" for o in options]
        env = {**os.environ, "SSL_CERT_FILE": str(self.root)}
        cmd = ["ssh", "-F", self.ssh_config, "-i", self.key, "-l", getpass.getuser(), "-oLogLevel=ERROR", *flags]
        return [*cmd, HOST, command], env

    def ssh_popen(self, command: str, output) -> subprocess.Popen:
        cmd, env = self.ssh_command(command)
        # Its own process group, so that `end_session` takes the ProxyCommand's websocat with it.
        return subprocess.Popen(cmd, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)

    @staticmethod
    def end_session(session: subprocess.Popen):
        """Kill the session and its children, and reap it. Until then its pid is still reserved as the group's id."""
        os.killpg(session.pid, signal.SIGKILL)
        session.wait()

    @staticmethod
    def session_exit(session: subprocess.Popen) -> int | None:
        """The session's exit code, or None while it runs; the session is not reaped (`poll` would reap it)."""
        done = os.waitid(os.P_PID, session.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if done is None:
            return None
        return done.si_status if done.si_code == os.CLD_EXITED else -done.si_status

    def pid_after_cut(self, command: str, old_pid: int, log: str) -> int:
        """The service's pid once `command`, run over SSH as the host's user, has restarted it.

        The restart cuts the session, and ssh may then wait for a connection that nothing closes: the session is
        ended here, and its output is kept in `log` under the test's temp directory.
        """
        output = self.tmp / log
        with open(output, "w") as out:
            session = self.ssh_popen(command, out)

            shown = False

            def restarted():
                nonlocal shown
                if (pid := self.pid()) not in (None, old_pid):
                    return pid
                # 255 is ssh losing the connection the restart cut; any other exit is the command failing before it.
                if (code := self.session_exit(session)) not in (None, 0, 255):
                    raise AssertionError(f"{command!r} ended with {code}, service not restarted:\n{output.read_text()}")
                if code == 255 and not shown:
                    shown = True
                    print(f"session ended with 255, service not restarted yet:\n{output.read_text()}", flush=True)

            try:
                return wait_until(restarted)
            finally:
                self.end_session(session)

    def ssh(self, command: str) -> subprocess.CompletedProcess:
        cmd, env = self.ssh_command(command)
        done = run(*cmd, env=env, check=False)
        if done.returncode:
            print(f"ssh {command!r} ended with {done.returncode}: {done.stderr.strip()}", flush=True)
        return done

    def ssh_works(self) -> bool:
        return self.ssh(f"echo {MARK}").stdout.strip() == MARK

    def https(self, name, path="/", *, method="GET", body=None, verified=True):
        """`(status, body)` of a request to `name`, which /etc/hosts sends to Traefik."""
        context = ssl.create_default_context(cafile=self.root if verified else None)
        if not verified:
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        connection = HTTPSConnection(name, 443, context=context)
        try:
            connection.request(method, path, body=body)
            response = connection.getresponse()
            return response.status, response.read().decode()
        finally:
            connection.close()

    def wait_served(self, name) -> dict:
        """The JSON the stub answers for `name`, once a verified request gets a 200."""
        _, body = wait_until(lambda: (answer := _try(self.https, name)) and answer[0] == 200 and answer)
        return json.loads(body)

    def frps_404(self, name) -> bool:
        """Whether `name` reaches frps and no tunnel answers it: Traefik's router matches and frps has no proxy.

        Retries, with no cap, a request that raises; any HTTP answer decides.
        """
        status, body = wait_until(lambda: _try(self.https, name, verified=False))
        return status == 404 and FRPS_404 in body

    def wait_unpublished(self, name):
        """Waits until frps has no proxy for `name`: an earlier test's may not be gone yet."""
        wait_until(lambda: self.frps_404(name))

    def peer_cert(self, name) -> dict:
        """The certificate Traefik serves for `name`, verified against Pebble's root; raises if it is not."""
        context = ssl.create_default_context(cafile=self.root)
        with socket.create_connection(("127.0.0.1", 443)) as sock:
            with context.wrap_socket(sock, server_hostname=name) as tls:
                return tls.getpeercert()

    def api(self, path):
        connection = HTTPConnection("127.0.0.1", 8088)
        try:
            connection.request("GET", f"/api/{path}")
            response = connection.getresponse()
            text = response.read().decode()
        finally:
            connection.close()
        return response.status, json.loads(text) if response.status == 200 else text

    def status(self) -> str:
        return run(INSTALLED, "status").stdout

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

    # Pebble's root changes at every start.
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

    # The client config is the README's template.
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", stack.key)
    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    with open(ssh_dir / "authorized_keys", "a") as keys:
        keys.write(Path(f"{stack.key}.pub").read_text())
    stack.ssh_config.write_text(client_template().replace("mothership", HOST))

    installed = run("sudo", BUILT, "install", "--host", HOST, "--join", code).stdout
    registration = re.search(r"uv run ctl add (\S+) (sha256:[0-9a-f]{64})", installed)
    assert registration, f"no `ctl add` line in the install output:\n{installed}"
    stack.registration = registration.groups()
    stack.stub_port = server.server_address[1]
    run("sudo", "tee", "-a", "/etc/reverse-tunnel/config.yaml", input=http_service("web", stack.stub_port))
    run("sudo", INSTALLED, "stop")
    stack.started_at = len(frpc_log())
    run("sudo", INSTALLED, "start")
    return stack


@pytest.fixture(scope="session")
def before_add(stack):
    """What the host and the bridge do before the bridge knows the host."""
    wait_log(stack.started_at, r"host not registered")
    return SimpleNamespace(pid=stack.pid(), log=len(frpc_log()))


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


def test_register_after_install(stack, before_add, registered):
    """SSH works after `ctl add`, with no restart of the host (`before_add` saw frpc refused before it)."""
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
    assert "certs.invalid" not in run("docker", "exec", "traefik", "cat", "/acme/dns-exec.log").stdout


def test_backend_name_reaches_http_service(stack, registered):
    """The host's HTTP service is reached through its own wildcard-certificate name and the frps router."""
    assert stack.wait_served(BACKEND) == {"marker": MARK, "host": BACKEND}


def test_alias_reaches_http_service(stack, alias):
    """A public name reaches the host's HTTP service, with the backend address as its `Host`."""
    assert stack.wait_served(ALIAS) == {"marker": MARK, "host": BACKEND}


def test_alias_routes_through_frps_vhost(stack, alias):
    router = wait_until(lambda: _router(stack, alias_key(ALIAS)))
    assert router["service"] == f"{FRPS_VHOST_SERVICE}@docker"
    frps = run("docker", "inspect", "-f", "{{.NetworkSettings.Networks.gateway.IPAddress}}", "reverse-tunnel-frps")
    service = stack.api(f"http/services/{FRPS_VHOST_SERVICE}@docker")[1]
    assert [s["url"] for s in service["loadBalancer"]["servers"]] == [f"http://{frps.stdout.strip()}:8080"]


def test_lookalike_domain_gets_404(stack, registered):
    """Names the frps router must not match are answered by Traefik's own 404, not passed to frps."""
    assert stack.frps_404(NOBODY)  # the control: a name the router matches reaches frps
    for name in (LOOKALIKE, TOO_DEEP):
        status, body = stack.https(name, verified=False)
        assert status == 404 and FRPS_404 not in body, (name, status, body)


def test_plugin_not_reachable_through_traefik(stack, registered):
    request = json.dumps({"op": "Login", "content": {"user": "nobody", "metas": {"token": "x"}}})
    # Control: the plugin answers on the internal network.
    # `ctl add` and `ctl alias` recreate the plugin, which may not listen yet.
    internal = wait_until(lambda: (done := run("docker", "exec", "reverse-tunnel-frps", "wget", "-qO-",
                                               f"--post-data={request}", "http://reverse-tunnel-plugin:9000/handler",
                                               check=False)).returncode == 0 and done)  # fmt: skip
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
    stack.wait_unpublished(OTHER_NAME)
    with Frpc(stack, OTHER, other, wrong, {"own": OTHER_NAME}) as frpc:
        frpc.wait(r"x509")
        assert stack.frps_404(OTHER_NAME)
    with Frpc(stack, OTHER, other, "/etc/reverse-tunnel/bridge.pem", {"own": OTHER_NAME}) as frpc:
        frpc.wait(r"own\].*start proxy success")


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
    new.write_bytes(BUILT.read_bytes() + b"\ne2e upgrade\n")  # ELF ignores trailing bytes
    new.chmod(0o755)
    want = hashlib.sha256(new.read_bytes()).hexdigest()
    pid = stack.pid_after_cut(f"sudo {INSTALLED} upgrade --from {new}", old_pid, "upgrade-session.log")
    assert hashlib.sha256(INSTALLED.read_bytes()).hexdigest() == want
    assert run("sudo", "sha256sum", f"/proc/{pid}/exe").stdout.split()[0] == want
    wait_until(stack.ssh_works)


def test_restart_applies_an_edited_config_through_the_tunnel(stack, registered):
    """`restart` run over SSH through the tunnel: a service added to config.yaml by hand is published afterwards."""
    wait_until(stack.pid)
    old_pid = stack.pid()
    entry = http_service("blog", stack.stub_port)
    edit = f"sudo tee -a /etc/reverse-tunnel/config.yaml > /dev/null <<'EOF'\n{entry}EOF"
    assert stack.ssh(edit).returncode == 0
    assert stack.frps_404(ADDED)  # the edit alone changes nothing: the service reads its config at start

    stack.pid_after_cut(f"sudo {INSTALLED} restart", old_pid, "restart-session.log")

    assert stack.wait_served(ADDED) == {"marker": MARK, "host": ADDED}
    wait_until(stack.ssh_works)


def test_plugin_down_refuses_login_keeps_tunnel(stack, registered, other):
    """With the plugin down a tunnel keeps carrying SSH and no new login is let in; back up, it is."""
    stack.wait_unpublished(OTHER_NAME)
    stack.compose("stop", "reverse-tunnel-plugin")
    try:
        assert stack.ssh_works()
        with Frpc(stack, OTHER, other, "/etc/reverse-tunnel/bridge.pem", {"own": OTHER_NAME}) as frpc:
            frpc.wait(r"send Login request to plugin error")
            assert stack.frps_404(OTHER_NAME)
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
