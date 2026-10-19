"""Fakes for everything `ctl doctor` reaches, and deployments they describe.

Each fake encodes a belief about the outside world (docker's JSON, frps's answers, a certificate's issuer), which is
why the belief is spelled out here once instead of in every test. Task 11 forces each condition for real.
"""

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

import httpx
from tests.unit.deployment_support import GOOD_TOKEN, REPO_ROOT, write_env
from tests.unit.host_support import HostTree, build_host

from ctl import perms
from ctl.config import Config, Role
from ctl.doctor import Check, Outcome
from ctl.doctor.probes import Probes, TcpResult, TlsProbeError

LABEL = "alpha"
DOMAIN = "tunnel.example.com"
CONTAINER_ID = "0123456789ab"
PS_ENTRY = {
    "ID": CONTAINER_ID, "Name": "frps", "Service": "frps", "State": "running", "Health": "healthy",
    "Status": "Up 5 minutes (healthy)"
}
PORT_BINDINGS = {
    "8001/tcp": [{"HostIp": "", "HostPort": "7000"}],
    "8001/udp": [{"HostIp": "", "HostPort": "7000"}],
    "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}],
    "7500/tcp": [{"HostIp": "127.0.0.1", "HostPort": "7500"}],
}
SSH_BANNER = "SSH-2.0-OpenSSH_9.6"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def by_name(checks: Sequence[Check]) -> dict[str, Check]:
    names = [check.name for check in checks]
    assert len(names) == len(set(names)), f"a check is reported twice: {names}"
    return {check.name: check for check in checks}


def failures(checks: Sequence[Check]) -> list[str]:
    return [check.name for check in checks if check.outcome is Outcome.FAIL]


# Docker ===============================================================================================================


class FakeDocker:
    """Scripted `docker` answers keyed by argv tokens; the first rule whose tokens all appear in a call answers it."""

    def __init__(self) -> None:
        self.rules: list[tuple[tuple[str, ...], subprocess.CompletedProcess[str] | Exception]] = []
        self.calls: list[list[str]] = []

    def on(self, *match: str, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.rules.insert(0, (match, subprocess.CompletedProcess(list(match), returncode, stdout, stderr)))

    def raises(self, *match: str, error: Exception) -> None:
        self.rules.insert(0, (match, error))

    def __call__(self, args: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(args))
        for match, answer in self.rules:
            if all(token in args for token in match):
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise AssertionError(f"unscripted docker call: docker {' '.join(args)}")

    def healthy(
        self,
        *,
        state: str = "running",
        health: str = "healthy",
        bindings: dict | None = None,
        restart: str = "unless-stopped"
    ) -> None:
        """A running, healthy frps with the ports compose.yaml publishes and the restart policy it declares."""
        entry = PS_ENTRY | {"State": state, "Health": health}
        self.on("version", stdout="27.0.0\n")
        self.on("ps", stdout=json.dumps(entry) + "\n")
        inspected = [{"HostConfig": {"RestartPolicy": {"Name": restart}, "PortBindings": bindings or PORT_BINDINGS}}]
        self.on("inspect", stdout=json.dumps(inspected))

    def recorded(self, *, config: bytes, token: bytes) -> None:
        """The digests the entrypoint wrote in the container, in `sha256sum`'s format."""
        self.on("exec", "/run/rt/config.sha256", stdout=f"{sha256(config)}  /run/rt/work/bridge/frps.toml\n")
        self.on("exec", "/run/rt/token.sha256", stdout=f"{sha256(token)}  /run/rt/work/secrets/token\n")


# The network ==========================================================================================================


class Net:
    """frps's admin API, its vhost, the public front, and the front a host probes, as one `httpx` transport."""

    def __init__(self, *, admin_port: int = 7500, vhost_port: int = 8080) -> None:
        self.admin_port, self.vhost_port = admin_port, vhost_port
        self.requests: list[httpx.Request] = []
        self.healthz = httpx.Response(200, text="OK")
        self.vhost = httpx.Response(404, text="The page you requested was not found.")
        self.front: httpx.Response | Exception = httpx.Response(
            400, headers={"Server": "websocat"}, text="Only WebSocket connections are welcome here"
        )
        self.proxies: list[dict] = [{
            "name": f"{LABEL}.ssh", "user": LABEL, "clientID": "c-1", "status": {"phase": "online"}
        }]
        self.clients: list[dict] = [{"key": "k-1", "user": LABEL, "clientID": "c-1", "online": True}]
        self.page_size: int | None = None  # None: everything on page 1
        self.truncate_clients_at: int | None = None  # stop serving client entries past this many, total unchanged
        self.truncate_proxies_at: int | None = None
        self.truncate_filtered_at: int | None = None  # as `truncate_clients_at`, but only for `user`-filtered queries
        self.down = False  # nothing answers on any loopback port, as when the container is not running
        self.stale_clients: list[dict] | None = None  # what an unfiltered, mid-churn listing claims, if not the truth

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if self.down and host == "127.0.0.1":
            raise httpx.ConnectError("connection refused", request=request)
        port = request.url.port or {"http": 80, "https": 443}[request.url.scheme]
        if host == "127.0.0.1" and port == self.admin_port:
            if path == "/healthz":
                return self.healthz
            if path == "/api/v2/proxies":
                return self._page(request, self.proxies, limit=self.truncate_proxies_at)
            if path == "/api/v2/clients":
                stale = self.stale_clients is not None and "user" not in request.url.params
                limit = self.truncate_filtered_at if "user" in request.url.params else self.truncate_clients_at
                return self._page(request, self.stale_clients if stale else self.clients, limit=limit)
            return httpx.Response(404)
        if host == "127.0.0.1" and port == self.vhost_port:
            return self.vhost
        if isinstance(self.front, Exception):
            raise self.front
        return self.front

    def _page(self, request: httpx.Request, items: list[dict], limit: int | None = None) -> httpx.Response:
        params = request.url.params
        wanted = [item for item in items if (not params.get("user") or item.get("user") == params["user"])]
        if params.get("status") == "online":  # a server-side filter, like `user`
            wanted = [item for item in wanted if item.get("online", item.get("status", {}).get("phase") == "online")]
        total = len(wanted)
        if limit is not None:
            wanted = wanted[:limit]
        number = int(params.get("page", "1"))
        size = self.page_size or max(len(wanted), 1)
        window = wanted[(number - 1) * size:number * size]
        return httpx.Response(200, json={"code": 200, "data": {"total": total, "items": window}})

    def asked(self, host: str, port: int | None = None) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.host == host and (port is None or r.url.port == port)]


# Sockets and certificates =============================================================================================


class FakeTcp:
    """Answers per (host, port); anything not scripted refuses the connection."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, int], TcpResult] = {}
        self.calls: list[tuple[str, int, bool]] = []

    def listening(self, port: int, banner: str = "") -> None:
        self.answers[("127.0.0.1", port)] = TcpResult(None, banner)

    def refusing(self, port: int, error: str = "connection refused") -> None:
        self.answers[("127.0.0.1", port)] = TcpResult(error, "")

    def __call__(self, host: str, port: int, *, read_banner: bool) -> TcpResult:
        self.calls.append((host, port, read_banner))
        return self.answers.get((host, port), TcpResult("connection refused", ""))


class FakeTls:

    def __init__(self, *, chain_error: str | None = None, issuer: str = "Example Trusted CA R3") -> None:
        self.chain_error, self.issuer_name = chain_error, issuer
        self.unreachable: str | None = None
        self.validations: list[tuple[str, int, str | None]] = []
        self.issuer_lookups: list[tuple[str, int]] = []

    def validate(self, host: str, port: int, cafile: str | None) -> str | None:
        self.validations.append((host, port, cafile))
        return self.chain_error

    def issuer(self, host: str, port: int) -> str:
        self.issuer_lookups.append((host, port))
        if self.unreachable:
            raise TlsProbeError(self.unreachable)
        return self.issuer_name


# Deployments ==========================================================================================================


def install_secrets(root: Path, token: str = GOOD_TOKEN) -> None:
    """`secrets/token` as `ctl install` leaves it. Modes and owners are the platform tests' business, see `World.principals`."""
    (root / "secrets").mkdir(exist_ok=True)
    (root / "secrets" / "token").write_text(token + "\n", encoding="utf-8")


@dataclasses.dataclass
class World:
    """The deployment under test and the fakes standing for the machine around it."""

    root: Path
    docker: FakeDocker = dataclasses.field(default_factory=FakeDocker)
    net: Net = dataclasses.field(default_factory=Net)
    tcp: FakeTcp = dataclasses.field(default_factory=FakeTcp)
    tls: FakeTls = dataclasses.field(default_factory=FakeTls)
    granted: dict[Path, frozenset[str]] = dataclasses.field(
        default_factory=dict
    )  # what a path grants, where not as installed

    @property
    def config(self) -> Config:
        return Config.load(self.root)

    def expected(self, path: Path, *, mode: int | None = None) -> frozenset[str]:
        """What `ctl install` grants `path`: spelled out here, apart from `ctl.doctor.permissions`, as its oracle."""
        modes = {".env": 0o600, "secrets": 0o711, "token": 0o600}
        operator = perms.operator_account(self.root).name
        service = perms.service_account(self.config).name if self.config.role is Role.HOST else operator
        owner = operator if path.name == ".env" else service
        return frozenset({f"owner={owner}", f"mode={modes[path.name] if mode is None else mode:04o}"})

    def principals(self, path: Path) -> frozenset[str]:
        """Stands in for `perms.principals`, so these tests do not depend on the files' real modes or owners."""
        if not os.path.lexists(path):
            raise FileNotFoundError(2, "No such file or directory", str(path))
        return self.granted.get(path) or self.expected(path)

    def loosen(self, path: Path, mode: int) -> None:
        self.granted[path] = self.expected(path, mode=mode)

    def probes(self, **overrides) -> Probes:
        probes = Probes(
            docker=self.docker,
            tcp=self.tcp,
            tls=self.tls,
            transport=self.net.transport,
            principals=self.principals,
            windows=False
        )
        return dataclasses.replace(probes, **overrides)

    def edit_env(self, **values: str) -> None:
        env = {}
        for line in (self.root / ".env").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            env[key] = value
        env.update(values)
        (self.root /
         ".env").write_text("".join(f"{key}={value}\n" for key, value in env.items()), encoding="utf-8", newline="\n")


def build_bridge(tmp_path: Path, **env: str) -> World:
    """A bridge as `ctl install` and `docker compose up` leave it: secured files, a healthy frps, answering ports."""
    root = tmp_path / "bridge-deployment"
    root.mkdir()
    (root / "bridge").mkdir()
    shutil.copy(REPO_ROOT / "bridge" / "frps.toml", root / "bridge" / "frps.toml")
    write_env(root, Role.BRIDGE, **env)
    install_secrets(root)
    world = World(root)
    world.docker.healthy()
    world.docker.recorded(
        config=(root / "bridge" / "frps.toml").read_bytes(), token=(root / "secrets" / "token").read_bytes()
    )
    return world


def build_host_world(tmp_path: Path, monkeypatch, **env: str) -> tuple[World, HostTree]:
    """A converged host: pinned binaries and record, both daemons running and current, ports and front answering."""
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    tree = build_host(tmp_path, monkeypatch, **({"RT_LABEL": LABEL} | env))
    tree.converge()
    install_secrets(tree.root)
    world = World(tree.root)
    world.tcp.listening(int(tree.config.require("RT_WS_PORT")))
    world.tcp.listening(int(tree.config.require("RT_SSH_PORT")), SSH_BANNER)
    return world, tree


def build_client(tmp_path: Path) -> World:
    root = tmp_path / "client-deployment"
    root.mkdir()
    write_env(root, Role.CLIENT)
    (root / "bin").mkdir()
    (root / "bin" / "websocat").write_bytes(b"websocat bytes")
    (root / "bin" / ".digests.json").write_text(json.dumps({"websocat": sha256(b"websocat bytes")}), encoding="utf-8")
    return World(root)
