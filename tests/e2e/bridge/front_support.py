"""The bridge stack under each front: bare HTTP, nginx, and the Traefik overlay. Every port is one Docker picked."""

import re
import shutil
import ssl
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
from bridge_support import FRPS_READY, GOOD_DOMAIN, GOOD_PASSWORD, REPO_ROOT, Project, make_project, run
from logwait import LineTail
from pki import Pki

HERE = Path(__file__).parent
COMPOSE_E2E = "compose.e2e.yaml"
CONTROL_HOST = "localhost"  # a name every machine resolves, so no test needs DNS or /etc/hosts
STAGING_HOST = "staging.localhost"
STAGING_ADDRESS = "127.0.0.1"  # the name-free way in: no SNI, so Traefik offers its default certificate
FRONTS = ("bare", "nginx", "caddy", "traefik")
# The line each front writes once it is serving what it was configured with; the tests wait on it, never on a health
# state. Measured: nginx logs it after it has bound its sockets, Caddy after its servers run, Traefik (debug level, no
# colour) when it has built the route for the control host from frps's labels.
READY: dict[str, str | re.Pattern[str]] = {
    "nginx": "start worker processes",
    "caddy": '"msg":"serving initial configuration"',
    "traefik": re.compile(r"Adding route for localhost .*routerName=rt-control@docker"),
}

# `examples/nginx.conf` as an operator copies it, adapted to a stack whose nginx is a container beside frps. Each edit is
# (text, replacement, how many times the example holds it); an example that drifts fails here instead of being skipped.
NGINX_EDITS = (
    ("bridge.example.com", CONTROL_HOST, 3),
    ("http://127.0.0.1:8080", "http://frps:8080", 1),
    ("http://127.0.0.1:7000", "http://frps:8001", 1),
)
HOST_HEADER = "proxy_set_header Host $host;"
# What nginx sends when the line above is left out: the name of the upstream, `frps:8080`.
HOST_HEADER_OMITTED = "proxy_set_header Host $proxy_host;"


def render_nginx(*, rewrite_host: bool = False) -> str:
    """The example nginx config for the e2e stack; `rewrite_host` drops the vhost's Host line, as a careless copy would."""
    text = (REPO_ROOT / "examples" / "nginx.conf").read_text(encoding="utf-8")
    for old, new, count in NGINX_EDITS:
        assert text.count(old) == count, f"examples/nginx.conf holds {text.count(old)} x {old!r}, expected {count}"
        text = text.replace(old, new)
    assert text.count(HOST_HEADER) == 2, "examples/nginx.conf no longer sets Host in both of its server blocks"
    return text.replace(HOST_HEADER, HOST_HEADER_OMITTED, 1) if rewrite_host else text


# `examples/Caddyfile` for the e2e stack: the same upstream edits, and the test CA's certificates instead of ACME.
CADDY_EDITS = (
    (
        "bridge.example.com {\n",
        f"{CONTROL_HOST} {{\n\ttls /etc/ssl/rt/{CONTROL_HOST}.pem /etc/ssl/rt/{CONTROL_HOST}.key\n", 1
    ),
    (
        "*.tunnel.example.com {\n",
        f"*.tunnel.example.com {{\n\ttls /etc/ssl/rt/{GOOD_DOMAIN}.pem /etc/ssl/rt/{GOOD_DOMAIN}.key\n",
        1,
    ),
    ("reverse_proxy 127.0.0.1:8080", "reverse_proxy frps:8080", 1),
    ("reverse_proxy 127.0.0.1:7000", "reverse_proxy frps:8001", 1),
)


def render_caddyfile() -> str:
    text = (REPO_ROOT / "examples" / "Caddyfile").read_text(encoding="utf-8")
    for old, new, count in CADDY_EDITS:
        assert text.count(old) == count, f"examples/Caddyfile holds {text.count(old)} x {old!r}, expected {count}"
        text = text.replace(old, new)
    return text


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Stack:
    project: Project
    front: str
    pki: Pki
    frps_log: LineTail
    front_log: LineTail | None
    admin: str  # base URL of frps's admin API, on the VM's loopback
    vhost: Endpoint  # where `<label>.<domain>` is served: the front's 443, or frps's own vhost publish when bare
    control: Endpoint  # frps's control port, published directly (tcp)
    control_udp: Endpoint  # the same port number's UDP publish, which Docker assigns separately
    control_front: Endpoint | None  # the same control port reached through the front, as `RT_CONTROL_HOST`
    ca_file: Path

    @property
    def secure(self) -> bool:
        return self.front != "bare"

    def request(self, host: str) -> httpx.Response:
        """A plain GET of `/` for `host`, sent to the front with that Host header (and SNI, when TLS)."""
        scheme = "https" if self.secure else "http"
        context = ssl.create_default_context(cafile=str(self.ca_file)) if self.secure else True
        with httpx.Client(verify=context, timeout=None) as client:
            return client.get(
                f"{scheme}://{self.vhost.address}/", headers={"Host": host}, extensions={"sni_hostname": host}
            )


def prepare_files(project: Project, pki: Pki, front: str, *, rewrite_host: bool) -> Path:
    """Write the compose overlay, certificates and front configuration the stack mounts; the CA file's path."""
    shutil.copy2(HERE / COMPOSE_E2E, project.root / COMPOSE_E2E)
    shutil.copy2(HERE / "traefik-dynamic.yaml", project.root / "e2e" / "traefik-dynamic.yaml")
    tls = project.root / "e2e" / "tls"
    tls.mkdir(parents=True)
    pki.issue(GOOD_DOMAIN, f"*.{GOOD_DOMAIN}").write(tls, GOOD_DOMAIN)
    pki.issue(CONTROL_HOST).write(tls, CONTROL_HOST)
    pki.issue(STAGING_HOST, STAGING_ADDRESS, staging=True).write(tls, STAGING_HOST)
    ca_file = project.root / "e2e" / "ca.pem"
    ca_file.write_bytes(pki.root_pem)
    (project.root / "e2e" / "Caddyfile").write_text(render_caddyfile(), encoding="utf-8")
    (project.root / "e2e" / "nginx.conf").write_text(render_nginx(rewrite_host=rewrite_host), encoding="utf-8")
    return ca_file


@contextmanager
def running_stack(directory: Path, pki: Pki, front: str, *, rewrite_host: bool = False) -> Generator[Stack]:
    """Start the bridge under `front`, wait for the log lines that say it is serving, and take it down afterwards."""
    assert front in FRONTS, front
    network = f"rt-e2e-proxy-{uuid.uuid4().hex[:10]}"
    project = make_project(
        directory,
        RT_CONTROL_PORT="0",
        RT_VHOST_PORT="0",
        RT_ADMIN_PORT="0",
        RT_CONTROL_HOST=CONTROL_HOST,
        RT_PROXY_NETWORK=network,
    )
    (project.root / "e2e").mkdir()
    ca_file = prepare_files(project, pki, front, rewrite_host=rewrite_host)
    overlay = front == "traefik"
    profiles = (front, ) if front != "bare" else ()
    options = tuple(argument for profile in profiles for argument in ("--profile", profile))
    extra = (COMPOSE_E2E, )
    if overlay:
        created = run("docker", "network", "create", network)
        assert created.returncode == 0, created.stderr
    try:
        frps_log = project.up(overlay=overlay, extra_files=extra, profiles=profiles)
        front_log = None
        if front != "bare":
            front_log = project.tail(front, overlay=overlay, extra_files=extra, profiles=profiles)
            project.tails.append(front_log)
            front_log.wait_for(READY[front], after=0)

        def port(service: str, number: int, protocol: str = "tcp") -> int:
            result = project.compose(
                *options, "port", "--protocol", protocol, service, str(number), overlay=overlay, extra_files=extra
            )
            assert result.returncode == 0, result.stderr
            return int(result.stdout.strip().rsplit(":", 1)[1])

        loopback = "127.0.0.1"
        secure = Endpoint(loopback, port(front, 443)) if front != "bare" else None
        yield Stack(
            project=project,
            front=front,
            pki=pki,
            frps_log=frps_log,
            front_log=front_log,
            admin=f"http://{loopback}:{port('frps', 7500)}",
            vhost=secure or Endpoint(loopback, port("frps", 8080)),
            control=Endpoint(loopback, port("frps", 8001)),
            control_udp=Endpoint(loopback, port("frps", 8001, "udp")),
            control_front=secure,
            ca_file=ca_file,
        )
    finally:
        try:
            project.down(overlay=overlay, extra_files=extra, profiles=profiles)
        finally:
            if overlay:
                removed = run("docker", "network", "rm", network)
                assert removed.returncode == 0, removed.stderr
