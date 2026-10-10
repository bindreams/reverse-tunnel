"""The bridge stack under each front: bare HTTP, nginx, and the Traefik overlay. Every port is one Docker picked."""

import shutil
import ssl
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
from bridge_support import GOOD_DOMAIN, GOOD_PASSWORD, REPO_ROOT, Project, make_project, run
from logwait import LineTail
from pki import Pki

HERE = Path(__file__).parent
COMPOSE_E2E = "compose.e2e.yaml"
CONTROL_HOST = "localhost"  # a name every machine resolves, so no test needs DNS or /etc/hosts
STAGING_HOST = "staging.localhost"
STAGING_ADDRESS = "127.0.0.1"  # the name-free way in: no SNI, so Traefik offers its default certificate
FRONTS = ("bare", "nginx", "traefik")

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
    admin: str  # base URL of frps's admin API, on the VM's loopback
    vhost: Endpoint  # where `<label>.<domain>` is served: the front's 443, or frps's own vhost publish when bare
    control: Endpoint  # frps's control port, published directly
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
    (project.root / "e2e" / "nginx.conf").write_text(render_nginx(rewrite_host=rewrite_host), encoding="utf-8")
    return ca_file


@contextmanager
def running_stack(directory: Path, pki: Pki, front: str, *, rewrite_host: bool = False) -> Generator[Stack]:
    """Start the bridge under `front`, wait until Docker reports every service healthy, and take it down afterwards."""
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
    options = ("--profile", front) if front != "bare" else ()
    extra = (COMPOSE_E2E, )
    if overlay:
        created = run("docker", "network", "create", network)
        assert created.returncode == 0, created.stderr
    frps_log: LineTail | None = None
    try:
        up = project.compose(*options, "up", "--detach", "--wait", "--build", overlay=overlay, extra_files=extra)
        assert up.returncode == 0, up.stdout + up.stderr
        frps_log = project.tail("frps", overlay=overlay, extra_files=extra)

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
            admin=f"http://{loopback}:{port('frps', 7500)}",
            vhost=secure or Endpoint(loopback, port("frps", 8080)),
            control=Endpoint(loopback, port("frps", 8001)),
            control_front=secure,
            ca_file=ca_file,
        )
    finally:
        if frps_log is not None:
            frps_log.close()
        down = project.compose(
            *options, "down", "--volumes", "--remove-orphans", "--rmi", "local", overlay=overlay, extra_files=extra
        )
        if overlay:
            removed = run("docker", "network", "rm", network)
            assert removed.returncode == 0, removed.stderr
        assert down.returncode == 0, down.stderr
