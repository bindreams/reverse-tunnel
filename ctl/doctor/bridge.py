# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The bridge's checks: Docker and the container, what frps says about itself and what it loaded, and its public front.

Everything that needs Docker hangs off one fact, whether Docker answers, and everything that needs the container off
another, whether it is running; each is reported once, by the check that owns it, and the checks behind it are not
applicable rather than failures of their own. Checks that only talk to the published loopback ports run regardless:
an operator outside the `docker` group has a running frps that `docker` cannot see.
"""

import functools
import hashlib
import json
import re
import subprocess
from typing import Any

import httpx

from ctl.atomic import read_file
from ctl.config import MAX_PORT, PORT, Config
from ctl.doctor import frps_api
from ctl.doctor.model import Check, Skip, Verdict, execute, fail, not_applicable, ok
from ctl.doctor.permissions import Permissions
from ctl.doctor.probes import DOCKER_TIMEOUT, Probes
from ctl.doctor.tls import TlsProbeError, is_staging
from ctl.errors import BinariesError

SERVICE = "frps"
RECREATE = "docker compose up -d --force-recreate"
LOOPBACK = "127.0.0.1"
CONTROL, VHOST = "8001", "8080/tcp"
DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
WILDCARDS = {"0.0.0.0": LOOPBACK, "::": "::1", "0:0:0:0:0:0:0:0": "::1"}
# Not a label any host would use; frps answers 404 for a name no proxy has registered.
UNREGISTERED = "rt-doctor-unregistered"


class DockerProblem(Exception):
    """Docker could not be run or asked; the message says why."""


class Found:
    """The result of listing the compose project: the frps container if there is one, or why it could not be listed."""

    def __init__(self, container: dict[str, Any] | None = None, problem: str | None = None) -> None:
        self.container, self.problem = container, problem


def parse_listing(text: str) -> list[dict[str, Any]]:
    """`docker compose ps --format json` prints a JSON array on older Compose and one object per line on newer."""
    text = text.strip()
    if not text:
        return []
    documents = json.loads(text) if text.startswith("[") else [
        json.loads(line) for line in text.splitlines() if line.strip()
    ]
    if not isinstance(documents, list) or not all(isinstance(entry, dict) for entry in documents):
        raise ValueError("not a list of objects")
    return documents


class Bridge:

    def __init__(self, config: Config, probes: Probes) -> None:
        self.config, self.probes, self.root = config, probes, config.root
        self.permissions = Permissions(config, probes)

    def checks(self) -> list[Check]:
        return execute([
            ("docker_reachable", self.docker_reachable),
            ("container_healthy", self.container_healthy),
            ("restart_policy", self.restart_policy),
            ("control_port_published", self.control_port_published),
            ("admin_healthz", self.admin_healthz),
            ("vhost_answers_404", self.vhost_answers_404),
            ("registered_labels", self.registered_labels),
            ("label_collisions", self.label_collisions),
            ("config_skew", lambda: self.skew("config.sha256", "bridge", "frps.toml", "bridge/frps.toml")),
            ("token_skew", lambda: self.skew("token.sha256", "secrets", "token", "secrets/token")),
            ("tls_chain_validates", self.tls_chain_validates),
            ("tls_issuer_is_not_staging", self.tls_issuer_is_not_staging),
            ("env_permissions", self.permissions.env),
            ("secrets_dir_permissions", self.permissions.secrets_dir),
            ("secrets_token_permissions", self.permissions.secrets_token),
        ])

    # Docker -----------------------------------------------------------------------------------------------------------

    def docker(self, *args: str) -> subprocess.CompletedProcess[str]:
        try:
            return self.probes.docker(args, cwd=self.root)
        except FileNotFoundError:
            raise DockerProblem("the docker command was not found on PATH") from None
        except subprocess.TimeoutExpired:
            raise DockerProblem(f"docker did not answer within {DOCKER_TIMEOUT} seconds") from None
        except OSError as exc:
            raise DockerProblem(f"docker could not be run: {exc.strerror or exc}") from exc

    @staticmethod
    def said(result: subprocess.CompletedProcess[str]) -> str:
        return " ".join((result.stderr.strip() or result.stdout.strip()).split()) or "it printed nothing"

    @functools.cached_property
    def docker_problem(self) -> str | None:
        """Why Docker cannot be used, or None. Asks the daemon, not just the client."""
        try:
            result = self.docker("version", "--format", "{{.Server.Version}}")
        except DockerProblem as exc:
            return str(exc)
        if result.returncode != 0:
            return f"docker could not reach its daemon (exit {result.returncode}): {self.said(result)}"
        return None

    @functools.cached_property
    def found(self) -> Found:
        try:
            result = self.docker("compose", "ps", "--all", "--format", "json")
        except DockerProblem as exc:
            return Found(problem=str(exc))
        if result.returncode != 0:
            return Found(problem=f"`docker compose ps` failed (exit {result.returncode}): {self.said(result)}")
        try:
            listing = parse_listing(result.stdout)
        except ValueError as exc:
            return Found(problem=f"`docker compose ps` printed something that is not JSON ({exc})")
        return Found(next((entry for entry in listing if entry.get("Service") == SERVICE), None))

    @functools.cached_property
    def host_config(self) -> dict[str, Any]:
        container = self.require_container()
        result = self.docker("inspect", str(container.get("ID", SERVICE)))
        if result.returncode != 0:
            raise DockerProblem(f"`docker inspect` failed (exit {result.returncode}): {self.said(result)}")
        try:
            return json.loads(result.stdout)[0]["HostConfig"]
        except (ValueError, LookupError, TypeError):
            raise DockerProblem("`docker inspect` printed something that is not a container's configuration") from None

    def require_container(self) -> dict[str, Any]:
        if self.docker_problem:
            raise Skip("Docker is not usable (see docker_reachable)")
        if self.found.problem:
            raise Skip("the containers could not be listed (see container_healthy)")
        if self.found.container is None:
            raise Skip(f"there is no {SERVICE} container (see container_healthy)")
        return self.found.container

    def require_running(self) -> dict[str, Any]:
        container = self.require_container()
        if container.get("State") != "running":
            raise Skip(f"the {SERVICE} container is not running (see container_healthy)")
        return container

    def skip_if_known_down(self) -> None:
        """For checks that talk to the published ports: when Docker shows the container is down, say so once."""
        if self.docker_problem or self.found.problem:
            return
        container = self.found.container
        if container is None or container.get("State") != "running":
            raise Skip(f"the {SERVICE} container is not running (see container_healthy)")

    def docker_reachable(self) -> Verdict:
        if self.docker_problem:
            return fail(
                f"Docker is not usable: {self.docker_problem}. Every check that asks the container is skipped until it is"
            )
        return ok("the docker daemon answered")

    def container_healthy(self) -> Verdict:
        if self.docker_problem:
            raise Skip("Docker is not usable (see docker_reachable)")
        if self.found.problem:
            return fail(self.found.problem)
        container = self.found.container
        if container is None:
            return fail(
                f"there is no {SERVICE} container in this project; start the bridge with `docker compose up -d`"
            )
        state, health = container.get("State"), container.get("Health")
        if state != "running":
            return fail(f"the {SERVICE} container is {state}, not running; see `docker compose logs {SERVICE}`")
        if health != "healthy":
            return fail(
                f"the {SERVICE} container is running but {health or 'reports no health status'}; "
                f"see `docker compose logs {SERVICE}`"
            )
        return ok(f"the {SERVICE} container is running and healthy")

    def restart_policy(self) -> Verdict:
        try:
            policy = self.host_config.get("RestartPolicy", {}).get("Name") or "no"
        except DockerProblem as exc:
            return fail(str(exc))
        if policy == "no":
            return fail(
                "the container's restart policy is 'no', so a reboot or a docker restart leaves the bridge down for "
                "every host. compose.yaml declares `restart: unless-stopped`; recreate the container with `docker compose up -d`"
            )
        return ok(f"the container's restart policy is {policy}")

    def control_port_published(self) -> Verdict:
        try:
            bindings = self.host_config.get("PortBindings") or {}
        except DockerProblem as exc:
            return fail(str(exc))
        port = self.config.require("RT_CONTROL_PORT")
        problems = []
        for protocol in ("tcp", "udp"):
            published = sorted({entry.get("HostPort", "") for entry in bindings.get(f"{CONTROL}/{protocol}") or []})
            if port not in published:
                problems.append(f"{CONTROL}/{protocol} is published on {', '.join(published) or 'nothing'}")
        if problems:
            return fail(
                f"RT_CONTROL_PORT={port} must be published on tcp and udp (QUIC hosts need udp): {'; '.join(problems)}. "
                "A compose overlay that replaces `ports` must re-declare both"
            )
        return ok(f"port {port} is published on tcp and udp")

    # frps over its published ports ------------------------------------------------------------------------------------

    def get(self, url: str, **kwargs: Any) -> httpx.Response | str:
        """The response, or why there was none."""
        try:
            with self.probes.http() as client:
                return client.get(url, **kwargs)
        except httpx.HTTPError as exc:
            return f"cannot reach {url}: {exc}"

    def admin_url(self) -> str:
        return f"http://{LOOPBACK}:{self.config.require('RT_ADMIN_PORT')}"

    def admin_healthz(self) -> Verdict:
        self.skip_if_known_down()
        answer = self.get(f"{self.admin_url()}/healthz")
        if isinstance(answer, str):
            return fail(answer)
        if answer.status_code != 200:
            return fail(f"{self.admin_url()}/healthz answered HTTP {answer.status_code}, not 200")
        return ok(f"{self.admin_url()}/healthz answered 200")

    def vhost_answers_404(self) -> Verdict:
        try:
            bindings = self.host_config.get("PortBindings") or {}
        except DockerProblem as exc:
            return fail(str(exc))
        if not bindings.get(VHOST):
            return not_applicable(
                "the vhost port is not published (compose.traefik.yaml): frps's vhost is reached over the docker "
                "network by the front proxy, so there is nothing on this machine to probe"
            )
        self.skip_if_known_down()
        bind, port = self.config.require("RT_VHOST_BIND"), self.config.require("RT_VHOST_PORT")
        address = WILDCARDS.get(bind, bind)
        authority = f"[{address}]" if ":" in address else address
        url = f"http://{authority}:{port}/"
        answer = self.get(url, headers={"Host": f"{UNREGISTERED}.{self.config.require('RT_DOMAIN')}"})
        if isinstance(answer, str):
            return fail(answer)
        if answer.status_code != 404:
            return fail(
                f"{url} answered HTTP {answer.status_code} for a subdomain nobody registered; frps answers 404, so "
                "something else holds the port or frps is not routing"
            )
        return ok(f"{url} answered frps's 404 for an unregistered subdomain")

    # frps's admin API -------------------------------------------------------------------------------------------------

    def api(self, lister):
        self.skip_if_known_down()
        return lister(self.admin_url(), self.config.require("RT_ADMIN_PASSWORD"), transport=self.probes.transport)

    def registered_labels(self) -> Verdict:
        try:
            page = self.api(frps_api.list_proxies)
        except frps_api.FrpsApiError as exc:
            return fail(str(exc))
        if not page.complete:
            return fail(
                "the list of proxies is incomplete (paging stopped short of frps's total), so it cannot be trusted"
            )
        labels = sorted({proxy.user or proxy.name for proxy in page.items if proxy.phase != "offline"})
        return ok(f"{len(labels)} online: {', '.join(labels)}" if labels else "none online")

    def label_collisions(self) -> Verdict:
        """Collisions show only in the clients: with two claimants the proxies list the winner alone."""
        try:
            page = self.api(frps_api.list_clients)
        except frps_api.FrpsApiError as exc:
            return fail(str(exc))
        if not page.complete:
            return fail(
                "the list of clients is incomplete (paging stopped short of frps's total), so a second claimant of a "
                "label may be missing from it and 'no collision' cannot be said"
            )
        claimants: dict[str, list[str]] = {}
        for client in page.items:
            if client.online and client.user:
                claimants.setdefault(client.user, []).append(client.client_id or client.key)
        collided = {label: ids for label, ids in claimants.items() if len(ids) > 1}
        if collided:
            listing = "; ".join(f"{label} is claimed by {', '.join(ids)}" for label, ids in sorted(collided.items()))
            return fail(
                f"{listing}. Only one claimant is routed, and the loser takes the label over when the winner "
                "disconnects; give each host its own RT_LABEL"
            )
        return ok(f"{len(claimants)} online client(s), none sharing a label")

    # What frps loaded -------------------------------------------------------------------------------------------------

    def skew(self, recorded_name: str, directory: str, name: str, shown: str) -> Verdict:
        """The digest the entrypoint recorded of what frps loaded against the file on disk now: content, never mtime."""
        self.require_running()
        try:
            result = self.docker("compose", "exec", "-T", SERVICE, "cat", f"/run/rt/{recorded_name}")
        except DockerProblem as exc:
            return fail(str(exc))
        if result.returncode != 0:
            return fail(f"the container's record of {shown} could not be read: {self.said(result)}")
        fields = result.stdout.split()
        if not fields or not DIGEST.fullmatch(fields[0]):
            return fail(f"the container's record of {shown} is not a digest")
        try:
            content = read_file(self.root / directory, name)
        except (BinariesError, OSError) as exc:
            return fail(str(exc))
        if content is None:
            return fail(f"{self.root / directory / name} is missing; run `ctl install`")
        if hashlib.sha256(content).hexdigest() != fields[0]:
            return fail(
                f"frps is running with a different {shown} than the one on disk now, and reads it only at startup. "
                f"Apply it with `{RECREATE}`; recreating drops every connected tunnel, and a host that does not hold "
                "the new token will not reconnect"
            )
        return ok(f"frps loaded the {shown} that is on disk")

    # The public front -------------------------------------------------------------------------------------------------

    def tls_target(self) -> tuple[str, int, str | None]:
        host = self.config.values.get("RT_PUBLIC_HOST", "")
        if not host:
            raise Skip("RT_PUBLIC_HOST is not set, so there is no public front to check")
        if self.config.values.get("RT_SCHEME") == "ws":
            raise Skip("RT_SCHEME=ws: the public front does not terminate TLS")
        port = self.config.values.get("RT_PUBLIC_PORT") or "443"
        if not PORT.fullmatch(port) or int(port) > MAX_PORT:
            raise ValueError(f"RT_PUBLIC_PORT={port!r} is not a port")
        return host, int(port), self.config.values.get("RT_TLS_CA_BUNDLE") or None

    def tls_chain_validates(self) -> Verdict:
        host, port, bundle = self.tls_target()
        problem = self.probes.tls.validate(host, port, bundle)
        trust = "the system store" + (f" and {bundle}" if bundle else "")
        if problem:
            return fail(
                f"the certificate chain at {host}:{port} does not validate for {host} against {trust}: {problem}"
            )
        return ok(f"the chain at {host}:{port} validates for {host} against {trust}")

    def tls_issuer_is_not_staging(self) -> Verdict:
        """Read from an unverified fetch, so it gives a verdict even for the chain the check above refused."""
        host, port, _ = self.tls_target()
        try:
            issuer = self.probes.tls.issuer(host, port)
        except TlsProbeError as exc:
            return fail(f"the issuer at {host}:{port} could not be inspected: {exc}")
        if is_staging(issuer):
            return fail(
                f"{host}:{port} is served with a staging certificate (issuer {issuer}); no client trusts it. Switch the "
                "front proxy's ACME directory to production and renew"
            )
        return ok(f"the certificate at {host}:{port} was issued by {issuer}")


def checks(config: Config, probes: Probes) -> list[Check]:
    return Bridge(config, probes).checks()
