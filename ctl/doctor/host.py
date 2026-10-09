# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""A host's checks: what is installed is what is tracked, both daemons run, and the tunnel carries traffic.

A host cannot reach the bridge's admin API, which is published on the bridge's loopback only, so "is my label
registered" is a data-path probe through the public front. It proves a tunnel for the label is serving, not that it is
this host's: under the shared token a second claimant takes the label over when the first disconnects, and nothing a
host can see tells the two apart. That needs `/api/v2/clients` on the bridge (`ctl doctor` there reports it).
"""

import functools

import httpx

from ctl import goetia
from ctl import host as installer
from ctl.client import DEFAULT_PORTS
from ctl.config import Config
from ctl.doctor.digests import binaries_match_record, input_matches_record
from ctl.doctor.model import Check, Skip, Verdict, execute, fail, ok
from ctl.doctor.permissions import Permissions
from ctl.doctor.probes import Probes
from ctl.doctor.tls import TlsProbeError, verification_failure
from ctl.errors import InstallError
from ctl.goetia import GoetiaError, Report

LOOPBACK = "127.0.0.1"
HTTP_SCHEMES = {"ws": "http", "wss": "https"}
SSH_BANNER = "SSH-"
INSTALL = "run `ctl install`"
SERVICE_CHECKS = {installer.FRPC_ID: "frpc_service", installer.WEBSOCAT_ID: "websocat_service"}


class Status:
    """What `goetia daemon status --json` said about the two daemons, or why it could not be asked."""

    def __init__(self, report: Report | None = None, problem: str | None = None, available: bool = True) -> None:
        self.report, self.problem, self.available = report, problem, available


class Host:

    def __init__(self, config: Config, probes: Probes) -> None:
        self.config, self.probes, self.root = config, probes, config.root
        self.permissions = Permissions(config, probes)

    def checks(self) -> list[Check]:
        return execute([
            ("bin_digests_match_record", self.binaries),
            ("token_matches_record", self.token),
            ("frpc_config_matches_record", self.frpc_config),
            ("frpc_service", lambda: self.service(installer.FRPC_ID)),
            ("websocat_service", lambda: self.service(installer.WEBSOCAT_ID)),
            ("frpc_spec_current", lambda: self.spec(installer.FRPC_ID)),
            ("websocat_spec_current", lambda: self.spec(installer.WEBSOCAT_ID)),
            ("websocat_listening", self.websocat_listening),
            ("local_target_answers", self.local_target),
            ("env_permissions", self.permissions.env),
            ("secrets_dir_permissions", self.permissions.secrets_dir),
            ("secrets_token_permissions", self.permissions.secrets_token),
            ("tunnel_end_to_end", self.tunnel),
        ])

    # Files ------------------------------------------------------------------------------------------------------------

    def binaries(self) -> Verdict:
        suffix = ".exe" if self.probes.windows else ""
        required = [name + suffix for name in installer.HOST_BINARIES]
        return binaries_match_record(self.root, required, inputs=set(installer.READS[installer.FRPC_ID]))

    def token(self) -> Verdict:
        """Compared with `RT_TOKEN`, from which install writes `secrets/token`: the file itself is never opened."""
        return input_matches_record(
            self.root,
            "token",
            installer.token_digest(self.config),
            what="RT_TOKEN in .env (secrets/token is written from it)"
        )

    def frpc_config(self) -> Verdict:
        try:
            actual = installer.frpc_toml_digest(self.root)
        except InstallError as exc:
            return fail(str(exc))
        return input_matches_record(self.root, "frpc.toml", actual, what="host/frpc.toml")

    # goetia -----------------------------------------------------------------------------------------------------------

    @functools.cached_property
    def status(self) -> Status:
        if not goetia.available(self.root):
            return Status(available=False, problem=f"{goetia.executable(self.root)} is missing; {INSTALL}")
        try:
            return Status(goetia.daemon_report(self.root, "status", installer.IDS))
        except GoetiaError as exc:
            return Status(problem=str(exc))

    def service(self, daemon_id: str) -> Verdict:
        status = self.status
        if status.report is None:
            return fail(status.problem or "goetia could not be asked")
        report = status.report
        problems = [p for p in report.problems if p.id in (daemon_id, None)]
        state = next((d for d in report.daemons if d.id == daemon_id), None)
        reasons = [str(problem) for problem in problems]
        if state is None:
            reasons.append(f"{daemon_id} is not installed")
        else:
            if state.state != "running":
                reasons.append(f"{daemon_id} is {state.state}")
            if not state.enabled:
                reasons.append(f"{daemon_id} is not enabled")
        if reasons:
            return fail(f"{'; '.join(reasons)}; {INSTALL}, which installs, enables and restarts what is wrong")
        assert state is not None
        return ok(f"{daemon_id} is running (pid {state.pid}) and enabled")

    def spec(self, daemon_id: str) -> Verdict:
        """The installed unit against what the tracked manifest renders now. `show`, never `diff`: its exit code is 0 both ways."""
        status = self.status
        if not status.available:
            raise Skip(f"goetia is not in bin/ (see {SERVICE_CHECKS[daemon_id]})")
        if status.report is not None and daemon_id not in {d.id for d in status.report.daemons}:
            raise Skip(f"{daemon_id} is not installed (see {SERVICE_CHECKS[daemon_id]})")
        try:
            current = goetia.spec_is_current(self.root, daemon_id)
        except GoetiaError as exc:
            return fail(f"the installed unit could not be compared with goetia.yaml: {exc}")
        if not current:
            return fail(
                f"the installed {daemon_id} differs from what goetia.yaml (with .env) renders now; {INSTALL} to "
                "install the new unit and restart the daemon"
            )
        return ok(f"the installed {daemon_id} is what goetia.yaml renders")

    # Sockets ----------------------------------------------------------------------------------------------------------

    def websocat_listening(self) -> Verdict:
        port = int(self.config.require("RT_WS_PORT"))
        result = self.probes.tcp(LOOPBACK, port, read_banner=False)
        if result.error:
            return fail(
                f"nothing accepts connections on {LOOPBACK}:{port} ({result.error}), so websocat is not listening "
                "where frpc forwards"
            )
        return ok(f"websocat accepts connections on {LOOPBACK}:{port}")

    def local_target(self) -> Verdict:
        port = int(self.config.require("RT_SSH_PORT"))
        result = self.probes.tcp(LOOPBACK, port, read_banner=True)
        if result.error:
            return fail(f"nothing accepts connections on {LOOPBACK}:{port} ({result.error}); is sshd running there?")
        if not result.banner.startswith(SSH_BANNER):
            seen = f"answered {result.banner!r}" if result.banner else "connected but sent nothing"
            return fail(
                f"{LOOPBACK}:{port} {seen}, which is not an SSH server (an SSH banner starts with {SSH_BANNER!r})"
            )
        return ok(f"{LOOPBACK}:{port} answered with {result.banner}")

    # The data path ----------------------------------------------------------------------------------------------------

    def probe_url(self) -> str:
        """`<scheme>://<label>.<domain>[:<port>]/`, with the port whenever it is not the scheme's default."""
        scheme, port = self.config.require("RT_SCHEME"), int(self.config.require("RT_PUBLIC_PORT"))
        host = f"{self.config.require('RT_LABEL')}.{self.config.require('RT_DOMAIN')}"
        authority = host if port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
        return f"{HTTP_SCHEMES[scheme]}://{authority}/"

    def tunnel(self) -> Verdict:
        url, label = self.probe_url(), self.config.require("RT_LABEL")
        try:
            with self.probes.http(self.config.values.get("RT_TLS_CA_BUNDLE") or None) as client:
                response = client.get(url)
        except TlsProbeError as exc:
            return fail(str(exc))
        except httpx.HTTPError as exc:
            if (untrusted := verification_failure(exc)) is not None:
                return fail(
                    f"the public front answered, but its certificate does not validate for {url}: "
                    f"{getattr(untrusted, 'verify_message', '') or untrusted}. This is a certificate problem, and the front itself is up: "
                    "a staging or private-CA certificate is the usual cause. `ctl doctor` on the bridge reports it as "
                    "tls_chain_validates and tls_issuer_is_not_staging; for a private CA set RT_TLS_CA_BUNDLE here"
                )
            return fail(
                f"the public front is unreachable: GET {url} failed ({exc}). Check DNS for the name, the front proxy, "
                "and RT_SCHEME and RT_PUBLIC_PORT"
            )
        server = response.headers.get("server")
        if response.status_code == 400 and server == "websocat":
            return ok(f"{url} reaches this host's websocat (HTTP 400, Server: websocat)")
        if response.status_code == 404 and server is None:
            return fail(
                f"frps has no route for label {label} (HTTP 404 from {url} with no Server header): either the label is "
                f"not registered upstream, or it is registered and the local backend is dead. websocat_listening "
                "tells the two apart"
            )
        return fail(
            f"{url} answered HTTP {response.status_code} with Server: {server or '(none)'}; a working tunnel answers "
            "400 from websocat"
        )


def checks(config: Config, probes: Probes) -> list[Check]:
    return Host(config, probes).checks()
