# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Everything doctor reaches outside the repository, behind one seam so tests can stand in for each of it."""

import dataclasses
import socket
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NamedTuple, Protocol

import httpx

from ctl import perms, perms_windows, winacl
from ctl.doctor import tls
from ctl.doctor.tls import SocketTls, TlsProbe, TlsProbeError  # noqa: F401  re-exported: callers import them from here

# Each of these is a failure bound shown to a human for an event outside this process; none synchronises anything.
# external-bound: docker answering.
DOCKER_TIMEOUT = 60
# external-bound: a local port accepting a connection and sshd sending its banner.
TCP_TIMEOUT = 5.0
# external-bound: the public front answering the data-path probe.
HTTP_TIMEOUT = httpx.Timeout(15.0)


class DockerRunner(Protocol):

    def __call__(self, args: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
        """Run `docker <args>` in `cwd`. Raise `OSError` (`FileNotFoundError`: no docker) or `TimeoutExpired`."""


def run_docker(args: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=DOCKER_TIMEOUT,
    )


class TcpResult(NamedTuple):
    error: str | None  # None: the connection was accepted
    banner: str  # the first line the server sent, if asked for


class TcpProbe(Protocol):

    def __call__(self, host: str, port: int, *, read_banner: bool) -> TcpResult:
        """Connect to `host:port`; with `read_banner`, also read what the server says first."""


def connect_tcp(host: str, port: int, *, read_banner: bool) -> TcpResult:
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT) as connection:
            if not read_banner:
                return TcpResult(None, "")
            received = connection.recv(256).decode("ascii", errors="replace").splitlines()
            return TcpResult(None, received[0] if received else "")
    except TimeoutError:
        return TcpResult(f"no answer within {TCP_TIMEOUT:g} seconds", "")
    except OSError as exc:
        return TcpResult(exc.strerror or str(exc), "")


@dataclasses.dataclass(frozen=True)
class Probes:
    """What doctor asks of the world. The defaults are the real thing; a test replaces the part it is about."""

    docker: DockerRunner = run_docker
    tcp: TcpProbe = connect_tcp
    tls: TlsProbe = dataclasses.field(default_factory=SocketTls)
    transport: httpx.BaseTransport | None = None  # None: the real network
    principals: Callable[[Path], frozenset[str]] = perms.principals
    acl: Callable[[Path], winacl.Acl] = winacl.read_acl
    # Every ACE, inherit-only ones included, which `acl` leaves out: the files-only ACE on `host` is one.
    entries: Callable[[Path], tuple[list[winacl.Entry], bool]] = winacl.read_dacl
    operator_sid: Callable[[Path], str] = perms_windows.operator_sid
    windows: bool = sys.platform == "win32"

    def http(self, ca_bundle: str | None = None) -> httpx.Client:
        """An HTTP client that follows no redirect and, on the real network, trusts the system store plus `ca_bundle`."""
        if self.transport is not None:
            return httpx.Client(transport=self.transport, timeout=HTTP_TIMEOUT, follow_redirects=False)
        return httpx.Client(verify=tls.build_context(ca_bundle), timeout=HTTP_TIMEOUT, follow_redirects=False)
