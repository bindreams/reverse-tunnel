"""The host side of a tunnel, run as plain processes: websocat and frpc from the pinned release, an echo target behind.

The commands and environments come from `goetia.yaml`, and `host/frpc.toml` is the tracked file itself, expanded by frpc
from that environment, so the tests fail if the shipped manifest or config stops working. Every wait is
`LineTail.wait_for` on a log line a process writes.
"""

import hashlib
import signal
import socket
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from bridge_support import GOOD_TOKEN, REPO_ROOT, clean_environment
from front_support import CONTROL_HOST, Stack
from logwait import ProcessTail, tail_process
from manifest import daemon

# The lines frp 0.71.0 writes, on the server and on the client. frps logs `close proxy [..] success` only when frpc sends
# a CloseProxy (a config reload that drops the proxy); a frpc that is stopped or dies is logged as `proxy closing`.
NEW_PROXY = "new proxy [{label}.ssh] type [http] success"
CLOSE_PROXY = "[{label}.ssh] proxy closing"
ALREADY_EXISTS = "[ssh] start error: proxy [{label}.ssh] already exists"
START_PROXY = "[ssh] start proxy success"
LISTENING = "LISTEN proto=tcp"


def new_label() -> str:
    """A label no other test used, so a log line replayed from an earlier test cannot be mistaken for this one's."""
    return f"t{uuid.uuid4().hex[:12]}"


def spawn(command: list[str | Path], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> ProcessTail:
    """Start `command` with stdout and stderr merged, and follow it. Closing the tail ends the process."""
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return tail_process(process)


class Host:
    """One reverse-tunnel host: websocat in front of an echo target, and frpc registering it under `label`.

    Built step by step and closed whatever step failed, so no process outlives the test that started it.
    """

    def __init__(self, directory: Path, binaries: dict[str, Path], label: str, target_port: int) -> None:
        self.label = label
        self._directory, self._binaries, self._target_port = directory, binaries, target_port
        self.websocat_log: ProcessTail | None = None
        self.frpc_log: ProcessTail | None = None
        # The port is reserved by a bound, never-listening socket for as long as the host lives: nothing else can be
        # handed it, and websocat (which sets SO_REUSEADDR like this socket does) can still listen on it.
        self._reserved = socket.socket()
        self._reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._reserved.bind(("127.0.0.1", 0))
        self.port: int = self._reserved.getsockname()[1]

    def _launch(self, name: str, **values: str) -> tuple[list[str | Path], Path, dict[str, str]]:
        """The manifest's command for daemon `name`, with the pinned binary in place of `bin/<name>`."""
        entry = daemon(name, {"RT_WS_PORT": str(self.port), "RT_SSH_PORT": str(self._target_port), **values})
        program = Path(entry.argv[0]).name
        return [self._binaries[program], *entry.argv[1:]], Path(entry.cwd), entry.env

    def start_websocat(self) -> None:
        """Start websocat as the manifest runs it, plus a flag that makes it say when it is listening."""
        command, _, environment = self._launch("reverse-tunnel-websocat")
        command.insert(1, "--stdout-announce-listening-ports")
        self.websocat_log = spawn(command, env={**clean_environment(), **environment})
        self.websocat_log.wait_for(LISTENING, after=0)

    def start_frpc(self, server: tuple[str, int], protocol: str, ca_file: Path | None = None) -> None:
        """Start frpc as the manifest runs it, on the tracked `host/frpc.toml`; it has not registered when this returns."""
        command, cwd, environment = self._launch(
            "reverse-tunnel-frpc",
            RT_LABEL=self.label,
            RT_SERVER_ADDR=server[0],
            RT_SERVER_PORT=str(server[1]),
            RT_PROTOCOL=protocol,
        )
        root = self._directory / f"host-{self.label}-{uuid.uuid4().hex[:8]}"
        (root / "host").mkdir(parents=True)
        (root / "secrets").mkdir()
        (root / cwd).mkdir()
        (root / "host" / "frpc.toml").write_bytes((REPO_ROOT / "host" / "frpc.toml").read_bytes())
        (root / "secrets" / "token").write_text(GOOD_TOKEN + "\n")
        environment = {**clean_environment(), **environment, **({"SSL_CERT_FILE": str(ca_file)} if ca_file else {})}
        self.frpc_log = spawn(command, cwd=root / cwd, env=environment)

    def stop_frpc(self) -> None:
        """Interrupt frpc as Ctrl-C does, which lets it tell the server it is leaving, and wait for it to exit."""
        assert self.frpc_log is not None
        self.frpc_log.process.send_signal(signal.SIGINT)
        self.frpc_log.process.wait()

    def close(self) -> None:
        for log in (self.frpc_log, self.websocat_log):
            if log is not None:
                log.close()
        self._reserved.close()


class Hosts:
    """The hosts of one test. `close` stops them all; call it from a fixture's teardown."""

    def __init__(self, directory: Path, binaries: dict[str, Path], target_port: int) -> None:
        self._directory, self._binaries, self._target_port = directory, binaries, target_port
        self._started: list[Host] = []

    def start(
        self,
        stack: Stack,
        *,
        label: str | None = None,
        protocol: str = "tcp",
        through_front: bool = False,
        wait_for_registration: bool = True,
    ) -> Host:
        """Start a host for `label`; by default return once frps has registered it.

        `protocol` is `RT_PROTOCOL`: `tcp`, `websocket` (plain, to the control port) and `quic` (to its UDP publish)
        connect to frps directly. `through_front` connects as `wss` to `RT_CONTROL_HOST` behind the front, trusting the
        test CA; a plain `websocket` cannot go that way, because the shipped front configs serve the control host over TLS.
        """
        host = Host(self._directory, self._binaries, label or new_label(), self._target_port)
        self._started.append(host)
        mark = stack.frps_log.mark()
        host.start_websocat()
        if through_front:
            assert stack.control_front is not None, "this stack has no front to reach the control port through"
            host.start_frpc((CONTROL_HOST, stack.control_front.port), "wss", stack.ca_file)
        else:
            control = stack.control_udp if protocol == "quic" else stack.control
            host.start_frpc((control.host, control.port), protocol)
        if wait_for_registration:
            stack.frps_log.wait_for(NEW_PROXY.format(label=host.label), after=mark)
        return host

    def close(self) -> None:
        for host in self._started:
            host.close()


# The data path ========================================================================================================


def websocat_client(stack: Stack, binaries: dict[str, Path], host_name: str) -> list[str | Path]:
    """websocat as a client of the front, with an explicit Host header, so no test needs DNS or /etc/hosts."""
    if stack.secure:
        target = f"ws-c:tls-c:tcp:{stack.vhost.address}"
        return [
            binaries["websocat"], "--binary", "-", target, f"--ws-c-uri=wss://{host_name}/", "--tls-domain", host_name
        ]
    return [binaries["websocat"], "--binary", "-", f"ws-c:tcp:{stack.vhost.address}", f"--ws-c-uri=ws://{host_name}/"]


@dataclass(frozen=True)
class Echoed:
    data: bytes
    diagnostics: str  # what the client wrote to stderr

    def matches(self, payload: bytes) -> bool:
        return self.data == payload

    def __str__(self) -> str:
        return f"{len(self.data)} bytes (sha256 {hashlib.sha256(self.data).hexdigest()[:12]}); client said {self.diagnostics!r}"


# websocat holds back the end of what it writes to stdout until more arrives (measured: a TLS client left 623 bytes
# short of a 4 MiB echo, and delivered them only when more data followed). Its buffer is 64 KiB, so a tail of padding
# that is never read keeps the held-back bytes out of the payload.
PADDING = bytes(1024 * 1024)


def round_trip(command: list[str | Path], payload: bytes, *, ca_file: Path | None = None) -> Echoed:
    """Send `payload` (and padding) through `command` and return the first `len(payload)` bytes that come back.

    The client is stopped once it has delivered them, not asked to close: stdin stays open until then, because closing
    it first would close the WebSocket while the echo is still on its way. A short result means the stream ended early.
    """
    environment = {**clean_environment(), **({"SSL_CERT_FILE": str(ca_file)} if ca_file else {})}
    with tempfile.TemporaryFile() as errors:
        with subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, env=environment
        ) as client:
            stdin, stdout = client.stdin, client.stdout
            assert stdin is not None and stdout is not None

            def send() -> None:
                try:
                    stdin.write(payload + PADDING)
                    stdin.flush()
                except OSError:
                    pass  # the client was stopped, or the connection died; the read comes back short in that case

            writer = threading.Thread(target=send, daemon=True)
            writer.start()
            received = stdout.read(len(payload))
            # Stopping it breaks the pipe under a writer that is still sending padding; only then is stdin safe to close.
            client.terminate()
            client.wait()
            writer.join()
            try:
                stdin.close()
            except OSError:
                pass  # flushing what the stopped client never read
        errors.seek(0)
        return Echoed(received, errors.read().decode(errors="replace"))
