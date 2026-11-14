"""The only module that runs `docker`."""

import subprocess
from pathlib import Path

# -p and -f pin the project and files: COMPOSE_FILE and COMPOSE_PROJECT_NAME in the shell must not redirect it
_COMPOSE = ["compose", "-p", "reverse-tunnel", "-f", "compose.yaml", "-f", "compose.generated.yaml"]


class DockerError(OSError):
    """`docker` could not be run, or reported a failure of its own."""


# Seconds. `wget -T` does not bound a hung docker or daemon, so `exec` gets its own, longer limit.
FRPS_ANSWER_WITHIN = 10
EXEC_WITHIN = FRPS_ANSWER_WITHIN + 5

# Where frps's API listens: `webServer.addr` and `webServer.port` in etc/frps.toml, which a test checks.
FRPS_API_ADDR = "127.0.0.1"
FRPS_API_PORT = 7500


class FrpsApiMissing(DockerError):
    """frps runs but nothing answers on its API port."""


def _docker(*args: str, **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], **kwargs)
    except FileNotFoundError as e:
        raise DockerError("docker is not installed") from e


def compose_up(folder: Path, build: bool = False) -> bool:
    """Bring the bridge up from the folder's compose files: the plugin created or updated, frps started if it is
    not running. An existing frps container is never built for, removed or recreated, because that drops every tunnel.

    `build` is for `init`: it also builds the plugin, and frps too when it has no container. Returns whether `init`
    found an existing frps container and kept it as it is; `False` when not `init`.
    """
    kept = build and _frps_exists(_COMPOSE, folder)
    up = [*_COMPOSE, "up", "-d"]
    flags = ["--build"] if build else []
    _docker(*up, *flags, "--no-deps", "reverse-tunnel-plugin", cwd=folder, check=True)
    _docker(*up, *(flags if not kept else []), "--no-recreate", "reverse-tunnel-frps", cwd=folder, check=True)
    return kept


def _frps_exists(command: list[str], folder: Path) -> bool:
    # stderr is not captured: docker's own failure reaches the user
    ps = [*command, "ps", "-a", "-q", "reverse-tunnel-frps"]
    return bool(_docker(*ps, cwd=folder, check=True, stdout=subprocess.PIPE, text=True).stdout.strip())


def network_exists(name: str) -> bool:
    """Whether the Docker network exists; docker's own failures (daemon down, no permission) raise DockerError."""
    result = _docker("network", "inspect", name, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    stderr = result.stderr.strip()
    if f"network {name} not found" in stderr or f"No such network: {name}" in stderr:
        return False
    raise DockerError(f"docker exited with {result.returncode}" + (f": {stderr}" if stderr else ""))


def frps_clients(folder: Path) -> str:
    """frps's `/api/clients` answer, read by `wget` inside the frps container: the API listens on its loopback only.
    Raises `FrpsApiMissing` when nothing listens there, and `DockerError`, with what docker or `wget` printed, for any
    other failure, among them frps not answering: `wget` gives up after `FRPS_ANSWER_WITHIN` seconds, and docker itself
    after `EXEC_WITHIN`.
    """
    api = f"http://{FRPS_API_ADDR}:{FRPS_API_PORT}/api/clients"
    ask = [*_COMPOSE, "exec", "-T", "reverse-tunnel-frps", "wget", "-T", str(FRPS_ANSWER_WITHIN), "-qO-", api]
    try:
        result = _docker(*ask, cwd=folder, capture_output=True, text=True, timeout=EXEC_WITHIN)
    except subprocess.TimeoutExpired:
        raise DockerError(f"frps did not answer within {EXEC_WITHIN} s") from None
    if result.returncode:
        stderr = result.stderr.strip()
        if "timed out" in stderr:
            raise DockerError(f"frps did not answer within {FRPS_ANSWER_WITHIN} s")
        message = stderr or f"docker exited with {result.returncode}"
        raise (FrpsApiMissing if "Connection refused" in stderr else DockerError)(message)
    return result.stdout
