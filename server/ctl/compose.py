"""The only module that runs `docker`."""

import json
import subprocess
from pathlib import Path

# -p and -f pin the project and files: COMPOSE_FILE and COMPOSE_PROJECT_NAME in the shell must not redirect it
_COMPOSE = ["compose", "-p", "reverse-tunnel", "-f", "compose.yaml", "-f", "compose.generated.yaml"]


class DockerError(OSError):
    """`docker` could not be run, or reported a failure of its own."""


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


def frps_online(folder: Path) -> dict[str, int]:
    """Each host with a session open at frps, to the epoch second it began; asked through the plugin container, the
    only one that can reach frps's API. Raises `DockerError`, with what the container printed, when it cannot be asked.
    """
    ask = [*_COMPOSE, "exec", "-T", "reverse-tunnel-plugin", "python", "-m", "ctl.frps"]
    result = _docker(*ask, cwd=folder, capture_output=True, text=True)
    if result.returncode:
        stderr = result.stderr.strip()
        raise DockerError(stderr or f"docker exited with {result.returncode}")
    return json.loads(result.stdout)
