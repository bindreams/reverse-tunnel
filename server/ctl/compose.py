"""The only module that runs `docker`."""

import subprocess
from pathlib import Path


class DockerError(OSError):
    """`docker` could not be run, or reported a failure of its own."""


def _docker(*args: str, **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["docker", *args], **kwargs)
    except FileNotFoundError as e:
        raise DockerError("docker is not installed") from e


def compose_up_plugin(folder: Path) -> None:
    """Create or update the plugin container from the bridge folder's compose files, leaving frps alone."""
    _docker("compose", "up", "-d", "--no-deps", "reverse-tunnel-plugin", cwd=folder, check=True)


def network_exists(name: str) -> bool:
    """Whether the Docker network exists; docker's own failures (daemon down, no permission) raise DockerError."""
    result = _docker("network", "inspect", name, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    stderr = result.stderr.strip()
    if f"network {name} not found" in stderr or f"No such network: {name}" in stderr:
        return False
    raise DockerError(stderr)
