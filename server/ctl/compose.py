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


def compose_up(folder: Path, build: bool = False) -> bool | None:
    """Bring the bridge up from the folder's compose files: the plugin created or updated, frps started if it is
    absent. A running frps is never recreated, because that drops every tunnel.

    `build` is for `init`: it builds both images and removes frps's container so that the new image is used, unless
    the daemon refuses, which it does for a container that is running, paused or restarting. Returns, for `init`,
    whether such a held frps was kept (its image, `compose.yaml` and `.env` are then not applied to it); `None`
    otherwise.
    """
    # -p and -f pin the project and files: COMPOSE_FILE and COMPOSE_PROJECT_NAME in the shell must not redirect it
    command = ["compose", "-p", "reverse-tunnel", "-f", "compose.yaml", "-f", "compose.generated.yaml"]
    kept = None
    if build:
        _docker(*command, "build", cwd=folder, check=True)
        kept = _remove_frps(command, folder)
    up = [*command, "up", "-d"]
    _docker(*up, "--no-deps", "reverse-tunnel-plugin", cwd=folder, check=True)
    _docker(*up, "--no-recreate", "reverse-tunnel-frps", cwd=folder, check=True)
    return kept


def _remove_frps(command: list[str], folder: Path) -> bool:
    """Remove frps's container without `-f`, so the daemon decides; returns whether it refused (the frps is held)."""
    # stderr is not captured: docker's own failure reaches the user
    ps = [*command, "ps", "-a", "-q", "reverse-tunnel-frps"]
    listed = _docker(*ps, cwd=folder, check=True, stdout=subprocess.PIPE, text=True)
    kept = False
    for container in listed.stdout.split():
        result = _docker("rm", container, capture_output=True, text=True)
        if result.returncode == 0:
            continue
        if "force remove" not in result.stderr:  # what the daemon says of a running, paused or restarting container
            raise DockerError(f"docker rm {container} exited with {result.returncode}: {result.stderr.strip()}")
        kept = True
    return kept


def network_exists(name: str) -> bool:
    """Whether the Docker network exists; docker's own failures (daemon down, no permission) raise DockerError."""
    result = _docker("network", "inspect", name, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    stderr = result.stderr.strip()
    if f"network {name} not found" in stderr or f"No such network: {name}" in stderr:
        return False
    raise DockerError(f"docker exited with {result.returncode}" + (f": {stderr}" if stderr else ""))
