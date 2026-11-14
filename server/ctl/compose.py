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


def compose_up(folder: Path, build: bool = False) -> bool:
    """Bring the bridge up from the folder's compose files: the plugin created or updated, frps started if it is
    not running. An existing frps container is never built for, removed or recreated, because that drops every tunnel.

    `build` is for `init`: it also builds the plugin, and frps too when it has no container. Returns whether `init`
    found an existing frps container and kept it as it is; `False` when not `init`.
    """
    # -p and -f pin the project and files: COMPOSE_FILE and COMPOSE_PROJECT_NAME in the shell must not redirect it
    command = ["compose", "-p", "reverse-tunnel", "-f", "compose.yaml", "-f", "compose.generated.yaml"]
    kept = build and _frps_exists(command, folder)
    up = [*command, "up", "-d"]
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
