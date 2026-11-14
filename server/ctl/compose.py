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
    """Bring the bridge up from the folder's compose files: the plugin created or updated, frps started if it is not
    running. A running frps is never recreated, because that drops every tunnel. `build` (for `init`) rebuilds both
    images, frps's only if it is not running (a rebuilt image would be discarded). Returns whether frps was running
    and left as it was, in which case its image, `compose.yaml` and `.env` are not applied to it.
    """
    # -p and -f pin the project and files: COMPOSE_FILE and COMPOSE_PROJECT_NAME in the shell must not redirect it
    command = ["compose", "-p", "reverse-tunnel", "-f", "compose.yaml", "-f", "compose.generated.yaml"]
    running = [*command, "ps", "-q", "--status", "running", "reverse-tunnel-frps"]
    # no capture of stderr: docker's own failure reaches the user, and check=True stops the bring-up
    frps_running = build and bool(_docker(*running, cwd=folder, check=True, stdout=subprocess.PIPE, text=True).stdout.strip())
    up = [*command, "up", "-d"]
    _docker(*up, *(["--build"] if build else []), "--no-deps", "reverse-tunnel-plugin", cwd=folder, check=True)
    # a frps that is not running has no tunnel to drop, so on `init` it is built and started as it should be
    frps_flag = "--build" if build and not frps_running else "--no-recreate"
    _docker(*up, frps_flag, "reverse-tunnel-frps", cwd=folder, check=True)
    return frps_running


def network_exists(name: str) -> bool:
    """Whether the Docker network exists; docker's own failures (daemon down, no permission) raise DockerError."""
    result = _docker("network", "inspect", name, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    stderr = result.stderr.strip()
    if f"network {name} not found" in stderr or f"No such network: {name}" in stderr:
        return False
    raise DockerError(f"docker exited with {result.returncode}" + (f": {stderr}" if stderr else ""))
