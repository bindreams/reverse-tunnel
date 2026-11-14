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
    running. A running frps is never recreated, because that drops every tunnel. `build` rebuilds the plugin's image,
    and frps's only if there is no frps container yet (a rebuilt image would be discarded). Returns whether the frps
    container already existed, in which case its image, `compose.yaml` and `.env` are not applied to it.
    """
    # -p and -f pin the project and files: COMPOSE_FILE and COMPOSE_PROJECT_NAME in the shell must not redirect it
    command = ["compose", "-p", "reverse-tunnel", "-f", "compose.yaml", "-f", "compose.generated.yaml"]
    ps = ["ps", "-aq", "reverse-tunnel-frps"]
    frps_exists = bool(_docker(*command, *ps, cwd=folder, check=True, capture_output=True, text=True).stdout.strip())
    up = [*command, "up", "-d"]
    plugin_build = ["--build"] if build else []
    frps_build = ["--build"] if build and not frps_exists else []
    _docker(*up, *plugin_build, "--no-deps", "reverse-tunnel-plugin", cwd=folder, check=True)
    _docker(*up, *frps_build, "--no-recreate", "reverse-tunnel-frps", cwd=folder, check=True)
    return frps_exists


def network_exists(name: str) -> bool:
    """Whether the Docker network exists; docker's own failures (daemon down, no permission) raise DockerError."""
    result = _docker("network", "inspect", name, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    stderr = result.stderr.strip()
    if f"network {name} not found" in stderr or f"No such network: {name}" in stderr:
        return False
    raise DockerError(f"docker exited with {result.returncode}" + (f": {stderr}" if stderr else ""))
