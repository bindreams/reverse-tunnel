"""The only module that runs `docker`."""

import subprocess
from pathlib import Path


def compose_up_plugin(folder: Path) -> None:
    """Create or update the plugin container from the bridge folder's compose files."""
    subprocess.run(["docker", "compose", "up", "-d", "reverse-tunnel-plugin"], cwd=folder, check=True)


def network_exists(name: str) -> bool:
    return subprocess.run(["docker", "network", "inspect", name], capture_output=True).returncode == 0
