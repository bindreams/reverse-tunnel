"""The pinned third-party binaries, fetched the way `ctl install` fetches them: verified against `binaries.lock.toml`."""

from pathlib import Path

from ctl import binaries
from ctl.download import Fetcher


def fetch_pinned(destination: Path, *tools: str) -> dict[str, Path]:
    """Download and verify every binary of `tools` for this platform into `destination`; install name to path."""
    lock = binaries.load_lock(binaries.LOCK_PATH)
    platform = binaries.current_platform()
    installed: dict[str, Path] = {}
    destination.mkdir(parents=True, exist_ok=True)
    with Fetcher() as fetcher:
        for tool in tools:
            for pin in binaries.pins_for(lock, tool, platform):
                installed[pin.install_name] = fetcher.fetch(pin, destination, binaries.bundle_for(lock, tool)).path
    return installed
