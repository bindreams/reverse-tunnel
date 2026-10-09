"""Rendering the host manifest with a real goetia, and reducing the output to what does not depend on the machine."""

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ctl import binaries
from ctl.download import Fetcher
from tests.unit.deployment_support import REPO_ROOT, write_env
from ctl.config import Role

SERVICE_USER = "svc-example"
SPEC = re.compile(r"^(Spec[=:] ?)([A-Za-z0-9+/=]+)$", re.MULTILINE)
GOETIA_ENV = "RT_TEST_GOETIA"
MISSING = (
    f"no goetia to render with: set {GOETIA_ENV} to a goetia executable, or leave it unset to download the pinned "
    "release (needs the network). `-m 'not goetia'` opts out explicitly."
)


def fetch_pinned_goetia(directory: Path) -> Path:
    """The pinned goetia for this machine, downloaded, digest-checked and attested into `directory`."""
    lock = binaries.load_lock(binaries.LOCK_PATH)
    pins = binaries.pins_for(lock, "goetia", binaries.current_platform())
    with Fetcher() as fetch:
        for pin in pins:
            fetch.fetch(pin, directory, binaries.bundle_for(lock, "goetia"))
    return directory / ("goetia.exe" if sys.platform == "win32" else "goetia")


def goetia_binary(factory: pytest.TempPathFactory) -> Path:
    given = os.environ.get(GOETIA_ENV)
    if given:
        path = Path(given)
        if not path.is_file():
            pytest.fail(f"{GOETIA_ENV}={given} is not a file. {MISSING}", pytrace=False)
        return path
    directory = factory.mktemp("goetia")
    try:
        return fetch_pinned_goetia(directory)
    except Exception as exc:
        pytest.fail(f"{MISSING} Downloading failed: {type(exc).__name__}: {exc}", pytrace=False)


def manifest_directory(directory: Path) -> Path:
    """A directory holding the tracked manifest and a `.env` made from the shipped example, as an operator would."""
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO_ROOT / "goetia.yaml", directory / "goetia.yaml")
    write_env(directory, Role.HOST, RT_SERVICE_USER=SERVICE_USER)
    return directory


def render(goetia: Path, directory: Path, *arguments: str) -> str:
    command = [str(goetia), "daemon", *arguments, "-f", str(directory)]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(f"goetia {' '.join(arguments)} exited {result.returncode}: {result.stderr}", pytrace=False)
    return result.stdout


def normalize(text: str, root: Path) -> str:
    """`text` with the checkout's path replaced and goetia's base64 `Spec` blob decoded, so it reads the same anywhere."""

    def decode(match: re.Match[str]) -> str:
        document = json.loads(base64.b64decode(match.group(2)))
        return match.group(1) + json.dumps(document, sort_keys=True).replace(str(root), "<ROOT>")

    return SPEC.sub(decode, text).replace(str(root), "<ROOT>").replace("\r\n", "\n")
