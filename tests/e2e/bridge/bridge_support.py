"""Helpers shared by the bridge tests. Not a conftest: `from conftest import` would hit tests/unit's."""

import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SANDBOX_VARIABLE = "RT_E2E_SANDBOX"

GOOD_TOKEN = "0123456789abcdef" * 4
GOOD_PASSWORD = "correct-horse-battery_staple"
GOOD_DOMAIN = "tunnel.example.com"
BRIDGE_FILES = ("compose.yaml", "compose.traefik.yaml", "bridge")


def clean_environment() -> dict[str, str]:
    """The process environment minus every `RT_*`, which compose would let override the project's `.env`."""
    return {key: value for key, value in os.environ.items() if not key.startswith("RT_")}


def run(*args: str, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env or clean_environment(), capture_output=True, text=True, check=False)


@dataclass
class Entrypoint:
    """Runs the image's entrypoint against a token and a config, then a command that proves the checks passed."""

    image: str
    directory: Path

    def run(
        self,
        *,
        token: bytes | str | None = GOOD_TOKEN + "\n",
        config: str | None = None,
        environment: Mapping[str, str | None] | None = None,
        command: tuple[str, ...] = ("echo", "STARTED"),
    ) -> subprocess.CompletedProcess[str]:
        """`token=None` and `config=None` mount nothing at that path."""
        environment = {"RT_DOMAIN": GOOD_DOMAIN, "RT_ADMIN_PASSWORD": GOOD_PASSWORD, **(environment or {})}
        mounts: list[str] = []
        if token is not None:
            path = self.directory / f"token-{uuid.uuid4().hex[:8]}"
            path.write_bytes(token if isinstance(token, bytes) else token.encode())
            mounts += self.mount(path, "/rt/secrets/token")
        if config is not None:
            path = self.directory / f"frps-{uuid.uuid4().hex[:8]}.toml"
            path.write_text(config, encoding="utf-8")
            mounts += self.mount(path, "/rt/bridge/frps.toml")
        flags = [f"--env={name}={value}" for name, value in environment.items() if value is not None]
        return run("docker", "run", "--rm", "--network", "none", *mounts, *flags, self.image, *command)

    def run_with_mounts(
        self,
        mounts: list[tuple[Path, str]],
        *,
        command: tuple[str, ...] = ("echo", "STARTED"),
    ) -> subprocess.CompletedProcess[str]:
        flags = [f"--env=RT_DOMAIN={GOOD_DOMAIN}", f"--env=RT_ADMIN_PASSWORD={GOOD_PASSWORD}"]
        arguments = [argument for source, target in mounts for argument in self.mount(source, target)]
        return run("docker", "run", "--rm", "--network", "none", *arguments, *flags, self.image, *command)

    @staticmethod
    def mount(source: Path, target: str) -> list[str]:
        return ["--mount", f"type=bind,source={source},target={target},readonly"]


@dataclass
class Project:
    """A copy of the deployment files in a scratch directory, with its own `.env` and a unique compose project."""

    root: Path
    name: str
    values: dict[str, str]

    def write_env(self) -> None:
        (self.root / ".env").write_text("".join(f"{key}={value}\n" for key, value in self.values.items()))

    def compose(self, *args: str, overlay: bool = False) -> subprocess.CompletedProcess[str]:
        files = ["-f", "compose.yaml", *(["-f", "compose.traefik.yaml"] if overlay else [])]
        self.write_env()
        return run("docker", "compose", "--project-name", self.name, *files, *args, cwd=self.root)

    def config(self, *, overlay: bool = False) -> dict:
        result = self.compose("config", "--format", "json", overlay=overlay)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    @property
    def token_file(self) -> Path:
        return self.root / "secrets" / "token"


def make_project(directory: Path, **overrides: str | None) -> Project:
    root = directory / "deployment"
    root.mkdir()
    for name in BRIDGE_FILES:
        source = REPO_ROOT / name
        if source.is_dir():
            shutil.copytree(source, root / name)
        else:
            shutil.copy2(source, root / name)
    (root / "secrets").mkdir(mode=0o711)
    (root / "secrets" / "token").write_text(GOOD_TOKEN + "\n")
    values = {
        "RT_DOMAIN": GOOD_DOMAIN,
        "RT_ADMIN_PASSWORD": GOOD_PASSWORD,
        "RT_CONTROL_PORT": "17000",
        "RT_VHOST_BIND": "127.0.0.1",
        "RT_VHOST_PORT": "18080",
        "RT_ADMIN_PORT": "17500",
        "RT_CONTROL_HOST": "bridge.example.com",
        "RT_PROXY_NETWORK": "rt-e2e-proxy",
    }
    for key, value in overrides.items():
        if value is None:
            del values[key]
        else:
            values[key] = value
    return Project(root, f"rt-e2e-{uuid.uuid4().hex[:10]}", values)


def assert_refused(result: subprocess.CompletedProcess[str], message: str) -> None:
    assert result.returncode != 0, result.stdout
    assert message in result.stderr, result.stderr
    assert "STARTED" not in result.stdout, "the command ran although the checks failed"
