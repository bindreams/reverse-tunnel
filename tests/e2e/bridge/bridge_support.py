"""Helpers shared by the bridge tests. Not a conftest: `from conftest import` would hit tests/unit's."""

import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from logwait import LineTail, tail_compose

REPO_ROOT = Path(__file__).resolve().parents[3]
SANDBOX_VARIABLE = "RT_E2E_SANDBOX"

FRPS_READY = "frps started successfully"
GOOD_TOKEN = "0123456789abcdef" * 4
GOOD_PASSWORD = "correct-horse-battery_staple"
GOOD_DOMAIN = "tunnel.example.com"
BRIDGE_FILES = ("compose.yaml", "compose.traefik.yaml", "bridge")
# What `compose up` says when Docker's pick for a port published as `0` was already held by a socket it does not track:
# its range is the kernel's ephemeral one, which every outgoing connection of the runner draws from too.
DYNAMIC_PORT_COLLISIONS = ("address already in use", "port is already allocated")


def get(url: str, **kwargs) -> httpx.Response:
    """GET `url` with no client-side timeout: httpx's default is a bet that 5 s is long enough, and a request that never
    answers ends at the CI job's own limit."""
    with httpx.Client(timeout=None) as client:
        return client.get(url, **kwargs)


def clean_environment() -> dict[str, str]:
    """The process environment minus every `RT_*`, which compose would let override the project's `.env`."""
    return {key: value for key, value in os.environ.items() if not key.startswith("RT_")}


def run(*args: str, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=env or clean_environment(), capture_output=True, text=True, check=False)


# A uid that is neither root nor, in the sandbox, the account running the tests.
OTHER_UID = 12345


def write_operator_token(path: Path, content: bytes) -> None:
    """A token as `ctl install` leaves it: mode 0600 and owned by an account other than the container's root."""
    path.write_bytes(content)
    path.chmod(0o600)
    if os.geteuid() == 0:
        os.chown(path, OTHER_UID, OTHER_UID)


@dataclass
class Entrypoint:
    """Runs the image's entrypoint against a token and a config, then a command that proves the checks passed.

    `service` is the frps service of the repository's `compose.yaml` as `docker compose config` renders it; its
    capabilities, security options, read-only root and tmpfs become `docker run` flags, so a run is hardened exactly
    as the stack is.
    """

    image: str
    directory: Path
    service: dict

    def hardening(self, *, tmpfs: bool = True, add_capabilities: bool = True) -> list[str]:
        flags: list[str] = []
        for capability in self.service.get("cap_drop", []):
            flags += ["--cap-drop", capability]
        for capability in self.service.get("cap_add", []) if add_capabilities else []:
            flags += ["--cap-add", capability]
        for option in self.service.get("security_opt", []):
            flags += ["--security-opt", option]
        if self.service.get("read_only"):
            flags.append("--read-only")
        for target in self.service.get("tmpfs", []) if tmpfs else []:
            flags += ["--tmpfs", target]
        return flags

    def run(
        self,
        *,
        token: bytes | str | None = GOOD_TOKEN + "\n",
        config: str | None = None,
        environment: Mapping[str, str | None] | None = None,
        command: tuple[str, ...] = ("echo", "STARTED"),
        tmpfs: bool = True,
        add_capabilities: bool = True,
        extra: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        """`token=None` and `config=None` mount nothing at that path."""
        mounts: list[str] = []
        if token is not None:
            path = self.directory / f"token-{uuid.uuid4().hex[:8]}"
            write_operator_token(path, token if isinstance(token, bytes) else token.encode())
            mounts += self.mount(path, "/rt/secrets/token")
        if config is not None:
            path = self.directory / f"frps-{uuid.uuid4().hex[:8]}.toml"
            path.write_text(config, encoding="utf-8")
            mounts += self.mount(path, "/rt/bridge/frps.toml")
        return self.docker_run(mounts, environment, command, tmpfs, add_capabilities, extra)

    def run_with_mounts(
        self,
        mounts: list[tuple[Path, str]],
        *,
        command: tuple[str, ...] = ("echo", "STARTED"),
    ) -> subprocess.CompletedProcess[str]:
        arguments = [argument for source, target in mounts for argument in self.mount(source, target)]
        return self.docker_run(arguments, None, command, True, True, ())

    def docker_run(self, mounts, environment, command, tmpfs, add_capabilities, extra):
        environment = {"RT_DOMAIN": GOOD_DOMAIN, "RT_ADMIN_PASSWORD": GOOD_PASSWORD, **(environment or {})}
        flags = [f"--env={name}={value}" for name, value in environment.items() if value is not None]
        hardening = self.hardening(tmpfs=tmpfs, add_capabilities=add_capabilities)
        return run(
            "docker", "run", "--rm", "--network", "none", *hardening, *extra, *mounts, *flags, self.image, *command
        )

    @staticmethod
    def mount(source: Path, target: str) -> list[str]:
        return ["--mount", f"type=bind,source={source},target={target},readonly"]


@dataclass
class Project:
    """A copy of the deployment files in a scratch directory, with its own `.env` and a unique compose project."""

    root: Path
    name: str
    values: dict[str, str]
    tails: list[LineTail] = field(default_factory=list)  # logs followed since `up`, ended by `down`

    @property
    def dynamic_ports(self) -> bool:
        """Whether every published port is one Docker picks; the front services publish theirs that way always."""
        return all(value == "0" for key, value in self.values.items() if key.endswith("_PORT"))

    def write_env(self) -> None:
        (self.root / ".env").write_text("".join(f"{key}={value}\n" for key, value in self.values.items()))

    def arguments(self,
                  *,
                  overlay: bool = False,
                  extra_files: tuple[str, ...] = (),
                  profiles: tuple[str, ...] = ()) -> list[str]:
        """The global `docker compose` options that select this project, its files and its profiles."""
        names = ["compose.yaml", *(["compose.traefik.yaml"] if overlay else []), *extra_files]
        return [
            "--project-name", self.name, *(argument for name in names for argument in ("-f", name)),
            *(argument for profile in profiles for argument in ("--profile", profile))
        ]

    def compose(self,
                *args: str,
                overlay: bool = False,
                extra_files: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
        self.write_env()
        return run("docker", "compose", *self.arguments(overlay=overlay, extra_files=extra_files), *args, cwd=self.root)

    def bare_compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        """`docker compose` as an operator types it: no `-f`, so the files are the ones `COMPOSE_FILE` in `.env` names."""
        self.write_env()
        return run("docker", "compose", "--project-name", self.name, *args, cwd=self.root)

    def tail(
        self,
        service: str,
        *,
        overlay: bool = False,
        extra_files: tuple[str, ...] = (),
        profiles: tuple[str, ...] = ()
    ) -> LineTail:
        """Follow `service`'s log from its first line; see `logwait.tail_compose`."""
        self.write_env()
        return tail_compose(
            self.root,
            service,
            compose_args=self.arguments(overlay=overlay, extra_files=extra_files, profiles=profiles),
            env=clean_environment(),
        )

    def up(
        self, *, overlay: bool = False, extra_files: tuple[str, ...] = (), profiles: tuple[str, ...] = ()
    ) -> LineTail:
        """Build and start the stack, then wait for frps to say it is serving; the frps log, followed from its start.

        Nothing waits on the compose healthcheck, which Docker evaluates on a schedule: the test blocks on the line.

        A port published as `0` is picked by Docker, and nothing can reserve it for the stack: another socket on the
        host may take the pick before Docker binds it. Such a refusal is answered by removing the half-started project
        and starting it again, which draws a new port; a fixed port that is busy is not retried, it is the test's answer.
        """
        options = [argument for profile in profiles for argument in ("--profile", profile)]
        while True:
            started = self.compose(*options, "up", "--detach", "--build", overlay=overlay, extra_files=extra_files)
            if started.returncode == 0:
                break
            output = started.stdout + started.stderr
            if not (self.dynamic_ports and any(marker in output for marker in DYNAMIC_PORT_COLLISIONS)):
                pytest.fail(output, pytrace=False)
            cleared = self.compose(*options, "down", "--remove-orphans", overlay=overlay, extra_files=extra_files)
            assert cleared.returncode == 0, cleared.stderr
        log = self.tail("frps", overlay=overlay, extra_files=extra_files, profiles=profiles)
        self.tails.append(log)
        log.wait_for(FRPS_READY, after=0)
        return log

    def down(self, *, overlay: bool = False, extra_files: tuple[str, ...] = (), profiles: tuple[str, ...] = ()) -> None:
        """End every followed log, then remove the containers, networks, volumes and the image built for the project."""
        for log in self.tails:
            log.close()
        options = [argument for profile in profiles for argument in ("--profile", profile)]
        removed = self.compose(
            *options,
            "down",
            "--volumes",
            "--remove-orphans",
            "--rmi",
            "local",
            overlay=overlay,
            extra_files=extra_files
        )
        assert removed.returncode == 0, removed.stderr

    def config(self, *, overlay: bool = False) -> dict:
        result = self.compose("config", "--format", "json", overlay=overlay)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    @property
    def token_file(self) -> Path:
        return self.root / "secrets" / "token"


def make_project(
    directory: Path,
    root_name: str | None = None,
    *,
    copy_in: Mapping[str, Path] | None = None,
    **overrides: str | None,
) -> Project:
    """A scratch deployment. With `root_name`, the compose project is named after the directory, as `ctl` runs it.

    `copy_in` maps a file name in the project to the source it is copied from, for example `compose.override.yaml`.
    """
    root = directory / (root_name or "deployment")
    root.mkdir()
    for name in BRIDGE_FILES:
        source = REPO_ROOT / name
        if source.is_dir():
            shutil.copytree(source, root / name)
        else:
            shutil.copy2(source, root / name)
    for name, source in (copy_in or {}).items():
        shutil.copy2(source, root / name)
    (root / "secrets").mkdir(mode=0o711)
    write_operator_token(root / "secrets" / "token", (GOOD_TOKEN + "\n").encode())
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
    return Project(root, root_name or f"rt-e2e-{uuid.uuid4().hex[:10]}", values)


def assert_refused(result: subprocess.CompletedProcess[str], message: str) -> None:
    assert result.returncode != 0, result.stdout
    assert message in result.stderr, result.stderr
    assert "STARTED" not in result.stdout, "the command ran although the checks failed"
