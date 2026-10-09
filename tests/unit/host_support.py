"""A host deployment for the install tests: the real manifest and frpc config, a lock, pinned binaries, a fake goetia."""

import dataclasses
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from tests.unit.binaries_support import SEED_LOCK, VERSIONS, Upstream, member_content
from tests.unit.deployment_support import GOOD_TOKEN, REPO_ROOT, write_env
from tests.unit.goetia_support import FakeGoetia, daemon

from ctl import binaries, goetia, host
from ctl.config import Config, Role
from ctl.download import DIGESTS, Fetcher
from ctl.install import Services

PLATFORM = "linux-x86_64"
FRPC, WEBSOCAT = host.FRPC_ID, host.WEBSOCAT_ID
BINARIES = {"frp": ("frpc", ), "websocat": ("websocat", ), "goetia": ("goetia", "goetia-shim")}
MANIFEST_SPEC = {FRPC: "command: [frpc]\nuser: svc\n", WEBSOCAT: "command: [websocat]\nuser: svc\n"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


SERVICE_ACCOUNT = "rt-test-svc"  # provisioned where the tests run as root, see tests/platform/README.md


def current_user() -> str:
    """The account that owns the deployment and runs the daemons in the same-account mode.

    Root may not run the daemons, so under root the tree is handed to `rt-test-svc` instead.
    """
    if sys.platform == "win32":
        return "tunnel"
    import os
    import pwd

    return SERVICE_ACCOUNT if os.geteuid() == 0 else pwd.getpwuid(os.getuid()).pw_name


@dataclasses.dataclass
class HostTree:
    root: Path
    services: Services
    fake: FakeGoetia
    upstream: Upstream
    pins: dict[str, binaries.Pin]  # install name -> pin, for every binary a host installs
    served_before: int = 0  # requests answered while the lock was being generated

    @property
    def downloads(self) -> list:
        """The requests the install under test has made."""
        return self.upstream.requests[self.served_before:]

    @property
    def uid(self) -> int:
        """The owner of the deployment, who is also the service account in the same-account mode."""
        return self.root.stat().st_uid

    @property
    def config(self) -> Config:
        return Config.load(self.root)

    @property
    def bin(self) -> Path:
        return self.root / "bin"

    def write_binaries(self, *names: str) -> None:
        """Put the pinned bytes of each named binary in `bin/` (all of them when none is named)."""
        self.bin.mkdir(exist_ok=True)
        for name in names or self.pins:
            (self.bin / name).write_bytes(self.pinned_bytes(name))

    def pinned_bytes(self, name: str) -> bytes:
        pin = self.pins[name]
        return member_content(pin.tool, pin.version, PLATFORM, name)

    def token_digest(self, token: str = GOOD_TOKEN) -> str:
        return sha256(f"{token}\n".encode())

    def frpc_toml_digest(self) -> str:
        return sha256((self.root / "host" / "frpc.toml").read_bytes())

    def record(self, overrides: dict[str, str | None] | None = None) -> dict[str, str]:
        """Write `bin/.digests.json` as a successful apply leaves it; `None` drops an entry, a string replaces it."""
        recorded = {name: pin.member_sha256 for name, pin in self.pins.items()}
        recorded.update({"token": self.token_digest(), "frpc.toml": self.frpc_toml_digest()})
        for name, digest in (overrides or {}).items():
            if digest is None:
                recorded.pop(name, None)
            else:
                recorded[name] = digest
        self.bin.mkdir(exist_ok=True)
        (self.bin / DIGESTS).write_text(json.dumps(recorded), encoding="utf-8")
        return recorded

    def converge(self) -> None:
        """The state after a clean install: binaries and record in place, both daemons installed, running, current."""
        self.write_binaries()
        self.record()
        self.script_running()

    def script_running(self, websocat: str = "running", enabled: bool = True, frpc: str = "running") -> None:
        """Both daemons installed and current, in the given states."""
        self.fake.forget("status")
        self.fake.status(daemon(FRPC, frpc), daemon(WEBSOCAT, websocat, enabled))
        for daemon_id, text in MANIFEST_SPEC.items():
            self.set_spec(daemon_id, text)

    def set_spec(self, daemon_id: str, installed: str, manifest: str | None = None) -> None:
        self.fake.forget("show", "-f", daemon_id)
        self.fake.forget("show", daemon_id)
        self.fake.spec(daemon_id, installed=installed, manifest=manifest)

    def edit_env(self, **values: str) -> None:
        env = {}
        for line in (self.root / ".env").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            env[key] = value
        env.update(values)
        (self.root / ".env").write_text("".join(f"{key}={value}\n" for key, value in env.items()), encoding="utf-8")


def hand_to(root: Path, entry) -> None:
    os.chown(root, entry.pw_uid, entry.pw_gid)
    for directory, names, files in os.walk(root):
        for name in names + files:
            os.chown(os.path.join(directory, name), entry.pw_uid, entry.pw_gid)


def build_host(tmp_path: Path, monkeypatch, **env: str) -> HostTree:
    """A fresh, never-installed host deployment under `tmp_path/deployment`; goetia is the fake until a test says not."""
    root = tmp_path / "deployment"
    root.mkdir()
    (root / "host").mkdir()
    shutil.copy(REPO_ROOT / "goetia.yaml", root / "goetia.yaml")
    shutil.copy(REPO_ROOT / "host" / "frpc.toml", root / "host" / "frpc.toml")
    write_env(root, Role.HOST, **({"RT_SERVICE_USER": current_user()} | env))
    if sys.platform != "win32" and os.geteuid() == 0:
        import pwd

        hand_to(root, pwd.getpwnam(SERVICE_ACCOUNT))

    upstream = Upstream()
    for tool, version in VERSIONS.items():
        upstream.add_tool(tool, version)
    lock_path = tmp_path / "binaries.lock.toml"
    lock_path.write_text(SEED_LOCK)
    binaries.refresh(lock_path, None, transport=upstream.transport)
    lock = binaries.load_lock(lock_path)
    pins = {
        pin.install_name: pin
        for tool, names in BINARIES.items()
        for pin in binaries.pins_for(lock, tool, PLATFORM) if pin.install_name in names
    }
    assert set(pins) == {"frpc", "websocat", "goetia", "goetia-shim"}

    fake = FakeGoetia(tmp_path / "fake")
    monkeypatch.setattr(goetia, "command", lambda _root: fake.command)
    monkeypatch.setattr(goetia, "available", lambda root: (root / "bin" / "goetia").exists())
    services = Services(
        lock_path=lock_path,
        platform=PLATFORM,
        fetcher=lambda: Fetcher(transport=upstream.transport, attest=lambda artifact, bundle, policy: None),
    )
    return HostTree(root, services, fake, upstream, pins, len(upstream.requests))
