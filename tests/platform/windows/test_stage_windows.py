"""`stage` on a repository an earlier install left: one run converges it, and a second changes no ACL."""

import subprocess
from pathlib import Path

from tests.unit.deployment_support import write_env

from ctl import host, perms_windows, winacl
from ctl.config import Config, Role
from ctl.perms import SID_LOCAL_SERVICE, AccountMode
from ctl.services import Services


def acls(root: Path) -> dict[Path, tuple[list[winacl.Entry], bool]]:
    """Every ACE, in stored order, and the inheritance state of `root` and everything under it."""
    found = {}
    for path in [root, *root.rglob("*")]:
        with perms_windows._handle(path, directory=path.is_dir(), access=perms_windows.winfile.READ_CONTROL) as handle:
            found[path] = winacl.read_entries(handle)
    return found


def previous_install(tmp_path: Path) -> Config:
    """A host as the install that wrote an inheritable service ACE on the root left it, with logs it wrote."""
    repo = tmp_path / "repo"
    for name in ("bin", "host", "logs"):
        (repo / name).mkdir(parents=True)
    (repo / "bin" / "frpc.exe").write_bytes(b"")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    (repo / "logs" / "frpc.log").write_bytes(b"")
    config = write_env(repo, Role.HOST)
    grant = f"*{SID_LOCAL_SERVICE}:(OI)(CI)(RX)"
    subprocess.run(["icacls", str(repo), "/grant", grant], check=True, capture_output=True)
    return config


def stage(config: Config) -> None:
    plan = host.Plan(
        binaries_to_replace=(),
        daemons_to_converge=(),
        mode=AccountMode.SEPARATE,
        platform="windows-x86_64",
        pins=(),
        bundle=None,
        installed=(),
        detach=False,
        inputs={},
        reasons={},
    )
    host.stage(config, plan, services=Services())


def test_one_stage_converges_a_repository_an_earlier_install_granted(tmp_path):
    config = previous_install(tmp_path)
    stage(config)
    first = acls(config.root)
    stage(config)
    assert acls(config.root) == first
