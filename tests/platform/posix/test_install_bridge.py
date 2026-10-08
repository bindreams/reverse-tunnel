import os
import stat
from pathlib import Path

import pytest

from ctl import download, perms
from ctl import install as installer
from ctl.config import Config, Role
from ctl.errors import InstallError
from ctl.install import Services, install, uninstall
from ctl.perms import PermsError
from tests.unit.deployment_support import GOOD_TOKEN, OTHER_TOKEN, tree, write_env


class Docker:
    """Stands in for running `docker`; records each command and the directory it ran in."""

    def __init__(self, returncode: int = 0, missing: bool = False) -> None:
        self.returncode = returncode
        self.missing = missing
        self.calls: list[tuple[list[str], Path]] = []
        self.on_call = lambda: None

    def __call__(self, args: list[str], *, cwd: Path) -> int:
        self.calls.append((args, cwd))
        self.on_call()
        if self.missing:
            raise FileNotFoundError(args[0])
        return self.returncode


@pytest.fixture
def docker() -> Docker:
    return Docker()


@pytest.fixture
def services(docker) -> Services:
    return Services(run=docker)


@pytest.fixture
def root(tmp_path) -> Path:
    return tmp_path


@pytest.fixture
def config(root) -> Config:
    return write_env(root, Role.BRIDGE)


@pytest.fixture(autouse=True)
def nothing_is_downloaded(monkeypatch):

    def refuse(self, *args, **kwargs):
        pytest.fail("the bridge downloads nothing", pytrace=False)

    monkeypatch.setattr(download.Fetcher, "__enter__", refuse)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# Install ==============================================================================================================


def test_bridge_install_writes_only_the_token_and_hardens_env(config, root, services, docker):
    before = tree(root)
    assert install(config, services=services) == 0
    assert {path: kind
            for path, kind in tree(root).items() if path not in before} == {
                "secrets": "dir",
                "secrets/token": "file",
            }
    assert (root / "secrets" / "token").read_text() == GOOD_TOKEN + "\n"
    assert mode_of(root / ".env") == 0o600
    assert mode_of(root / "secrets") == 0o711
    assert mode_of(root / "secrets" / "token") == 0o600
    assert (root / "secrets" / "token").stat().st_uid == os.geteuid()
    assert docker.calls == []


def test_bridge_install_creates_the_secrets_dir_before_writing_the_token(config, root, services, monkeypatch):
    events: list[str] = []
    real_converge, real_write, real_harden = perms.converge_dir, perms.write_secret, perms.harden_file

    def converge(path, *args, **kwargs):
        events.append(f"converge {path.name}")
        return real_converge(path, *args, **kwargs)

    def write(path, *args, **kwargs):
        assert path.parent.is_dir(), "the token was written before its directory existed"
        events.append(f"write {path.name}")
        return real_write(path, *args, **kwargs)

    def harden(path, *args, **kwargs):
        events.append(f"harden {path.name}")
        return real_harden(path, *args, **kwargs)

    monkeypatch.setattr(perms, "converge_dir", converge)
    monkeypatch.setattr(perms, "write_secret", write)
    monkeypatch.setattr(perms, "harden_file", harden)
    assert install(config, services=services) == 0
    assert events == ["converge secrets", "write token", "harden .env"]


def test_bridge_install_is_idempotent(config, root, services, capsys):
    assert install(config, services=services) == 0
    first = (root / "secrets" / "token").read_bytes()
    capsys.readouterr()
    assert install(config, services=services) == 0
    assert (root / "secrets" / "token").read_bytes() == first
    assert sorted(path.name for path in (root / "secrets").iterdir()) == ["token"]
    assert "recreate" not in capsys.readouterr().err


def test_bridge_install_reports_that_a_changed_token_needs_a_recreate(root, config, services, capsys):
    assert install(config, services=services) == 0
    capsys.readouterr()
    changed = write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN)
    assert install(changed, services=services) != 0
    out, err = capsys.readouterr()
    assert "recreate" in err
    assert "drops every connected tunnel" in err
    assert "docker compose up -d --force-recreate" in err
    assert (root / "secrets" / "token").read_text() == OTHER_TOKEN + "\n"  # the file the recreate will read
    for token in (GOOD_TOKEN, OTHER_TOKEN):
        assert token not in out + err


def test_bridge_install_still_hardens_env_when_the_token_changed(root, config, services):
    assert install(config, services=services) == 0
    changed = write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN)
    assert install(changed, services=services) != 0
    assert mode_of(root / ".env") == 0o600


def test_a_token_file_that_differs_only_in_whitespace_is_not_a_change(root, config, services, capsys):
    (root / "secrets").mkdir(mode=0o711)
    token = root / "secrets" / "token"
    token.write_bytes(f"  {GOOD_TOKEN}".encode())
    token.chmod(0o644)
    assert install(config, services=services) == 0
    assert token.read_bytes() == f"  {GOOD_TOKEN}".encode()  # the running frps copied these exact bytes
    assert mode_of(token) == 0o600
    assert "recreate" not in capsys.readouterr().err


def test_a_malformed_token_file_is_a_change(root, config, services, capsys):
    (root / "secrets").mkdir(mode=0o711)
    (root / "secrets" / "token").write_text("not the token\n")
    assert install(config, services=services) != 0
    assert (root / "secrets" / "token").read_text() == GOOD_TOKEN + "\n"
    assert "recreate" in capsys.readouterr().err


def test_bridge_install_tightens_env_and_config_load_does_not(root, config):
    assert mode_of(root / ".env") == 0o644
    Config.load(root)
    assert mode_of(root / ".env") == 0o644
    assert install(config, services=Services(run=Docker())) == 0
    assert mode_of(root / ".env") == 0o600


# Refusals =============================================================================================================


def test_bridge_install_refuses_a_symlinked_secrets_dir_and_changes_nothing(root, config, services, tmp_path_factory):
    target = tmp_path_factory.mktemp("elsewhere")
    target.chmod(0o755)
    (root / "secrets").symlink_to(target)
    before = tree(root)
    with pytest.raises(InstallError, match="symlink"):
        install(config, services=services)
    assert mode_of(target) == 0o755
    assert tree(root) == before
    assert mode_of(root / ".env") == 0o644


def test_bridge_install_refuses_a_secrets_path_that_is_not_a_directory(root, config, services):
    (root / "secrets").write_text("x")
    with pytest.raises(InstallError, match="not a directory"):
        install(config, services=services)
    assert (root / "secrets").read_text() == "x"


def test_bridge_install_detects_a_directory_where_the_token_belongs(root, config, services):
    """What `docker compose up` leaves when it runs first; here owned by the operator, so no `sudo` is needed."""
    (root / "secrets" / "token").mkdir(parents=True)
    before = tree(root)
    with pytest.raises(InstallError) as raised:
        install(config, services=services)
    message = str(raised.value)
    assert "secrets/token is a directory" in message
    assert "rm -rf ./secrets" in message and "sudo rm -rf" not in message
    assert "ctl install" in message and "docker compose up" in message
    assert tree(root) == before
    assert mode_of(root / ".env") == 0o644


def test_bridge_install_refuses_a_token_that_is_a_symlink(root, config, services, tmp_path_factory):
    target = tmp_path_factory.mktemp("elsewhere") / "victim"
    target.write_text("keep")
    (root / "secrets").mkdir(mode=0o711)
    (root / "secrets" / "token").symlink_to(target)
    with pytest.raises(InstallError, match="symlink"):
        install(config, services=services)
    assert target.read_text() == "keep"


# Uninstall ============================================================================================================


def test_bridge_uninstall_removes_the_token_and_tolerates_its_absence(root, config, services, docker):
    assert install(config, services=services) == 0
    present_at_down: list[bool] = []
    docker.on_call = lambda: present_at_down.append((root / "secrets" / "token").exists())
    assert uninstall(config, services=services) == 0
    assert docker.calls == [(["docker", "compose", "down", "--remove-orphans"], root)]
    assert present_at_down == [True]  # the container goes down while the file it mounts still exists
    assert not (root / "secrets").exists()
    assert (root / ".env").exists()
    assert uninstall(config, services=services) == 0
    assert len(docker.calls) == 2


def test_bridge_uninstall_keeps_the_token_when_the_container_will_not_go_down(root, config, docker):
    assert install(config, services=Services(run=docker)) == 0
    failing = Docker(returncode=1)
    assert uninstall(config, services=Services(run=failing)) != 0
    assert (root / "secrets" / "token").exists()


def test_bridge_uninstall_without_docker_cannot_tell_whether_the_container_runs_and_keeps_the_token(
    root, config, capsys
):
    assert install(config, services=Services(run=Docker())) == 0
    assert uninstall(config, services=Services(run=Docker(missing=True))) == 1
    err = capsys.readouterr().err
    assert "docker" in err and "could not be checked" in err and "--force" in err
    assert (root / "secrets" / "token").exists()


def test_bridge_uninstall_force_skips_docker_and_removes_the_token(root, config, capsys):
    assert install(config, services=Services(run=Docker())) == 0
    docker = Docker(missing=True)
    assert uninstall(config, force=True, services=Services(run=docker)) == 0
    assert docker.calls == []
    assert not (root / "secrets").exists()
    assert "--force" in capsys.readouterr().out


def test_bridge_uninstall_never_removes_through_a_symlinked_secrets_dir(root, config, services, tmp_path_factory):
    target = tmp_path_factory.mktemp("elsewhere")
    (target / "token").write_text("keep")
    (root / "secrets").symlink_to(target)
    with pytest.raises(InstallError, match="symlink"):
        uninstall(config, services=services)
    assert (target / "token").read_text() == "keep"
    assert (root / "secrets").is_symlink()


def test_bridge_uninstall_removes_the_empty_directory_docker_left_at_the_token(root, config, services):
    (root / "secrets" / "token").mkdir(parents=True)
    assert uninstall(config, services=services) == 0
    assert not (root / "secrets").exists()


# A later step failing -------------------------------------------------------------------------------------------------


def test_the_recreate_notice_survives_a_failure_after_the_token_changed(root, config, services, capsys, monkeypatch):
    assert install(config, services=services) == 0
    capsys.readouterr()
    changed = write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN)

    def fail(path, *args, **kwargs):
        raise PermsError(f"{path}: injected")

    monkeypatch.setattr(perms, "harden_file", fail)
    with pytest.raises(PermsError, match="injected"):
        install(changed, services=services)
    err = capsys.readouterr().err
    assert "recreate" in err and "drops every connected tunnel" in err
    assert (root / "secrets" / "token").read_text() == OTHER_TOKEN + "\n"


def test_the_recreate_notice_survives_a_failure_inside_the_write_itself(root, config, services, capsys, monkeypatch):
    """`write_secret` fails after its rename (the directory sync): the token has changed though the call raised."""
    assert install(config, services=services) == 0
    capsys.readouterr()
    changed = write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN)
    real = perms.write_secret

    def write_then_fail(*args, **kwargs):
        real(*args, **kwargs)
        raise PermsError("injected after the rename")

    monkeypatch.setattr(perms, "write_secret", write_then_fail)
    with pytest.raises(PermsError, match="injected"):
        install(changed, services=services)
    assert "drops every connected tunnel" in capsys.readouterr().err


def test_no_recreate_notice_when_the_write_failed_and_the_old_token_stands(root, config, services, capsys, monkeypatch):
    assert install(config, services=services) == 0
    capsys.readouterr()
    changed = write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN)

    def fail(*args, **kwargs):
        raise PermsError("injected before the rename")

    monkeypatch.setattr(perms, "write_secret", fail)
    with pytest.raises(PermsError):
        install(changed, services=services)
    assert "recreate" not in capsys.readouterr().err
    assert (root / "secrets" / "token").read_text() == GOOD_TOKEN + "\n"


def test_the_notice_says_so_when_it_cannot_tell_whether_the_token_changed(root, config, services, capsys, monkeypatch):
    assert install(config, services=services) == 0
    capsys.readouterr()
    changed = write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN)
    real = installer.read_file
    reads = []

    def read_once_then_fail(*args, **kwargs):
        reads.append(args)
        if len(reads) > 1:
            raise OSError(5, "I/O error")
        return real(*args, **kwargs)

    monkeypatch.setattr(installer, "read_file", read_once_then_fail)
    assert install(changed, services=services) == 1
    err = capsys.readouterr().err
    assert "may now hold the new RT_TOKEN (could not re-read it)" in err
    assert "drops every connected tunnel" in err


def test_the_notice_says_now_holds_when_it_re_read_the_new_token(root, config, services, capsys):
    assert install(config, services=services) == 0
    capsys.readouterr()
    assert install(write_env(root, Role.BRIDGE, RT_TOKEN=OTHER_TOKEN), services=services) == 1
    err = capsys.readouterr().err
    assert "now holds the new RT_TOKEN" in err and "could not re-read" not in err
