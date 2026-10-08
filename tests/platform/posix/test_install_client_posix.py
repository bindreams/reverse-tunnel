import os
import stat
from pathlib import Path

import pytest

from ctl import binaries
from ctl.config import Config, Role
from ctl.download import Fetcher
from ctl.errors import InstallError
from ctl.install import Services, install, uninstall
from ctl.perms import PermsError
from tests.deployment_support import write_env
from tests.unit.binaries_support import SEED_LOCK, VERSIONS, Upstream


@pytest.fixture
def services(tmp_path_factory) -> Services:
    upstream = Upstream()
    for tool, version in VERSIONS.items():
        upstream.add_tool(tool, version)
    lock = tmp_path_factory.mktemp("lock") / "binaries.lock.toml"
    lock.write_text(SEED_LOCK)
    binaries.refresh(lock, None, transport=upstream.transport)
    return Services(
        lock_path=lock,
        platform="linux-x86_64",
        fetcher=lambda: Fetcher(transport=upstream.transport),
        run=lambda args, *, cwd: pytest.fail("the client runs no commands", pytrace=False),
    )


@pytest.fixture
def config(tmp_path) -> Config:
    return write_env(tmp_path, Role.CLIENT)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_client_install_hardens_env_and_installs_an_executable(config, services, tmp_path):
    assert mode_of(tmp_path / ".env") == 0o644
    assert install(config, services=services) == 0
    assert mode_of(tmp_path / ".env") == 0o600
    assert mode_of(tmp_path / "bin") == 0o755
    assert mode_of(tmp_path / "bin" / "websocat") == 0o755
    assert (tmp_path / "bin").stat().st_uid == os.geteuid()


def test_client_install_refuses_a_symlinked_bin_and_follows_nothing(config, services, tmp_path, tmp_path_factory):
    target = tmp_path_factory.mktemp("elsewhere")
    (tmp_path / "bin").symlink_to(target)
    with pytest.raises(PermsError, match="symlink"):
        install(config, services=services)
    assert list(target.iterdir()) == []
    assert mode_of(tmp_path / ".env") == 0o644


def test_client_uninstall_never_removes_through_a_symlinked_bin(config, services, tmp_path, tmp_path_factory):
    target = tmp_path_factory.mktemp("elsewhere")
    (target / "websocat").write_text("keep")
    (tmp_path / "bin").symlink_to(target)
    with pytest.raises(InstallError, match="symlink"):
        uninstall(config, services=services)
    assert (target / "websocat").read_text() == "keep"
