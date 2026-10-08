"""The compose-first hazard, with the ownership Docker really leaves: root-owned `secrets/` and `secrets/token`."""

import contextlib
import os
import shutil
import stat
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from ctl.config import Config, Role
from ctl.errors import InstallError
from ctl.install import Services, install
from tests.deployment_support import GOOD_TOKEN, tree, write_env

OPERATOR_UID = OPERATOR_GID = 4242


@contextlib.contextmanager
def as_operator() -> Generator[None]:
    """Run the block with the effective ids of an unprivileged operator; root is restored on exit."""
    os.setegid(OPERATOR_GID)
    os.seteuid(OPERATOR_UID)
    try:
        yield
    finally:
        os.seteuid(0)
        os.setegid(0)


@pytest.fixture
def deployment() -> Generator[Path]:
    """The state after `docker compose up` ran first: the operator's tree plus root-owned directories Docker made."""
    # /tmp rather than $TMPDIR: the operator must be able to reach it, and macOS's $TMPDIR is private to its owner.
    root = Path(tempfile.mkdtemp(prefix="rt-compose-first-", dir="/tmp"))
    os.chown(root, OPERATOR_UID, OPERATOR_GID)
    root.chmod(0o755)
    write_env(root, Role.BRIDGE)
    os.chown(root / ".env", OPERATOR_UID, OPERATOR_GID)
    (root / "secrets" / "token").mkdir(parents=True)  # created as root, as Docker's daemon does
    try:
        yield root
    finally:
        shutil.rmtree(root)


def install_as_operator(root: Path) -> int:
    with as_operator():
        return install(Config.load(root), services=Services(run=lambda args, *, cwd: pytest.fail("no docker")))


@pytest.mark.root
def test_bridge_install_detects_a_compose_created_token_directory(deployment):
    before = tree(deployment)
    with pytest.raises(InstallError) as raised:
        install_as_operator(deployment)
    message = str(raised.value)
    assert "sudo rm -rf ./secrets" in message
    assert "ctl install" in message and "docker compose up" in message
    steps = message[message.index(", run `"):]  # the instruction, after the explanation that also names the commands
    assert steps.index("sudo rm -rf ./secrets") < steps.index("ctl install") < steps.index("docker compose up")
    assert tree(deployment) == before
    assert stat.S_IMODE((deployment / ".env").stat().st_mode) == 0o644  # nothing was mutated before the refusal


@pytest.mark.root
def test_a_root_owned_secrets_dir_is_named_even_when_the_token_directory_is_absent(deployment):
    (deployment / "secrets" / "token").rmdir()
    with pytest.raises(InstallError) as raised:
        install_as_operator(deployment)
    assert "sudo rm -rf ./secrets" in str(raised.value)
    assert "owned by uid 0" in str(raised.value)


@pytest.mark.root
def test_the_named_remedy_works(deployment):
    with pytest.raises(InstallError):
        install_as_operator(deployment)
    shutil.rmtree(deployment / "secrets")  # what `sudo rm -rf ./secrets` does, in a throwaway directory
    assert install_as_operator(deployment) == 0
    token = deployment / "secrets" / "token"
    assert token.read_text() == GOOD_TOKEN + "\n"
    assert (token.stat().st_uid, (deployment / "secrets").stat().st_uid) == (OPERATOR_UID, OPERATOR_UID)
