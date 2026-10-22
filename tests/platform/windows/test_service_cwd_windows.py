"""A service whose working directory is `logs` starts only if `logs` grants the service what `winacl.LIST_AND_ADD` names.

goetia-shim spawns the daemon with `current_dir(logs)`, and creating a process in a directory checks it with
`GetFileAttributesW`, which needs FILE_READ_ATTRIBUTES on it. The test installs a real service as LocalService through
goetia, with `logs` holding exactly the rights under test. The service has no `restart:`, so goetia's default `never`
applies: the shim reports the service running only once the one spawn succeeded, and a failed spawn is a failed
`goetia daemon start`, with nothing to wait for.
"""

import contextlib
import os
import shutil
from collections.abc import Generator
from pathlib import Path

import pytest
import yaml
from tests.unit.dry_run_support import goetia_binary

from ctl import goetia, perms_windows, winacl
from ctl.goetia import GoetiaError
from ctl.perms import SID_LOCAL_SERVICE, Account

DAEMON = "rtcwd"
# What the doctor required of `logs` before it asked for FILE_READ_ATTRIBUTES: list, add, traverse, synchronize.
WITHOUT_ATTRIBUTES = 0x1 | 0x2 | 0x20 | 0x100000
INHERIT = winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE


@pytest.fixture(scope="module")
def binaries(tmp_path_factory) -> Path:
    """The directory holding the pinned goetia and goetia-shim."""
    return goetia_binary(tmp_path_factory).parent


def deployment(root: Path, binaries: Path, logs_mask: int) -> None:
    """A deployment of one daemon whose working directory is `logs`, which grants the service `logs_mask` and nothing
    inherited, as an owned directory does. The root grants the service nothing, as after an install: a right to list
    the root would give it the read of attributes of `logs` whatever `logs` grants."""
    root.mkdir()
    allow = winacl.ACCESS_ALLOWED_ACE_TYPE
    operator = perms_windows.operator_sid(root)
    admin_and_operator = [
        winacl.Entry(allow, INHERIT, winacl.FULL, winacl.SID_ADMINISTRATORS),
        winacl.Entry(allow, INHERIT, winacl.FULL, operator),
    ]
    with perms_windows._handle(root, directory=True, access=perms_windows.ACL_ACCESS) as handle:
        winacl.set_dacl(handle, admin_and_operator, protected=True)
    (root / "bin").mkdir()
    for member in binaries.iterdir():
        if member.is_file():
            shutil.copy(member, root / "bin" / member.name)
    perms_windows.converge_owned(root / "bin", Account("LocalService", None, None), write=False, root=root)
    logs = root / "logs"
    logs.mkdir()
    with perms_windows._handle(logs, directory=True, access=perms_windows.ACL_ACCESS) as handle:
        winacl.set_dacl(
            handle,
            [*admin_and_operator, winacl.Entry(allow, INHERIT, logs_mask, SID_LOCAL_SERVICE)], protected=True
        )
    hold = [str(Path(os.environ["SystemRoot"]) / "System32" / "waitfor.exe"), "/t", "99999", "rtcwdhold"]
    manifest = {
        "daemons": {
            DAEMON: {
                "command": hold,
                "cwd": str(logs),
                "logs": str(logs / "rtcwd.log"),
                "backend-specific": {"scm": {"user": "LocalService"}},
            }
        }
    }
    (root / goetia.MANIFEST).write_text(yaml.safe_dump(manifest))


@contextlib.contextmanager
def installed(root: Path) -> Generator[None]:
    goetia.daemon_install(root, DAEMON, enable=True)
    try:
        yield
    finally:
        goetia.daemon_uninstall(root, [DAEMON])


@pytest.mark.goetia
def test_a_service_cannot_start_in_a_logs_directory_that_grants_no_read_of_attributes(tmp_path, binaries):
    root = tmp_path / "without"
    deployment(root, binaries, WITHOUT_ATTRIBUTES)
    with installed(root), pytest.raises(GoetiaError):
        goetia.daemon_start(root, DAEMON)


@pytest.mark.goetia
def test_a_service_starts_in_a_logs_directory_that_grants_what_the_doctor_requires(tmp_path, binaries):
    root = tmp_path / "with"
    deployment(root, binaries, winacl.LIST_AND_ADD)
    with installed(root):
        goetia.daemon_start(root, DAEMON)
