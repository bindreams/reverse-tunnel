"""`ctl doctor`'s check of the service's read, run against the ACLs `grant_service_read` really writes."""

from pathlib import Path

from tests.unit.deployment_support import write_env

from ctl import perms_windows, winacl
from ctl.config import Config, Role
from ctl.doctor import Outcome
from ctl.doctor.permissions import Permissions
from ctl.doctor.probes import Probes
from ctl.perms import SID_LOCAL_SERVICE, Account, grant_service_read

LOCAL_SERVICE = Account("LocalService", None, None)


def installed_repo(tmp_path: Path) -> tuple[Path, Config]:
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    (repo / "host").mkdir()
    (repo / "bin" / "frpc.exe").write_bytes(b"")
    (repo / "bin" / ".digests.json").write_bytes(b"{}")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    config = write_env(repo, Role.HOST)
    grant_service_read(repo, LOCAL_SERVICE)
    return repo, config


def test_doctor_passes_what_grant_service_read_writes(tmp_path):
    _, config = installed_repo(tmp_path)
    outcome, detail = Permissions(config, Probes()).service_read()
    assert outcome is Outcome.PASS, detail


def test_doctor_fails_the_inheritable_root_ace_an_earlier_install_wrote(tmp_path):
    repo, config = installed_repo(tmp_path)
    with perms_windows._handle(repo, directory=True, access=perms_windows.ACL_ACCESS) as handle:
        entries, protected = winacl.read_entries(handle)
        old = [
            e._replace(flags=winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE)
            if e.sid == SID_LOCAL_SERVICE and not e.flags & winacl.INHERITED_ACE else e for e in entries
        ]
        winacl.set_dacl(handle, old, protected=protected)
    outcome, detail = Permissions(config, Probes()).service_read()
    assert outcome is Outcome.FAIL
    assert f"{repo}: " in detail and "is inheritable" in detail and "ctl install" in detail
