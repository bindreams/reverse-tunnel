"""The groups the install assumes the service's token holds, checked against the token of a real service.

The service manager starts a daemon the way goetia installs it: through `goetia-shim`, as LocalService, which runs the
daemon's command. The test installs such a service whose command lists the groups of its own token, then uninstalls it.
"""

import csv
import io
import json
import os
import shutil
import subprocess
import winreg
from pathlib import Path

import pytest
import yaml
from tests.platform.windows.service_access import service_token
from tests.unit.dry_run_support import goetia_binary

from ctl import authz, goetia, perms_windows, winacl
from ctl.perms import SID_LOCAL_SERVICE, Account, PermsError

# The integrity label in a service token is no group: measured, a deny ACE naming it does not stop the service and an
# allow ACE naming it does not let the service in. Every other SID the token lists is a group an ACE can name,
# including the unnamed per-build aliases `S-1-5-32-<eight sub-authorities>` (a deny for one stops the service).
LABEL_PREFIX = "S-1-16-"
ALL = 0x1F01FF
DAEMON = "rttoken"
SERVICE_WAIT_MS = 120_000
SCRIPT = """@whoami.exe /groups /fo csv > groups.csv
@whoami.exe /user /fo csv > user.csv
@echo x > done
@waitfor.exe /t 99999 rttokenhold
"""


def groups_of(rows: list[dict[str, str]], user: str) -> set[str]:
    """The SIDs of the token's rows that are groups an ACE can name, without the account's own SID."""
    return {row["SID"] for row in rows if not row["SID"].startswith(LABEL_PREFIX)} - {user}


def alias(sid: str) -> bool:
    return sid.startswith("S-1-5-32-") and sid.count("-") > 4


def run(*command: str) -> None:
    done = subprocess.run(command, capture_output=True, text=True)
    assert done.returncode == 0, f"{command}: {done.returncode}: {done.stdout}{done.stderr}"


def rows_of(path: Path) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(path.read_text(encoding="utf-8", errors="replace"))))


def service_token_rows(root: Path, binaries: Path) -> tuple[list[dict[str, str]], str]:
    """The groups of a token the service manager gives LocalService, and its user SID, as the daemon itself lists them.

    `root` is a deployment of one daemon, `rttoken`, installed through goetia like the real ones and started by it; its
    command writes `whoami /groups` and `whoami /user` into `root/out`, then stays up until it is uninstalled.
    """
    import win32con
    import win32event
    import win32file

    root.mkdir()
    run("icacls", str(root), "/grant", f"*{SID_LOCAL_SERVICE}:(OI)(CI)M")
    (root / "bin").mkdir()
    for member in binaries.iterdir():
        if member.is_file():
            shutil.copy(member, root / "bin" / member.name)
    out = root / "out"
    out.mkdir()
    script = out / "run.cmd"
    script.write_text(SCRIPT, newline="\r\n")
    command = [str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"), "/c", str(script)]
    manifest = {
        "daemons": {
            DAEMON: {
                "command": command,
                "cwd": str(out),
                "logs": str(out / "service.log"),
                "backend-specific": {"scm": {"user": "LocalService"}},
            }
        }
    }
    (root / goetia.MANIFEST).write_text(yaml.safe_dump(manifest))
    done = out / "done"
    notify = win32file.FindFirstChangeNotification(str(out), False, win32con.FILE_NOTIFY_CHANGE_FILE_NAME)
    try:
        try:
            goetia.daemon_install(root, DAEMON, enable=True)
            goetia.daemon_start(root, DAEMON)
            while not done.exists():
                # external-bound: the service writing its result
                if win32event.WaitForSingleObject(notify, SERVICE_WAIT_MS) != win32event.WAIT_OBJECT_0:
                    log = (out / "service.log").read_text(errors="replace") if (out / "service.log").exists() else ""
                    raise AssertionError(f"the service {DAEMON} wrote nothing in {SERVICE_WAIT_MS // 1000} s: {log}")
                win32file.FindNextChangeNotification(notify)
        finally:
            goetia.daemon_uninstall(root, [DAEMON])
    finally:
        win32file.FindCloseChangeNotification(notify)
    users = rows_of(out / "user.csv")
    assert len(users) == 1, users
    return rows_of(out / "groups.csv"), users[0]["SID"]


def denying(sid: str) -> bytes:
    """A descriptor that allows the service everything and then denies the group `sid` read-and-execute."""
    owner = winacl.SID_ADMINISTRATORS
    entries = [
        winacl.Entry(winacl.ACCESS_DENIED_ACE_TYPE, 0, winacl.READ_EXECUTE, sid),
        winacl.Entry(winacl.ACCESS_ALLOWED_ACE_TYPE, 0, ALL, SID_LOCAL_SERVICE),
    ]
    return authz.descriptor_for(entries, protected=True, owner=owner, group=owner)


@pytest.fixture(scope="module")
def measured(tmp_path_factory):
    """(rows of `whoami /groups`, user SID) from the token of a service installed through the pinned goetia."""
    binaries = goetia_binary(tmp_path_factory).parent
    return service_token_rows(tmp_path_factory.mktemp("service") / "deployment", binaries)


def table(rows: list[dict[str, str]]) -> str:
    return json.dumps([[r["Group Name"], r["SID"], r["Attributes"]] for r in rows], indent=1)


@pytest.mark.goetia
def test_the_well_known_groups_of_a_real_service_token_are_the_ones_the_install_assumes(measured):
    rows, user = measured
    assert user == SID_LOCAL_SERVICE
    well_known = {sid for sid in groups_of(rows, user) if not alias(sid)}
    assert well_known == set(perms_windows.SERVICE_TOKEN_GROUPS), table(rows)


@pytest.mark.goetia
def test_the_groups_of_the_check_context_are_the_groups_of_a_real_service_token(measured):
    rows, user = measured
    real = groups_of(rows, user)
    with service_token() as token:
        context = token.groups() - {user}
    extra, missing = sorted(context - real), sorted(real - context)
    assert context == real, f"only in the context: {extra}; only in the token: {missing}"


@pytest.mark.goetia
def test_a_deny_for_each_group_of_a_real_service_token_is_caught(measured):
    rows, user = measured
    with service_token() as token:
        missed = sorted(sid for sid in groups_of(rows, user) if token.grants(denying(sid), winacl.READ_EXECUTE))
    assert not missed, f"the install's idea of the service's token lacks {missed}: {table(rows)}"


@pytest.mark.parametrize("sid", [SID_LOCAL_SERVICE, *perms_windows.SERVICE_TOKEN_GROUPS])
def test_a_deny_for_the_service_or_a_group_it_is_in_leaves_it_without_read(sid):
    with service_token() as token:
        assert not token.grants(denying(sid), winacl.READ_EXECUTE)


def test_an_allow_for_the_service_alone_leaves_it_with_read():
    allowed = [winacl.Entry(winacl.ACCESS_ALLOWED_ACE_TYPE, 0, winacl.READ_EXECUTE, SID_LOCAL_SERVICE)]
    owner = winacl.SID_ADMINISTRATORS
    with service_token() as token:
        assert token.grants(
            authz.descriptor_for(allowed, protected=True, owner=owner, group=owner), winacl.READ_EXECUTE
        )


BUILTIN_USERS = bytes.fromhex("01020000000000052000000021020000")  # S-1-5-32-545


def test_the_groups_among_registry_values_are_the_group_n_binary_sids():
    values = [
        ("Group1", BUILTIN_USERS, winreg.REG_BINARY),
        ("GROUP12", BUILTIN_USERS, winreg.REG_BINARY),
        ("Other", b"not a sid", winreg.REG_BINARY),
        ("", "default", winreg.REG_SZ),
    ]
    assert perms_windows.lsa_group_sids(values) == ["S-1-5-32-545", "S-1-5-32-545"]


@pytest.mark.parametrize(
    "data,kind", [
        (BUILTIN_USERS, winreg.REG_SZ),
        ("S-1-5-32-545", winreg.REG_SZ),
        (BUILTIN_USERS[:-1], winreg.REG_BINARY),
        (BUILTIN_USERS + b"\0", winreg.REG_BINARY),
        (b"", winreg.REG_BINARY),
        (b"\x02" + BUILTIN_USERS[1:], winreg.REG_BINARY),
    ]
)
def test_a_group_value_that_is_not_one_binary_sid_is_an_error(data, kind):
    with pytest.raises(OSError):
        perms_windows.lsa_group_sids([("Group1", data, kind)])


def test_an_account_the_lsa_adds_no_groups_to_has_only_the_well_known_ones():
    # A well-formed SID that no machine has an LSA key for.
    assert perms_windows.service_token_groups("S-1-5-21-1-2-3-4") == perms_windows.SERVICE_TOKEN_GROUPS


def test_a_failure_to_open_the_lsa_key_names_the_key_not_only_the_path_being_installed(tmp_path, monkeypatch):

    def refuse(*args):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(winreg, "OpenKey", refuse)
    with pytest.raises(PermsError) as raised:
        perms_windows.grant_service_read(tmp_path, Account("LocalService", None, None))
    message = str(raised.value)
    assert f"{perms_windows.LSA_GROUPS_KEY}\\{SID_LOCAL_SERVICE}" in message
    assert "Access is denied" in message
