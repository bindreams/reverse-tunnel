"""The groups the install assumes the service's token holds, checked against a token Windows makes for LocalService.

A scheduled task run as LocalService gets a service logon, like the one the service manager gives a daemon; `whoami`
inside it lists the groups of that token.
"""

import csv
import io
import subprocess
from pathlib import Path

import pytest
from tests.platform.windows.service_access import service_token

from ctl import authz, perms_windows, winacl
from ctl.perms import SID_AUTHENTICATED_USERS, SID_EVERYONE, SID_LOCAL_SERVICE, SID_USERS

SID_SERVICE = "S-1-5-6"
SID_THIS_ORGANIZATION = "S-1-5-15"
# Groups of a LocalService token that name no ACE an operator can write: integrity labels, the task's own SID and the
# per-machine aliases `S-1-5-32-<eight sub-authorities>` the task host adds.
UNNAMEABLE_PREFIXES = ("S-1-16-", "S-1-5-87-")
ALL = 0x1F01FF
TASK = "rttoken"
TASK_WAIT_MS = 120_000


def unnameable(sid: str) -> bool:
    return sid.startswith(UNNAMEABLE_PREFIXES) or (sid.startswith("S-1-5-32-") and sid.count("-") > 4)


def run(*command: str) -> None:
    done = subprocess.run(command, capture_output=True, text=True)
    assert done.returncode == 0, f"{command}: {done.returncode}: {done.stdout}{done.stderr}"


def real_groups(directory: Path) -> set[str]:
    """The group SIDs of a token that Windows makes for LocalService, listed by a task that runs as it."""
    import win32con
    import win32event
    import win32file

    directory.mkdir()
    run("icacls", str(directory), "/grant", f"*{SID_LOCAL_SERVICE}:(OI)(CI)M")
    listing, done, script = directory / "groups.csv", directory / "done", directory / "run.cmd"
    # schtasks takes at most 261 characters of command, which a temporary path can use up by itself.
    script.write_text(f'@whoami.exe /groups /fo csv > "{listing}"\r\n@echo x > "{done}"\r\n')
    notify = win32file.FindFirstChangeNotification(str(directory), False, win32con.FILE_NOTIFY_CHANGE_FILE_NAME)
    try:
        run(
            "schtasks", "/create", "/tn", TASK, "/tr", f'"{script}"', "/sc", "once", "/st", "23:59", "/ru",
            r"NT AUTHORITY\LocalService", "/f"
        )
        try:
            run("schtasks", "/run", "/tn", TASK)
            while not done.exists():
                # external-bound: the scheduled task writing its result
                if win32event.WaitForSingleObject(notify, TASK_WAIT_MS) != win32event.WAIT_OBJECT_0:
                    raise AssertionError(f"the task {TASK} wrote nothing in {TASK_WAIT_MS // 1000} s")
                win32file.FindNextChangeNotification(notify)
        finally:
            run("schtasks", "/delete", "/tn", TASK, "/f")
    finally:
        win32file.FindCloseChangeNotification(notify)
    rows = csv.DictReader(io.StringIO(listing.read_text(encoding="utf-8", errors="replace")))
    return {row["SID"] for row in rows}


def denying(sid: str) -> bytes:
    """A descriptor that allows the service everything and then denies the group `sid` read-and-execute."""
    owner = winacl.SID_ADMINISTRATORS
    entries = [
        winacl.Entry(winacl.ACCESS_DENIED_ACE_TYPE, 0, winacl.READ_EXECUTE, sid),
        winacl.Entry(winacl.ACCESS_ALLOWED_ACE_TYPE, 0, ALL, SID_LOCAL_SERVICE),
    ]
    return authz.descriptor_for(entries, protected=True, owner=owner, group=owner)


def test_a_deny_for_each_group_of_a_real_localservice_token_is_caught(tmp_path):
    groups = {sid for sid in real_groups(tmp_path / "out") if not unnameable(sid)}
    assert groups, "the task listed no groups"
    with service_token() as token:
        missed = sorted(sid for sid in groups if token.grants(denying(sid), winacl.READ_EXECUTE))
    assert not missed, f"the install's idea of the service's token lacks {missed}"


@pytest.mark.parametrize(
    "sid", [
        SID_LOCAL_SERVICE, SID_EVERYONE, SID_USERS, SID_AUTHENTICATED_USERS, SID_SERVICE, SID_THIS_ORGANIZATION,
        *perms_windows.SERVICE_TOKEN_GROUPS
    ]
)
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
