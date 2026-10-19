"""The traversal check: which path the service account cannot reach, and how the kernel's answer is read."""

import errno
import os
import stat
import subprocess
import sys
import types
from pathlib import Path, PurePosixPath

import pytest

from ctl import access
from ctl.access import Inspection
from ctl.errors import InstallError
from ctl.perms import Account

ROOT = PurePosixPath("/srv/rt")
SERVICE = Account("rt-test-svc", 998, 998)


def asker(refused: set[str]):
    """A fake `can` that answers `False` for the paths in `refused` and records every question in order."""
    asked: list[tuple[str, str]] = []

    def can(flag: str, path: PurePosixPath) -> bool:
        asked.append((flag, str(path)))
        return str(path) not in refused

    return can, asked


# first_untraversable --------------------------------------------------------------------------------------------------


def test_the_first_untraversable_ancestor_is_returned():
    can, asked = asker({"/srv"})
    assert access.first_untraversable(PurePosixPath("/srv/rt"), can) == PurePosixPath("/srv")
    assert asked == [("-x", "/"), ("-x", "/srv")]


def test_a_root_directory_that_is_itself_closed_is_returned_after_its_ancestors():
    can, asked = asker({"/srv/rt"})
    assert access.first_untraversable(ROOT, can) == ROOT
    assert asked == [("-x", "/"), ("-x", "/srv"), ("-x", "/srv/rt")]


def test_an_unreadable_frpc_config_is_returned():
    can, asked = asker({"/srv/rt/host/frpc.toml"})
    assert access.first_untraversable(ROOT, can) == ROOT / "host" / "frpc.toml"
    assert asked[-2:] == [("-x", "/srv/rt/host"), ("-r", "/srv/rt/host/frpc.toml")]


def test_a_closed_host_directory_is_returned_before_the_config_is_asked_about():
    can, asked = asker({"/srv/rt/host"})
    assert access.first_untraversable(ROOT, can) == ROOT / "host"
    assert ("-r", "/srv/rt/host/frpc.toml") not in asked


def test_a_fully_reachable_tree_returns_none():
    can, asked = asker(set())
    assert access.first_untraversable(ROOT, can) is None
    assert asked == [("-x", "/"), ("-x", "/srv"), ("-x", "/srv/rt"), ("-x", "/srv/rt/host"),
                     ("-r", "/srv/rt/host/frpc.toml")]


# account_can ----------------------------------------------------------------------------------------------------------


class Ran:
    """Stands in for `subprocess.run`."""

    def __init__(self, *, returncode=0, stdout="", stderr="", raises: Exception | None = None):
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.raises = raises
        self.argv: list[str] = []
        self.kwargs: dict = {}

    def __call__(self, argv, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        if self.raises is not None:
            raise self.raises
        return self.result


@pytest.mark.parametrize(("stdout", "expected"), [("rt-traverse:0\n", True), ("rt-traverse:1\n", False),
                                                  ("motd noise\nrt-traverse:0\n", True)])
def test_account_can_reads_the_sentinel(monkeypatch, stdout, expected):
    monkeypatch.setattr(access.subprocess, "run", Ran(stdout=stdout))
    assert access.account_can(SERVICE, "-x", PurePosixPath("/srv/rt")) is expected


def test_account_can_never_lets_the_wrapper_prompt_and_decodes_leniently(monkeypatch):
    ran = Ran(stdout="rt-traverse:0\n")
    monkeypatch.setattr(access.subprocess, "run", ran)
    access.account_can(SERVICE, "-x", PurePosixPath("/srv/rt"))
    assert ran.kwargs["stdin"] is subprocess.DEVNULL
    assert ran.kwargs["capture_output"] is True and ran.kwargs["text"] is True
    assert ran.kwargs["errors"] == "replace"


@pytest.mark.parametrize(
    ("ran", "needle"),
    [
        (Ran(returncode=1, stderr="runuser: may not be used by non-root users\n"), "may not be used by non-root"),
        (Ran(returncode=1, stderr="sudo: a password is required\n"), "a password is required"),
        (Ran(raises=FileNotFoundError(2, "No such file or directory")), "No such file"),
        (Ran(stdout="rt-traverse:2\n"), "rt-traverse:2"),
        (Ran(stdout="rt-traverse:0\nlater noise\n"), "later noise"),
        (Ran(stdout=""), "exited 0"),
        (Ran(returncode=1, stdout="rt-traverse:0\n"), "exited 1"),
        (Ran(returncode=126, stdout="rt-traverse:1\n"), "exited 126"),
    ],
    ids=[
        "runuser-refused", "sudo-wants-a-password", "wrapper-missing", "another-status", "sentinel-not-last",
        "status-0-without-output", "nonzero-status-with-a-yes", "nonzero-status-with-a-no"
    ],
)
def test_account_can_raises_when_the_wrapper_fails(monkeypatch, ran, needle):
    monkeypatch.setattr(access.subprocess, "run", ran)
    with pytest.raises(InstallError) as raised:
        access.account_can(SERVICE, "-x", PurePosixPath("/srv/rt"))
    message = str(raised.value)
    assert needle in message and "rt-test-svc" in message and "/srv/rt" in message
    assert "not traversable" not in message


def test_account_can_reports_undecodable_wrapper_output_as_an_install_error(monkeypatch):
    """A wrapper message in a non-UTF-8 locale must not escape as a UnicodeDecodeError."""
    stderr = b"runuser: \xff\xfe\n"

    def run(argv, **kwargs):
        errors = kwargs.get("errors", "strict")
        return subprocess.CompletedProcess(argv, 1, "", stderr.decode("utf-8", errors=errors))

    monkeypatch.setattr(access.subprocess, "run", run)
    with pytest.raises(InstallError) as raised:
        access.account_can(SERVICE, "-x", PurePosixPath("/srv/rt"))
    message = str(raised.value)
    assert "runuser -u rt-test-svc" in message and "/srv/rt" in message


@pytest.mark.parametrize(("platform", "prefix"), [("linux", ["runuser", "-u", "rt-test-svc", "--"]),
                                                  ("darwin", ["sudo", "-n", "-u", "rt-test-svc"])])
def test_account_can_builds_the_platform_command(monkeypatch, platform, prefix):
    ran = Ran(stdout="rt-traverse:0\n")
    monkeypatch.setattr(access.subprocess, "run", ran)
    monkeypatch.setattr(sys, "platform", platform)
    access.account_can(SERVICE, "-r", PurePosixPath("/srv/rt/host/frpc.toml"))
    assert ran.argv[:len(prefix)] == prefix
    assert ran.argv[len(prefix):] == [
        "sh", "-c", 'test "$1" "$2"; echo "rt-traverse:$?"', "sh", "-r", "/srv/rt/host/frpc.toml"
    ]


# inspect_path ---------------------------------------------------------------------------------------------------------


def status(mode: int, uid: int = 1000) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


def lstat_returning(monkeypatch, answer) -> None:
    """Make `os.lstat` answer for `/probe` only; any other path reaches the real one."""
    real = os.lstat

    def lstat(path, *args, **kwargs):
        if os.fspath(path) not in ("/probe", "\\probe"):
            return real(path, *args, **kwargs)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(access.os, "lstat", lstat)


PROBE = PurePosixPath("/probe")


@pytest.mark.parametrize("error", [FileNotFoundError(errno.ENOENT, "gone"), NotADirectoryError(errno.ENOTDIR, "no")])
def test_only_not_found_errors_mean_missing(monkeypatch, error):
    lstat_returning(monkeypatch, error)
    assert access.inspect_path(PROBE).kind == "missing"


@pytest.mark.parametrize(
    "error", [
        OSError(errno.ELOOP, "Too many levels of symbolic links"),
        PermissionError(errno.EACCES, "Permission denied"),
        OSError(errno.EIO, "Input/output error"),
    ]
)
def test_any_other_error_is_reported_with_its_text(monkeypatch, error):
    lstat_returning(monkeypatch, error)
    found = access.inspect_path(PROBE)
    assert found.kind == "error" and str(error) in found.detail


@pytest.mark.parametrize(("mode", "kind"), [(stat.S_IFDIR | 0o700, "directory"), (stat.S_IFREG | 0o600, "file"),
                                            (stat.S_IFSOCK | 0o600, "other"), (stat.S_IFIFO | 0o600, "other")])
def test_the_kind_comes_from_the_file_type(monkeypatch, mode, kind):
    lstat_returning(monkeypatch, status(mode))
    found = access.inspect_path(PROBE)
    assert (found.kind, found.mode) == (kind, stat.S_IMODE(mode))


def test_a_symlink_carries_its_target_when_it_can_be_read(monkeypatch):
    lstat_returning(monkeypatch, status(stat.S_IFLNK | 0o777))
    monkeypatch.setattr(access.os, "readlink", lambda path: "/etc/elsewhere")
    found = access.inspect_path(PROBE)
    assert (found.kind, found.detail) == ("symlink", "/etc/elsewhere")


def test_a_symlink_whose_target_cannot_be_read_has_no_target(monkeypatch):
    lstat_returning(monkeypatch, status(stat.S_IFLNK | 0o777))

    def unreadable(path):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(access.os, "readlink", unreadable)
    found = access.inspect_path(PROBE)
    assert (found.kind, found.detail) == ("symlink", "")


def test_the_owner_is_a_name_when_the_account_database_knows_it(monkeypatch):
    lstat_returning(monkeypatch, status(stat.S_IFDIR | 0o700, uid=1234))
    fake = types.SimpleNamespace(getpwuid=lambda uid: types.SimpleNamespace(pw_name="anna"))
    monkeypatch.setattr(access, "pwd", fake)
    assert access.inspect_path(PROBE).owner == "anna"


def test_the_owner_falls_back_to_the_numeric_uid_when_the_lookup_fails(monkeypatch):
    lstat_returning(monkeypatch, status(stat.S_IFDIR | 0o700, uid=1234))

    def unknown(uid):
        raise KeyError(uid)

    monkeypatch.setattr(access, "pwd", types.SimpleNamespace(getpwuid=unknown))
    assert access.inspect_path(PROBE).owner == "1234"


def test_the_owner_is_the_numeric_uid_where_there_is_no_account_database(monkeypatch):
    lstat_returning(monkeypatch, status(stat.S_IFDIR | 0o700, uid=1234))
    monkeypatch.setattr(access, "pwd", None)
    assert access.inspect_path(PROBE).owner == "1234"


# verify_traversable ---------------------------------------------------------------------------------------------------


@pytest.fixture
def separate_account(monkeypatch):
    """A POSIX host whose deployment `SERVICE` does not own. The root is a fixed path, so the test runs on every OS."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(access, "account_mode", lambda root, service: access.AccountMode.SEPARATE)
    return Path("/srv/rt")


DIRECTORY = Inspection("directory", 0o755, "operator")
FILE = Inspection("file", 0o644, "operator")
MISSING = Inspection("missing")
SYMLINK = Inspection("symlink", 0o777, "operator", "/etc/elsewhere")
SOCKET = Inspection("other", 0o600, "operator")


def refuse(monkeypatch, blocked: str) -> None:
    """The service account may reach everything but `blocked`."""
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path.as_posix() != blocked)


def inspected(monkeypatch, answers: dict[str, Inspection]) -> None:
    """Answer the inspection from `answers`, else as a well-formed directory or config: no real lookup decides."""
    monkeypatch.setattr(
        access, "inspect_path",
        lambda path: answers.get(path.as_posix(), FILE if path.name == "frpc.toml" else DIRECTORY)
    )


def refusal(root: Path) -> str:
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(root, SERVICE)
    return str(raised.value)


def test_verify_traversable_names_the_path_account_and_an_example_location(separate_account, monkeypatch):
    refuse(monkeypatch, "/srv")
    inspected(monkeypatch, {"/srv": Inspection("directory", 0o700, "operator")})
    message = refusal(separate_account)
    assert "/srv " in message and "rt-test-svc" in message and "/opt/reverse-tunnel" in message
    assert "mode 0700, owner operator" in message and "Nothing was changed" in message


@pytest.mark.parametrize("blocked", ["/", "/srv"], ids=["filesystem-root", "ancestor"])
def test_verify_traversable_advises_relocating_when_an_ancestor_is_closed(separate_account, monkeypatch, blocked):
    refuse(monkeypatch, blocked)
    inspected(monkeypatch, {})
    message = refusal(separate_account)
    assert "/opt/reverse-tunnel" in message and "RT_SERVICE_USER" in message
    assert "chmod" not in message and "git" not in message


def test_verify_traversable_advises_granting_access_when_the_deployment_root_is_closed(separate_account, monkeypatch):
    """Moving the deployment would not change the root's own mode."""
    refuse(monkeypatch, "/srv/rt")
    inspected(monkeypatch, {})
    message = refusal(separate_account)
    assert "chmod o+x /srv/rt" in message and "group" in message
    assert "/opt" not in message and "RT_SERVICE_USER" not in message and "git" not in message


@pytest.mark.parametrize(("blocked", "chmod"), [("/srv/rt/host", "chmod o+x /srv/rt/host"),
                                                ("/srv/rt/host/frpc.toml", "chmod o+r /srv/rt/host/frpc.toml")],
                         ids=["host-directory", "frpc-config"])
def test_verify_traversable_advises_granting_access_when_the_host_files_are_closed(
    separate_account, monkeypatch, blocked, chmod
):
    refuse(monkeypatch, blocked)
    inspected(monkeypatch, {})
    message = refusal(separate_account)
    assert chmod in message and "group" in message and "git" not in message
    assert "/opt" not in message and "/srv/reverse-tunnel" not in message and "RT_SERVICE_USER" not in message


HOST, FRPC = "/srv/rt/host", "/srv/rt/host/frpc.toml"
RESTORE_HOST, RESTORE_FRPC = "git -C /srv/rt checkout -- host", "git -C /srv/rt checkout -- host/frpc.toml"


@pytest.mark.parametrize(
    ("blocked", "found", "command", "described"),
    [
        (HOST, MISSING, RESTORE_HOST, "does not exist"),
        (HOST, SYMLINK, RESTORE_HOST, "symlink to /etc/elsewhere"),
        (HOST, FILE, RESTORE_HOST, "mode 0644"),
        (HOST, SOCKET, RESTORE_HOST, "not a regular file or a directory"),
        (FRPC, MISSING, RESTORE_FRPC, "does not exist"),
        (FRPC, SYMLINK, RESTORE_FRPC, "symlink to /etc/elsewhere"),
        (FRPC, DIRECTORY, RESTORE_FRPC, "mode 0755"),
        (FRPC, SOCKET, RESTORE_FRPC, "not a regular file or a directory"),
    ],
    ids=[
        "host-missing", "host-symlink", "host-a-file", "host-a-socket", "frpc-missing", "frpc-symlink",
        "frpc-a-directory", "frpc-a-socket"
    ],
)
def test_verify_traversable_advises_restoring_a_host_path_that_is_missing_or_the_wrong_type(
    separate_account, monkeypatch, blocked, found, command, described
):
    """chmod cannot get the install through: preflight refuses a link, and a path the checkout lacks has no mode."""
    refuse(monkeypatch, blocked)
    inspected(monkeypatch, {blocked: found})
    message = refusal(separate_account)
    assert command in message and described in message
    assert "chmod" not in message and "RT_SERVICE_USER" not in message and "/opt" not in message


def test_a_symlink_is_described_as_a_link_not_by_its_own_mode(separate_account, monkeypatch):
    refuse(monkeypatch, FRPC)
    inspected(monkeypatch, {FRPC: SYMLINK})
    message = refusal(separate_account)
    assert "0777" not in message and "a symlink to /etc/elsewhere" in message


def test_a_symlink_whose_target_cannot_be_read_is_still_a_symlink(separate_account, monkeypatch):
    refuse(monkeypatch, FRPC)
    inspected(monkeypatch, {FRPC: Inspection("symlink", 0o777, "operator")})
    message = refusal(separate_account)
    assert "a symlink" in message and "symlink to" not in message and RESTORE_FRPC in message


def test_an_unexpected_inspection_error_is_reported_not_called_missing(separate_account, monkeypatch):
    refuse(monkeypatch, FRPC)
    inspected(monkeypatch, {FRPC: Inspection("error", detail="[Errno 40] Too many levels of symbolic links")})
    message = refusal(separate_account)
    assert "[Errno 40] Too many levels of symbolic links" in message and "does not exist" not in message
    assert "git" not in message


def test_verify_traversable_passes_when_every_path_answers_yes(separate_account, monkeypatch):
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: True)
    access.verify_traversable(separate_account, SERVICE)


def test_verify_traversable_asks_nothing_in_same_account_mode(monkeypatch):

    def never(account, flag, path):
        raise AssertionError("asked")

    monkeypatch.setattr(access, "account_mode", lambda root, service: access.AccountMode.SAME)
    monkeypatch.setattr(access, "account_can", never)
    access.verify_traversable(Path("/srv/rt"), SERVICE)


@pytest.mark.parametrize(("blocked", "found", "command"), [
    ("/srv/my rt", DIRECTORY, "chmod o+x '/srv/my rt'"),
    ("/srv/my rt/host", DIRECTORY, "chmod o+x '/srv/my rt/host'"),
    ("/srv/my rt/host/frpc.toml", FILE, "chmod o+r '/srv/my rt/host/frpc.toml'"),
    ("/srv/my rt/host/frpc.toml", MISSING, "git -C '/srv/my rt' checkout -- host/frpc.toml"),
],
                         ids=["chmod-root", "chmod-host", "chmod-config", "git"])
def test_the_suggested_command_quotes_a_path_with_a_space(monkeypatch, blocked, found, command):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(access, "account_mode", lambda root, service: access.AccountMode.SEPARATE)
    refuse(monkeypatch, blocked)
    inspected(monkeypatch, {blocked: found})
    assert command in refusal(Path("/srv/my rt"))
