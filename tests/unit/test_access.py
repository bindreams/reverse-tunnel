"""The traversal check: which path the service account cannot reach, and how the kernel's answer is read."""

import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest

from ctl import access
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
    """Stands in for `subprocess.run`: records the argv and answers with a canned result or raises."""

    def __init__(self, *, returncode=0, stdout="", stderr="", raises: Exception | None = None):
        self.result = subprocess.CompletedProcess([], returncode, stdout, stderr)
        self.raises = raises
        self.argv: list[str] = []

    def __call__(self, argv, **kwargs):
        self.argv = argv
        if self.raises is not None:
            raise self.raises
        return self.result


@pytest.mark.parametrize(("stdout", "expected"), [("rt-traverse:0\n", True), ("rt-traverse:1\n", False),
                                                  ("motd noise\nrt-traverse:0\n", True)])
def test_account_can_reads_the_sentinel(monkeypatch, stdout, expected):
    monkeypatch.setattr(access.subprocess, "run", Ran(stdout=stdout))
    assert access.account_can(SERVICE, "-x", Path("/srv/rt")) is expected


@pytest.mark.parametrize(
    ("ran", "needle"),
    [
        (Ran(returncode=1, stderr="runuser: may not be used by non-root users\n"), "may not be used by non-root"),
        (Ran(returncode=1, stderr="sudo: a password is required\n"), "a password is required"),
        (Ran(raises=FileNotFoundError(2, "No such file or directory")), "No such file"),
        (Ran(stdout="rt-traverse:2\n"), "rt-traverse:2"),
        (Ran(stdout="rt-traverse:0\nlater noise\n"), "later noise"),
    ],
    ids=["runuser-refused", "sudo-wants-a-password", "wrapper-missing", "another-status", "sentinel-not-last"],
)
def test_account_can_raises_when_the_wrapper_fails(monkeypatch, ran, needle):
    monkeypatch.setattr(access.subprocess, "run", ran)
    with pytest.raises(InstallError) as raised:
        access.account_can(SERVICE, "-x", Path("/srv/rt"))
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
        access.account_can(SERVICE, "-x", Path("/srv/rt"))
    message = str(raised.value)
    assert "runuser -u rt-test-svc" in message and "/srv/rt" in message


@pytest.mark.parametrize(("platform", "prefix"), [("linux", ["runuser", "-u", "rt-test-svc", "--"]),
                                                  ("darwin", ["sudo", "-n", "-u", "rt-test-svc"])])
def test_account_can_builds_the_platform_command(monkeypatch, platform, prefix):
    ran = Ran(stdout="rt-traverse:0\n")
    monkeypatch.setattr(access.subprocess, "run", ran)
    monkeypatch.setattr(sys, "platform", platform)
    access.account_can(SERVICE, "-r", Path("/srv/rt/host/frpc.toml"))
    assert ran.argv[:len(prefix)] == prefix
    assert ran.argv[len(prefix):] == [
        "sh", "-c", 'test "$1" "$2"; echo "rt-traverse:$?"', "sh", "-r", "/srv/rt/host/frpc.toml"
    ]


# verify_traversable ---------------------------------------------------------------------------------------------------


@pytest.fixture
def separate_account(monkeypatch):
    """A POSIX host whose deployment `SERVICE` does not own. The root is a fixed path, so the test runs on every OS."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(access, "account_mode", lambda root, service: access.AccountMode.SEPARATE)
    return Path("/srv/rt")


def test_verify_traversable_names_the_path_account_and_an_example_location(separate_account, monkeypatch):
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: str(path.as_posix()) != "/srv")
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(separate_account, SERVICE)
    message = str(raised.value)
    assert "/srv " in message and "rt-test-svc" in message and "/opt/reverse-tunnel" in message
    assert "Nothing was changed" in message


@pytest.mark.parametrize("blocked", ["/", "/srv", "/srv/rt"], ids=["filesystem-root", "ancestor", "deployment-root"])
def test_verify_traversable_advises_relocating_when_the_root_or_an_ancestor_is_closed(
    separate_account, monkeypatch, blocked
):
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path.as_posix() != blocked)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(separate_account, SERVICE)
    message = str(raised.value)
    assert "/opt/reverse-tunnel" in message and "RT_SERVICE_USER" in message
    assert "chmod" not in message


@pytest.mark.parametrize(("blocked", "chmod"), [("/srv/rt/host", "chmod o+x /srv/rt/host"),
                                                ("/srv/rt/host/frpc.toml", "chmod o+r /srv/rt/host/frpc.toml")],
                         ids=["host-directory", "frpc-config"])
def test_verify_traversable_advises_granting_access_when_the_host_files_are_closed(
    separate_account, monkeypatch, blocked, chmod
):
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path.as_posix() != blocked)
    monkeypatch.setattr(access, "_exists", lambda path: True)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(separate_account, SERVICE)
    message = str(raised.value)
    assert chmod in message and "group" in message and "git" not in message
    assert "/opt" not in message and "/srv/reverse-tunnel" not in message and "RT_SERVICE_USER" not in message
    assert "Move the deployment" not in message


def test_verify_traversable_says_when_the_config_does_not_exist(separate_account, monkeypatch):
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: flag != "-r")
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(separate_account, SERVICE)
    message = str(raised.value)
    assert "/srv/rt/host/frpc.toml" in message and "does not exist" in message
    # Permissions cannot fix a file the checkout lacks.
    assert "git -C /srv/rt checkout -- host/frpc.toml" in message and "chmod" not in message


def test_verify_traversable_passes_when_every_path_answers_yes(separate_account, monkeypatch):
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: True)
    access.verify_traversable(separate_account, SERVICE)


def test_verify_traversable_asks_nothing_in_same_account_mode(monkeypatch):

    def never(account, flag, path):
        raise AssertionError("asked")

    monkeypatch.setattr(access, "account_mode", lambda root, service: access.AccountMode.SAME)
    monkeypatch.setattr(access, "account_can", never)
    access.verify_traversable(Path("/srv/rt"), SERVICE)


@pytest.mark.parametrize(("blocked", "exists", "command"), [
    ("/srv/my rt/host", True, "chmod o+x '/srv/my rt/host'"),
    ("/srv/my rt/host/frpc.toml", False, "git -C '/srv/my rt' checkout -- host/frpc.toml"),
],
                         ids=["chmod", "git"])
def test_the_suggested_command_quotes_a_path_with_a_space(monkeypatch, blocked, exists, command):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(access, "account_mode", lambda root, service: access.AccountMode.SEPARATE)
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path.as_posix() != blocked)
    monkeypatch.setattr(access, "_exists", lambda path: exists)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(Path("/srv/my rt"), SERVICE)
    assert command in str(raised.value)


def test_a_dangling_symlink_counts_as_missing(tmp_path):
    link = tmp_path / "frpc.toml"
    link.symlink_to(tmp_path / "absent")
    assert access._exists(PurePosixPath(link.as_posix())) is False
