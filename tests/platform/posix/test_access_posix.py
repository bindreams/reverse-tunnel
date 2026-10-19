"""Whether an account could write a path, from its mode and ownership."""

import grp
import os
import pwd
import shlex
import shutil
import tempfile
from pathlib import Path, PurePosixPath

import pytest

from ctl import access
from ctl.errors import InstallError
from ctl.perms import Account

STRANGER = Account("stranger", os.getuid() + 1, os.getgid() + 1)


def mine() -> Account:
    return Account(pwd.getpwuid(os.getuid()).pw_name, os.getuid(), os.getgid())


@pytest.fixture
def path(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    os.chown(target, -1, os.getgid())  # BSD gives a new file its directory's group, not the process's
    return target


@pytest.mark.parametrize(("mode", "expected"), [(0o777, True), (0o757, True), (0o755, False), (0o775, False),
                                                (0o444, False)])
def test_other_write_bit_decides_for_a_stranger(path, mode, expected):
    path.chmod(mode)
    assert access.service_can_write(path, STRANGER) is expected


@pytest.mark.parametrize(("mode", "expected"), [(0o200, True), (0o700, True), (0o500, False), (0o077, False)])
def test_owner_write_bit_decides_for_the_owner(path, mode, expected):
    path.chmod(mode)
    assert access.service_can_write(path, mine()) is expected


def test_group_write_counts_for_the_primary_group(path):
    path.chmod(0o770)
    in_group = Account("member", os.getuid() + 1, os.getgid())
    assert access.service_can_write(path, in_group) is True
    path.chmod(0o750)
    assert access.service_can_write(path, in_group) is False


def test_group_write_counts_for_a_supplementary_group(path, monkeypatch):
    path.chmod(0o770)
    monkeypatch.setattr(access, "account_groups", lambda account: {os.getgid()})
    assert access.service_can_write(path, STRANGER) is True
    monkeypatch.setattr(access, "account_groups", lambda account: set())
    assert access.service_can_write(path, STRANGER) is False


def test_a_symlink_is_judged_by_what_it_points_to(path, tmp_path):
    path.chmod(0o666)
    link = tmp_path / "link"
    link.symlink_to(path)
    assert access.service_can_write(link, STRANGER) is True
    path.chmod(0o644)
    assert access.service_can_write(link, STRANGER) is False


def test_a_missing_path_is_not_writable(tmp_path):
    assert access.service_can_write(tmp_path / "absent", STRANGER) is False


# The traversal check ==================================================================================================


def test_a_separate_account_is_refused_naming_the_first_untraversable_path(tmp_path, monkeypatch):
    closed = tmp_path.parent
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path != closed)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(tmp_path, STRANGER)
    message = str(raised.value)
    assert f"{closed} is not searchable by stranger" in message and "Nothing was changed" in message
    assert "/opt/reverse-tunnel" in message


def test_the_refusal_names_the_mode_and_owner_of_the_blocked_path(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path != tmp_path)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(tmp_path, STRANGER)
    assert f"mode 0700, owner {mine().name}" in str(raised.value)


def test_a_dangling_symlink_is_a_symlink_and_gets_the_restore_remedy(tmp_path, monkeypatch):
    """A link there is refused later in preflight, so chmod cannot get the install through."""
    config = tmp_path / "host" / "frpc.toml"
    config.parent.mkdir()
    config.symlink_to(tmp_path / "absent")
    found = access.inspect_path(PurePosixPath(config.as_posix()))
    assert (found.kind, found.detail) == ("symlink", str(tmp_path / "absent"))
    monkeypatch.setattr(access, "account_can", lambda account, flag, path: path.name != "frpc.toml")
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(tmp_path, STRANGER)
    message = str(raised.value)
    assert f"git -C {shlex.quote(str(tmp_path))} checkout -- host/frpc.toml" in message and "chmod" not in message


def test_the_account_that_owns_the_deployment_is_not_asked_to_prove_traversal(tmp_path):
    access.verify_traversable(tmp_path, mine())


# The traversal check, with a real account -----------------------------------------------------------------------------


@pytest.fixture
def deployment(request):
    """A deployment root that root owns, under a `/tmp` directory every account can search. Not `tmp_path`: pytest's
    base directory is `0700`."""
    base = Path(tempfile.mkdtemp(prefix="rt-traverse-", dir="/tmp"))
    request.addfinalizer(lambda: shutil.rmtree(base))
    base.chmod(0o755)
    parent = base / "parent"
    root = parent / "deploy"
    (root / "host").mkdir(parents=True)
    (root / "host" / "frpc.toml").write_text("x")
    (root / "host" / "frpc.toml").chmod(0o644)
    for directory in (parent, root, root / "host"):
        directory.chmod(0o755)
    return root


# Created, with `rt-test-svc` as a member, by the CI step that creates the account.
SHARED_GROUP = "rt-test-share"


def service() -> Account:
    entry = pwd.getpwnam("rt-test-svc")
    return Account(entry.pw_name, entry.pw_uid, entry.pw_gid)


@pytest.mark.root
def test_a_0700_parent_is_refused_for_a_separate_account(deployment):
    deployment.parent.chmod(0o700)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(deployment, service())
    assert f"{deployment.parent} is not searchable by rt-test-svc" in str(raised.value)


@pytest.mark.root
def test_a_0750_parent_outside_the_accounts_groups_is_refused(deployment):
    deployment.parent.chmod(0o750)
    assert deployment.parent.stat().st_gid not in access.account_groups(service())
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(deployment, service())
    assert f"{deployment.parent} is not searchable by rt-test-svc" in str(raised.value)


@pytest.mark.root
def test_a_traversable_tree_passes_for_a_separate_account(deployment):
    access.verify_traversable(deployment, service())


@pytest.mark.root
def test_a_0750_parent_in_a_group_the_account_belongs_to_passes(deployment):
    """Group access is judged by the kernel, as the account, not worked out from the modes."""
    shared = grp.getgrnam(SHARED_GROUP).gr_gid  # a missing group fails the test, never skips it
    assert shared in access.account_groups(service())
    os.chown(deployment.parent, -1, shared)
    deployment.parent.chmod(0o750)
    access.verify_traversable(deployment, service())


@pytest.mark.root
def test_a_config_only_root_can_read_is_refused_as_not_readable(deployment):
    config = deployment / "host" / "frpc.toml"
    config.chmod(0o600)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(deployment, service())
    message = str(raised.value)
    assert f"{config} is not readable by rt-test-svc" in message and "mode 0600, owner root" in message
    assert "chmod o+r" in message


@pytest.mark.root
def test_a_0700_host_directory_is_refused(deployment):
    (deployment / "host").chmod(0o700)
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(deployment, service())
    assert f"{deployment / 'host'} is not searchable by rt-test-svc" in str(raised.value)


@pytest.mark.root
def test_a_deployment_path_containing_a_space_passes(deployment):
    spaced = deployment.parent / "my deployment"
    deployment.rename(spaced)
    access.verify_traversable(spaced, service())
