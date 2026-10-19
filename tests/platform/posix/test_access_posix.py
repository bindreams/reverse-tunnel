"""Whether an account could write a path, from its mode and ownership."""

import os
import pwd

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


# The traversal seam ===================================================================================================


def test_a_separate_account_is_refused_with_a_message_that_names_the_account(tmp_path):
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(tmp_path, STRANGER)
    message = str(raised.value)
    assert "separate-account" in message and "not yet available" in message and "stranger" in message
    assert "RT_SERVICE_USER" in message


def test_the_account_that_owns_the_deployment_is_not_asked_to_prove_traversal(tmp_path):
    access.verify_traversable(tmp_path, mine())
