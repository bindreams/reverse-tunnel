"""The lock that keeps two installs, or an install and its own detached child, from running at once."""

import pytest

from ctl import lock
from ctl.errors import InstallError


def test_the_lock_file_is_created_at_the_repository_root(tmp_path):
    with lock.acquire(tmp_path, command="install"):
        assert (tmp_path / lock.LOCK_NAME).is_file()


def test_a_second_acquire_fails_at_once_and_says_an_install_is_running(tmp_path):
    with lock.acquire(tmp_path, command="install"):
        with pytest.raises(InstallError) as raised:
            lock.acquire(tmp_path, command="uninstall")
    message = str(raised.value)
    assert "already running" in message and "ctl" in message


def test_the_lock_is_free_again_once_it_is_closed(tmp_path):
    first = lock.acquire(tmp_path, command="install")
    first.close()
    lock.acquire(tmp_path, command="install").close()


def test_closing_twice_is_harmless(tmp_path):
    held = lock.acquire(tmp_path, command="install")
    held.close()
    held.close()


def test_a_failed_attempt_does_not_release_the_holder(tmp_path):
    with lock.acquire(tmp_path, command="install"):
        with pytest.raises(InstallError):
            lock.acquire(tmp_path, command="install")
        with pytest.raises(InstallError):
            lock.acquire(tmp_path, command="install")


def test_a_directory_in_place_of_the_lock_file_is_refused(tmp_path):
    (tmp_path / lock.LOCK_NAME).mkdir()
    with pytest.raises(InstallError):
        lock.acquire(tmp_path, command="install")
