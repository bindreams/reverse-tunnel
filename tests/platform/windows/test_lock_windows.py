"""The install lock on Windows: a handle opened with no sharing, which a detached child inherits."""

import pytest

from ctl import lock
from ctl.errors import InstallError


def test_a_second_acquire_fails_at_once(tmp_path):
    with lock.acquire(tmp_path, command="install"):
        with pytest.raises(InstallError, match="already running"):
            lock.acquire(tmp_path, command="uninstall")


def test_the_lock_is_free_after_close(tmp_path):
    lock.acquire(tmp_path, command="install").close()
    lock.acquire(tmp_path, command="install").close()


def test_the_handle_can_be_passed_to_a_child(tmp_path):
    import os

    with lock.acquire(tmp_path, command="install") as held:
        assert os.get_handle_inheritable(held.descriptor) is False  # only made inheritable by the spawn that passes it
