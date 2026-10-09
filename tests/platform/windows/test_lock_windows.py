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


def test_adopting_a_handle_to_another_file_is_refused(tmp_path):
    import msvcrt
    import os

    stranger = tmp_path / "stranger"
    stranger.write_text("x")
    with open(stranger, "rb") as handle:
        with pytest.raises(InstallError, match="lock"):
            lock.adopt(tmp_path, msvcrt.get_osfhandle(handle.fileno()), command="install")


def test_adopting_the_handle_of_the_lock_itself_succeeds(tmp_path):
    with lock.acquire(tmp_path, command="install") as held:
        lock.adopt(tmp_path, held.descriptor, command="install")


def test_adopting_a_number_that_is_no_handle_is_refused(tmp_path):
    with pytest.raises(InstallError, match="lock"):
        lock.adopt(tmp_path, 0x7FFF0, command="install")
