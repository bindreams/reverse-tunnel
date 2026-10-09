"""The lock on POSIX: `flock` on a file created through the directory descriptor, inherited by the detached child."""

import os
import stat
import sys

import pytest

from ctl import lock
from ctl.detach import spawn_detached
from ctl.errors import InstallError

HOLD = """
import os, sys
lock_fd, go, done = int(sys.argv[1]), sys.argv[2], sys.argv[3]
open(go).read()
os.close(lock_fd)
open(done, "w").write("released")
"""


def test_the_lock_file_is_0640_and_names_the_holder(tmp_path):
    with lock.acquire(tmp_path, command="install") as held:
        assert stat.S_IMODE(os.stat(tmp_path / lock.LOCK_NAME).st_mode) == 0o640
        with pytest.raises(InstallError) as raised:
            lock.acquire(tmp_path, command="uninstall")
        assert f"pid {os.getpid()}" in str(raised.value) and "ctl install" in str(raised.value)
        assert held.descriptor >= 0


def test_a_symlink_in_place_of_the_lock_file_is_refused_and_its_target_untouched(tmp_path):
    target = tmp_path / "target"
    target.write_text("precious")
    (tmp_path / lock.LOCK_NAME).symlink_to(target)
    with pytest.raises(InstallError, match="symlink"):
        lock.acquire(tmp_path, command="install")
    assert target.read_text() == "precious"


def test_a_hard_linked_lock_file_is_refused(tmp_path):
    (tmp_path / "other").write_text("")
    os.link(tmp_path / "other", tmp_path / lock.LOCK_NAME)
    with pytest.raises(InstallError, match="hard link"):
        lock.acquire(tmp_path, command="install")


def test_adopting_an_inherited_descriptor_succeeds_where_acquiring_would_fail(tmp_path):
    with lock.acquire(tmp_path, command="install") as held:
        inherited = os.dup(held.descriptor)  # what the child holds: the same open file description
        try:
            adopted = lock.adopt(tmp_path, inherited, command="install")
            assert adopted.descriptor == inherited
        finally:
            os.close(inherited)


def test_adopting_a_descriptor_that_is_not_the_lock_is_refused(tmp_path):
    stranger = tmp_path / "stranger"
    stranger.write_text("")
    fd = os.open(stranger, os.O_RDWR)
    try:
        with pytest.raises(InstallError, match="lock"):
            lock.adopt(tmp_path, fd, command="install")
    finally:
        os.close(fd)


def test_adopting_a_descriptor_whose_lock_is_not_held_by_it_is_refused(tmp_path):
    """A descriptor to the right file that holds nothing, while someone else holds the lock."""
    with lock.acquire(tmp_path, command="install"):
        fd = os.open(tmp_path / lock.LOCK_NAME, os.O_RDWR)
        try:
            with pytest.raises(InstallError):
                lock.adopt(tmp_path, fd, command="install")
        finally:
            os.close(fd)


def test_the_detached_child_keeps_the_lock_after_the_parent_lets_go(tmp_path):
    go, done = tmp_path / "go", tmp_path / "done"
    os.mkfifo(go)
    os.mkfifo(done)
    held = lock.acquire(tmp_path, command="install")
    with open(tmp_path / "install.log", "ab") as log:
        spawn_detached(
            [sys.executable, "-c", HOLD, str(held.descriptor),
             str(go), str(done)],
            cwd=tmp_path,
            log=log,
            inherit=[held.descriptor],
        )
    held.close()  # the parent is done; the child still holds the description
    with pytest.raises(InstallError, match="already running"):
        lock.acquire(tmp_path, command="install")
    with open(go, "w") as signal:  # let the child go; its own report says it has closed the descriptor
        signal.write("go")
    with open(done) as report:
        assert report.read() == "released"
    lock.acquire(tmp_path, command="install").close()
