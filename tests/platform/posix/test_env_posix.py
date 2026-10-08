import os

import pytest

from ctl import env
from ctl.env import EnvError, read


def test_read_refuses_a_symlink_without_reading_its_target(tmp_path):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)
    with pytest.raises(EnvError) as raised:
        read(link)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)


def test_read_refuses_a_dangling_symlink(tmp_path):
    link = tmp_path / ".env"
    link.symlink_to(tmp_path / "absent")
    with pytest.raises(EnvError) as raised:
        read(link)
    assert "symlink" in str(raised.value)


def test_read_refuses_a_fifo_without_blocking(tmp_path):
    fifo = tmp_path / ".env"
    os.mkfifo(fifo)
    with pytest.raises(EnvError) as raised:
        read(fifo)
    assert "regular file" in str(raised.value)


def test_read_opens_with_nofollow():
    assert env.OPEN_FLAGS & os.O_RDONLY == os.O_RDONLY
    assert env.OPEN_FLAGS & os.O_NOFOLLOW


def test_without_nofollow_a_symlink_is_refused(tmp_path, monkeypatch):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)
    monkeypatch.setattr(env, "OPEN_FLAGS", os.O_RDONLY)
    with pytest.raises(EnvError) as raised:
        read(link)
    assert "symlink" in str(raised.value)
