import io
import os
import stat

import pytest

from ctl.atomic import replace_file
from ctl.binaries import write_atomically
from ctl.errors import BinariesError


def test_a_symlinked_directory_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "bin").symlink_to(real)
    with pytest.raises(BinariesError, match="link"):
        replace_file(tmp_path / "bin", "tool", io.BytesIO(b"x"), 0o755)
    assert list(real.iterdir()) == []


def test_a_symlinked_destination_file_is_refused_and_never_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    victim.chmod(0o600)
    (tmp_path / "tool").symlink_to(victim)
    with pytest.raises(BinariesError, match="link"):
        replace_file(tmp_path, "tool", io.BytesIO(b"x"), 0o755)
    assert victim.read_bytes() == b"precious"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600


def test_write_atomically_refuses_a_symlink_and_never_takes_a_mode_from_its_target(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"precious")
    target.chmod(0o666)
    (tmp_path / "lock").symlink_to(target)
    with pytest.raises(BinariesError, match="link"):
        write_atomically(tmp_path / "lock", "new")
    assert target.read_bytes() == b"precious"
    assert os.path.islink(tmp_path / "lock")


def test_the_mode_does_not_depend_on_the_umask(tmp_path):
    old = os.umask(0o077)
    try:
        replace_file(tmp_path, "tool", io.BytesIO(b"x"), 0o755)
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "tool").stat().st_mode) == 0o755


def test_a_symlinked_digest_record_is_refused(tmp_path):
    from ctl.download import read_digests

    real = tmp_path / "elsewhere.json"
    real.write_text("{}")
    (tmp_path / ".digests.json").symlink_to(real)
    with pytest.raises(BinariesError, match="link"):
        read_digests(tmp_path)


def test_an_interrupt_right_after_the_temporary_is_created_leaves_nothing_behind(tmp_path, monkeypatch):
    real = os.open

    def interrupted(path, flags, *args, **kwargs):
        fd = real(path, flags, *args, **kwargs)
        if flags & os.O_EXCL:
            os.close(fd)
            raise KeyboardInterrupt
        return fd

    monkeypatch.setattr(os, "open", interrupted)
    with pytest.raises(KeyboardInterrupt):
        replace_file(tmp_path, "tool", io.BytesIO(b"data"), 0o755)
    assert list(tmp_path.iterdir()) == []
