"""Ctrl-C is held while a file is created, written, renamed or cleaned up, and delivered afterwards."""

import io
import signal
import threading

import pytest
from archive_support import write_archive

from ctl.archive import ArchiveFormat, extract_member
from ctl.atomic import deferred_interrupts, replace_file


def interrupt() -> None:
    signal.raise_signal(signal.SIGINT)


def test_an_interrupt_inside_the_block_is_raised_after_the_block_completes():
    finished = []
    with pytest.raises(KeyboardInterrupt):
        with deferred_interrupts():
            interrupt()
            finished.append(True)
    assert finished == [True]


def test_without_an_interrupt_nothing_is_raised_and_the_handler_is_restored():
    before = signal.getsignal(signal.SIGINT)
    with deferred_interrupts():
        assert signal.getsignal(signal.SIGINT) is not before
    assert signal.getsignal(signal.SIGINT) is before


def test_the_handler_is_restored_when_the_block_fails_and_the_interrupt_still_arrives():
    before = signal.getsignal(signal.SIGINT)
    with pytest.raises(KeyboardInterrupt):
        with deferred_interrupts():
            interrupt()
            raise RuntimeError("the block failed")
    assert signal.getsignal(signal.SIGINT) is before


def test_an_ignored_interrupt_stays_ignored():
    before = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        with deferred_interrupts():
            assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
            interrupt()
        assert signal.getsignal(signal.SIGINT) == signal.SIG_IGN
    finally:
        signal.signal(signal.SIGINT, before)


def test_off_the_main_thread_the_block_just_runs():
    ran = []

    def work():
        with deferred_interrupts():
            ran.append(signal.getsignal(signal.SIGINT))

    thread = threading.Thread(target=work)
    thread.start()
    thread.join()
    assert ran == [signal.getsignal(signal.SIGINT)]


class InterruptingSource(io.RawIOBase):
    """Delivers Ctrl-C the first time it is read, as the user would mid-write, and then ends."""

    sent = False

    def readable(self):
        return True

    def readinto(self, buffer):
        if not InterruptingSource.sent:
            InterruptingSource.sent = True
            interrupt()
        return 0


def test_replace_file_finishes_and_leaves_no_temporary_before_the_interrupt_is_raised(tmp_path):
    InterruptingSource.sent = False
    with pytest.raises(KeyboardInterrupt):
        replace_file(tmp_path, "tool", io.BufferedReader(InterruptingSource()), 0o755)
    assert InterruptingSource.sent
    assert [p.name for p in tmp_path.iterdir()] == ["tool"]
    assert (tmp_path / "tool").read_bytes() == b""


def test_extract_member_removes_its_target_when_an_interrupt_arrives_mid_copy(tmp_path, monkeypatch):
    from ctl import archive

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])
    real = archive._copy_hashing
    copied = []

    def interrupted(stream, out):
        interrupt()
        digest = real(stream, out)
        copied.append(digest)  # reached only if the interrupt was held back
        return digest

    monkeypatch.setattr(archive, "_copy_hashing", interrupted)
    with pytest.raises(KeyboardInterrupt):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", scratch / "tool")
    assert len(copied) == 1
    assert list(scratch.iterdir()) == []


def test_an_interrupt_never_removes_a_target_that_already_existed(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    (scratch / "tool").write_bytes(b"old")
    path = write_archive(tmp_path / "a.tar.xz", ArchiveFormat.TAR_XZ, [("top/tool", b"abc")])
    with pytest.raises(FileExistsError):
        extract_member(path, ArchiveFormat.TAR_XZ, "top/tool", scratch / "tool")
    assert (scratch / "tool").read_bytes() == b"old"
