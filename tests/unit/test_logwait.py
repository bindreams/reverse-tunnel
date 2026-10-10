"""`LineTail`, the one synchronisation primitive of the end-to-end suite: block on a line, never on the clock."""

import io
import os
import re
import subprocess
import sys
import threading
import types
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO

import logwait
import pytest
from logwait import LineTail, StreamEnded, tail_compose, tail_process


@dataclass
class Feed:
    """A pipe: lines written to `writer` reach `tail`, and `finish` is the producer exiting."""

    tail: LineTail
    writer: IO[str]

    def write(self, *lines: str) -> None:
        self.writer.write("".join(f"{line}\n" for line in lines))
        self.writer.flush()

    def finish(self) -> None:
        self.writer.close()

    def seen(self, line: str) -> None:
        """Return once the reader has taken `line` in: the only way to know where the buffer ends."""
        self.tail.wait_for(line, after=0)


@pytest.fixture
def feed() -> Iterator[Feed]:
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, encoding="utf-8") as reader, os.fdopen(write_fd, "w", encoding="utf-8") as writer:
        tail = LineTail(reader)
        yield Feed(tail, writer)
        writer.close()
        tail.close()


# Matching =============================================================================================================


def test_wait_for_returns_a_matching_line_after_the_mark(feed):
    feed.write("old news")
    feed.seen("old news")
    mark = feed.tail.mark()
    feed.write("new proxy [alpha.ssh] type [http] success")
    assert feed.tail.wait_for("new proxy [alpha.ssh]", after=mark) == "new proxy [alpha.ssh] type [http] success"


def test_wait_for_ignores_a_matching_line_before_the_mark(feed):
    feed.write("[alpha.ssh] proxy closing")
    feed.seen("[alpha.ssh] proxy closing")
    mark = feed.tail.mark()
    feed.write("something else")
    feed.finish()
    with pytest.raises(StreamEnded) as ended:
        feed.tail.wait_for("[alpha.ssh] proxy closing", after=mark)
    assert ended.value.lines == ("something else", )


def test_wait_for_returns_a_line_that_was_already_buffered(feed):
    feed.write("frps started successfully")
    assert feed.tail.wait_for("started successfully", after=0) == "frps started successfully"


def test_wait_for_takes_the_pattern_literally_unless_given_a_compiled_one(feed):
    feed.write("proxy [alpha.ssh] up", "proxy [bravo.ssh] up")
    assert feed.tail.wait_for("[bravo.ssh]", after=0) == "proxy [bravo.ssh] up"
    assert feed.tail.wait_for(re.compile(r"\[b\w+\.ssh\]"), after=0) == "proxy [bravo.ssh] up"


def test_wait_for_blocks_until_the_line_is_written(feed):
    results = []
    waiter = threading.Thread(target=lambda: results.append(feed.tail.wait_for("go", after=0)))
    waiter.start()
    feed.write("go now")
    waiter.join()
    assert results == ["go now"]


def test_the_mark_counts_the_lines_taken_in(feed):
    assert feed.tail.mark() == 0
    feed.write("one", "two", "three")
    feed.seen("three")
    assert feed.tail.mark() == 3


def test_after_is_mandatory(feed):
    with pytest.raises(TypeError):
        feed.tail.wait_for("anything")  # type: ignore[call-arg]


# The stream ends ======================================================================================================


def test_wait_for_raises_stream_ended_when_the_stream_closes_without_a_match(feed):
    feed.write("a", "b", "c")
    feed.finish()
    with pytest.raises(StreamEnded) as ended:
        feed.tail.wait_for("never", after=0)
    assert ended.value.pattern == "never"
    assert ended.value.lines == ("a", "b", "c")
    assert "c" in str(ended.value) and "never" in str(ended.value)


def test_a_partial_last_line_without_a_newline_is_still_a_line(feed):
    feed.writer.write("no newline at the end")
    feed.finish()
    assert feed.tail.wait_for("no newline", after=0) == "no newline at the end"


def test_a_match_that_arrived_before_the_end_is_still_returned(feed):
    feed.write("frps started successfully")
    feed.finish()
    assert feed.tail.wait_for("started", after=0) == "frps started successfully"


@pytest.fixture
def entered_wait(monkeypatch) -> threading.Event:
    """Set once a waiter is inside `Condition.wait`, which is the state the wake-ups below must end."""
    entered = threading.Event()

    class Observed(threading.Condition):

        def wait(self):  # ty: ignore[invalid-method-override]
            entered.set()
            return super().wait()

    # Only logwait sees the observing condition; `threading.Event` builds its own from the real class.
    monkeypatch.setattr(logwait, "threading", types.SimpleNamespace(Condition=Observed, Thread=threading.Thread))
    return entered


def blocked_waiter(tail: LineTail) -> tuple[threading.Thread, list[BaseException]]:
    outcome: list[BaseException] = []

    def wait() -> None:
        try:
            tail.wait_for("never", after=0)
        except StreamEnded as ended:
            outcome.append(ended)

    thread = threading.Thread(target=wait)
    thread.start()
    return thread, outcome


def test_close_unblocks_a_waiting_thread(entered_wait):
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, encoding="utf-8") as reader, os.fdopen(write_fd, "w", encoding="utf-8") as writer:
        tail = LineTail(reader)
        thread, outcome = blocked_waiter(tail)
        entered_wait.wait()
        tail.close()
        thread.join()
        assert len(outcome) == 1
        writer.close()


def test_the_stream_ending_unblocks_every_waiting_thread(entered_wait):
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, encoding="utf-8") as reader, os.fdopen(write_fd, "w", encoding="utf-8") as writer:
        tail = LineTail(reader)
        first, first_outcome = blocked_waiter(tail)
        second, second_outcome = blocked_waiter(tail)
        entered_wait.wait()
        writer.close()
        first.join()
        second.join()
        assert len(first_outcome) == len(second_outcome) == 1
        tail.close()


def test_wait_for_after_close_raises_instead_of_blocking(feed):
    feed.write("kept")
    feed.seen("kept")
    feed.tail.close()
    assert feed.tail.wait_for("kept", after=0) == "kept"
    with pytest.raises(StreamEnded):
        feed.tail.wait_for("absent", after=0)


def test_a_stream_that_fails_to_read_ends_the_wait_and_says_why():

    class Broken:

        def __iter__(self):
            return self

        def __next__(self):
            raise OSError("pipe went away")

    tail = LineTail(Broken())
    with pytest.raises(StreamEnded, match="pipe went away"):
        tail.wait_for("anything", after=0)


# Processes ============================================================================================================

READY_THEN_WAIT_FOR_STDIN = "import sys; print('ready', flush=True); sys.stdin.read()"


def test_tail_process_follows_a_child_and_close_ends_it():
    child = subprocess.Popen(
        [sys.executable, "-c", READY_THEN_WAIT_FOR_STDIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    tail = tail_process(child)
    assert tail.wait_for("ready", after=0) == "ready"
    tail.close()
    assert child.returncode is not None
    assert child.stdin is not None
    child.stdin.close()


def test_tail_process_sees_what_the_child_writes_to_stderr():
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; print('boom', file=sys.stderr)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    tail = tail_process(child)
    assert tail.wait_for("boom", after=0) == "boom"
    tail.close()


def test_tail_process_requires_a_piped_stdout():
    child = subprocess.Popen([sys.executable, "-c", "pass"], text=True)
    try:
        with pytest.raises(ValueError, match="stdout"):
            tail_process(child)
    finally:
        child.wait()


def test_tail_compose_follows_the_whole_history_of_one_service(monkeypatch, tmp_path):
    seen = {}

    class FakeProcess:
        stdout = io.StringIO("frps started successfully\n")
        returncode = None

        def terminate(self):
            seen["terminated"] = True

        def wait(self):
            self.returncode = 0
            return 0

    def popen(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return FakeProcess()

    monkeypatch.setattr(logwait.subprocess, "Popen", popen)
    tail = tail_compose(tmp_path, "frps", compose_args=("--project-name", "p"), env={"A": "1"})
    assert tail.wait_for("started", after=0) == "frps started successfully"
    tail.close()
    assert seen["argv"] == ["docker", "compose", "--project-name", "p", "logs", "--follow", "--no-log-prefix", "frps"]
    assert (seen["cwd"], seen["env"]) == (tmp_path, {"A": "1"})
    assert seen["stdout"] is subprocess.PIPE and seen["stderr"] is subprocess.STDOUT and seen["text"] is True
    assert seen["terminated"] is True
