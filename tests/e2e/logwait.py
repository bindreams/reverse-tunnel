"""`LineTail`: the only way the end-to-end tests wait. They block on a line appearing in a stream they own.

Nothing here sleeps, polls, or takes a timeout. A line that never comes blocks until the stream ends, which wakes every
waiter, or until the CI job's own limit, which is the failure bound a human reads.
"""

import pathlib
import re
import subprocess
import threading
from collections.abc import Iterable, Mapping, Sequence
from typing import Self

# How many trailing lines an exception message shows. The exception itself carries all of them.
SHOWN_LINES = 20


class StreamEnded(Exception):
    """The stream ended, or its tail was closed, before the awaited line arrived."""

    def __init__(self, pattern: str | re.Pattern[str], after: int, lines: tuple[str, ...], error: str | None) -> None:
        self.pattern = pattern if isinstance(pattern, str) else pattern.pattern
        self.after = after
        self.lines = lines
        self.error = error
        shown = "\n".join(f"    {line}" for line in lines[-SHOWN_LINES:]) or "    (no lines)"
        reason = f" ({error})" if error else ""
        super().__init__(
            f"the stream ended{reason} before {self.pattern!r} appeared after line {after}; "
            f"last of its {len(lines)} line(s) since then:\n{shown}"
        )


class LineTail:
    """Everything a stream has written so far, readable from any thread.

    One reader thread appends each line to a list under a `threading.Condition`; `wait_for` scans what has arrived and
    then waits on the condition, so a line is seen the moment it is appended and not a poll interval later.
    """

    def __init__(self, stream: Iterable[str]) -> None:
        self._lines: list[str] = []
        self._cond = threading.Condition()
        self._ended = False
        self._error: str | None = None
        self._reader = threading.Thread(target=self._read, args=(stream, ), name="LineTail", daemon=True)
        self._reader.start()

    def _read(self, stream: Iterable[str]) -> None:
        try:
            for line in stream:
                with self._cond:
                    self._lines.append(line.rstrip("\r\n"))
                    self._cond.notify_all()
        except (OSError, ValueError) as exc:
            # A pipe closed from the other side: the stream is over, and the waiters should learn why.
            with self._cond:
                self._error = f"{type(exc).__name__}: {exc}"
        finally:
            self._end()

    def _end(self) -> None:
        with self._cond:
            self._ended = True
            self._cond.notify_all()

    def mark(self) -> int:
        """The position after the last line taken in. Take it before the action whose effect is awaited."""
        with self._cond:
            return len(self._lines)

    def wait_for(self, pattern: str | re.Pattern[str], *, after: int) -> str:
        """Block until a line at index `after` or later contains `pattern`, and return it.

        A string matches as a substring, so a log line's brackets need no escaping; a compiled pattern is searched.
        Raises `StreamEnded` if the stream ends first. A match that arrived before the end is still returned.
        """
        if after < 0:
            raise ValueError(f"after must be a mark from `mark()`, not {after}")
        matches = pattern.search if isinstance(pattern, re.Pattern) else (lambda line: pattern in line)
        with self._cond:
            scanned = after
            while True:
                for index in range(scanned, len(self._lines)):
                    if matches(self._lines[index]):
                        return self._lines[index]
                scanned = max(scanned, len(self._lines))
                if self._ended:
                    raise StreamEnded(pattern, after, tuple(self._lines[after:]), self._error)
                self._cond.wait()

    def close(self) -> None:
        """Wake every waiter with `StreamEnded`. The stream itself belongs to its owner and is left open."""
        self._end()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class _ProcessTail(LineTail):
    """A tail that owns the process it follows: closing it ends the process."""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        assert process.stdout is not None
        self._process = process
        super().__init__(process.stdout)

    def close(self) -> None:
        super().close()
        self._process.terminate()
        self._process.wait()
        # The process is gone, so the reader is about to see end-of-file; closing the pipe earlier would block on it.
        self._reader.join()
        assert self._process.stdout is not None
        self._process.stdout.close()


# Sources ==============================================================================================================


def tail_process(process: subprocess.Popen[str]) -> LineTail:
    """Follow `process`'s stdout, which the caller must have piped (with stderr merged into it, if that matters).

    Closing the tail terminates the process and waits for it to exit.
    """
    if process.stdout is None:
        raise ValueError("tail_process needs a process started with stdout=subprocess.PIPE")
    return _ProcessTail(process)


def tail_compose(
    project_dir: pathlib.Path,
    service: str,
    *,
    compose_args: Sequence[str] = (),
    env: Mapping[str, str] | None = None,
) -> LineTail:
    """Follow one service's log through `docker compose logs --follow`.

    `logs` replays the whole history before it follows, so a tail started after an event still sees it: there is no
    start-order race, and `wait_for(..., after=)` is what keeps a replayed line from being taken for a new one.
    `compose_args` goes before `logs` (`--project-name`, `-f`), for a project not named after `project_dir`.
    """
    process = subprocess.Popen(
        ["docker", "compose", *compose_args, "logs", "--follow", "--no-log-prefix", service],
        cwd=project_dir,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return tail_process(process)
