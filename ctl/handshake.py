# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Learning that a detached process really started, without a clock.

What `spawn_detached` returns is the pid of whatever it launched, and under `systemd-run` that is systemd-run, which can
be refused (no authority, no bus) after the parent has long since moved on. So the child proves itself: the parent keeps
the read end of a pipe, the child holds the write end and writes one byte once it has taken over the install lock, and
the parent blocks reading. The read ends with the byte, or with end of file when every holder of the write end has gone
without writing, which is a child that failed or never ran. The parent closes its own copy first, so end of file really
does mean that nobody is left. Nothing is waited for on a timer: the child either writes or exits.
"""

import os
import sys

STARTED, REFUSED = b"1", b"0"


class Pipe:
    """The parent's side. `token` names the write end for the child: a descriptor on POSIX, a handle on Windows."""

    def __init__(self) -> None:
        self._read, self._write = os.pipe()
        self.refusal: str | None = None  # why the child declined to go on, when it said
        self._closed_write = False
        self._closed_read = False
        if sys.platform == "win32":
            import msvcrt

            self.token = msvcrt.get_osfhandle(self._write)
        else:
            self.token = self._write

    def wait(self) -> bool:
        """Block until the child says it started (True), declines (False, `refusal` set), or no holder of the write end is
        left without having said anything (False)."""
        self._close_write()
        try:
            first = os.read(self._read, 1)
            if first == REFUSED:
                chunks = []
                while chunk := os.read(self._read, 4096):  # the child closes its end right after the reason
                    chunks.append(chunk)
                self.refusal = b"".join(chunks).decode(errors="replace")
            return first == STARTED
        finally:
            self.close()

    def _close_write(self) -> None:
        if not self._closed_write:
            self._closed_write = True
            os.close(self._write)

    def close(self) -> None:
        self._close_write()
        if not self._closed_read:
            self._closed_read = True
            os.close(self._read)


def signal(token: int, refusal: str | None = None) -> None:
    """The child's side: say that it started, or why it will not go on, and let go of the pipe."""
    descriptor = token
    if sys.platform == "win32":
        import msvcrt

        descriptor = msvcrt.open_osfhandle(token, os.O_WRONLY)
    try:
        data = STARTED if refusal is None else REFUSED + refusal.encode()
        view = memoryview(data)
        while view:
            view = view[os.write(descriptor, view):]
    finally:
        os.close(descriptor)
