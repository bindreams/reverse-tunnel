"""A TCP echo server: the far end of a tunnel in the tests, standing in for sshd.

The tunnel does not care what is on the other end, and an echo target makes the same assertion possible on every
platform. Run as a script it prints the address it listens on, serves until its stdin reaches end-of-file, and exits.
"""

import socket
import sys
import threading

CHUNK = 65536


class EchoTarget:
    """Echoes every byte of every connection back until the peer closes. `port=0` takes a free port."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen()
        self.host, self.port = self._listener.getsockname()[:2]
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._closing = False
        self._acceptor = threading.Thread(target=self._accept, name="EchoTarget", daemon=True)
        self._acceptor.start()

    def _accept(self) -> None:
        while True:
            connection, _ = self._listener.accept()
            with self._lock:
                if self._closing:
                    connection.close()
                    return
                self._connections.add(connection)
            threading.Thread(target=self._echo, args=(connection, ), daemon=True).start()

    def _echo(self, connection: socket.socket) -> None:
        try:
            while data := connection.recv(CHUNK):
                connection.sendall(data)
        except OSError:
            pass  # the peer vanished, or close() shut this connection down
        finally:
            with self._lock:
                self._connections.discard(connection)
            connection.close()

    def close(self) -> None:
        """Stop accepting and end every open connection. Safe to call twice."""
        with self._lock:
            if self._closing:
                return
            self._closing = True
            open_connections = list(self._connections)
        for connection in open_connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)  # wakes the thread blocked reading it
            except OSError:
                pass
        # `accept` does not return when its socket is closed from another thread; a connection to it does.
        with socket.create_connection((self.host, self.port)):
            pass
        self._acceptor.join()
        self._listener.close()

    def __enter__(self) -> "EchoTarget":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def main() -> int:
    with EchoTarget() as target:
        print(f"listening on {target.host}:{target.port}", flush=True)
        sys.stdin.read()  # the parent closing our stdin is the signal to stop
    return 0


if __name__ == "__main__":
    sys.exit(main())
