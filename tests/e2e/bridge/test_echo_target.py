"""The echo target the tunnel tests end in."""

import socket
import threading

from echo_target import EchoTarget


def test_it_echoes_what_each_of_several_connections_sends(echo: EchoTarget):
    with socket.create_connection((echo.host, echo.port)) as first, socket.create_connection((echo.host, echo.port)
                                                                                             ) as second:
        first.sendall(b"one")
        second.sendall(b"two")
        assert (first.recv(16), second.recv(16)) == (b"one", b"two")


def test_it_echoes_a_payload_larger_than_any_buffer(echo: EchoTarget):
    payload = bytes(range(256)) * 4096
    with socket.create_connection((echo.host, echo.port)) as client:
        sender = threading.Thread(target=client.sendall, args=(payload, ))
        sender.start()
        received = b""
        while len(received) < len(payload):
            received += client.recv(65536)
        sender.join()
    assert received == payload


def test_close_ends_an_open_connection_and_is_safe_to_repeat():
    target = EchoTarget()
    client = socket.create_connection((target.host, target.port))
    client.sendall(b"x")
    assert client.recv(1) == b"x"
    target.close()
    assert client.recv(1) == b""  # end-of-file: the target shut the connection down
    client.close()
    target.close()
