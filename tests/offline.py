"""The network guard shared by tests/unit and tests/platform: any socket connection, send or name lookup fails the test."""

import socket

import pytest


def refuse_network(monkeypatch: pytest.MonkeyPatch) -> None:

    def refuse(self, address, *args, **kwargs):
        pytest.fail(f"unit tests must not touch the network (connect to {address!r})", pytrace=False)

    def refuse_lookup(host, *args, **kwargs):
        pytest.fail(f"unit tests must not touch the network (name lookup of {host!r})", pytrace=False)

    def refuse_send(self, *args, **kwargs):
        pytest.fail("unit tests must not touch the network (send to an address)", pytrace=False)

    # Code that imports the C module `_socket` directly is out of reach of these patches; nothing here does.
    for method in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, method, refuse)
    monkeypatch.setattr(socket.socket, "sendto", refuse_send)
    if hasattr(socket.socket, "sendmsg"):  # absent on Windows
        monkeypatch.setattr(socket.socket, "sendmsg", refuse_send)
    for function in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        monkeypatch.setattr(socket, function, refuse_lookup)
