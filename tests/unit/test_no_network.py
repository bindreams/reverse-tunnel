import socket

import pytest


def test_a_connection_attempt_fails_the_test():
    with pytest.raises(pytest.fail.Exception, match="must not touch the network"):
        socket.create_connection(("127.0.0.1", 9))


def test_a_connect_ex_attempt_fails_the_test():
    with socket.socket() as sock, pytest.raises(pytest.fail.Exception, match="must not touch the network"):
        sock.connect_ex(("127.0.0.1", 9))


@pytest.mark.parametrize("lookup", ["getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"])
def test_a_name_lookup_fails_the_test(lookup):
    with pytest.raises(pytest.fail.Exception, match="name lookup"):
        getattr(socket, lookup)("example.test")


def test_a_datagram_send_fails_the_test():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, pytest.raises(pytest.fail.Exception, match="send"):
        sock.sendto(b"x", ("127.0.0.1", 9))
