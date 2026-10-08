import socket

import pytest


def test_a_connection_attempt_fails_the_test():
    with pytest.raises(pytest.fail.Exception, match="must not touch the network"):
        socket.create_connection(("127.0.0.1", 9))


def test_a_connect_ex_attempt_fails_the_test():
    with socket.socket() as sock, pytest.raises(pytest.fail.Exception, match="must not touch the network"):
        sock.connect_ex(("127.0.0.1", 9))
