import socket

import pytest

from tests.offline import refuse_network


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    refuse_network(monkeypatch)


def test_a_sendmsg_fails_the_test():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, pytest.raises(pytest.fail.Exception, match="send"):
        sock.sendmsg([b"x"], [], 0, ("127.0.0.1", 9))
