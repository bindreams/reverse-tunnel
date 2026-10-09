"""The thin shells around the real machine: how they call out, and what they make of an answer or a refusal.

They open no connection here (unit tests are offline); Task 11 runs each against the real thing.
"""

import socket
import subprocess

import httpx
import pytest

from ctl.doctor import probes
from ctl.doctor.probes import Probes, TcpResult, TlsProbeError


def test_docker_is_run_in_the_deployment_with_a_failure_bound(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, "out", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = probes.run_docker(["compose", "ps"], cwd=tmp_path)
    assert result.stdout == "out"
    assert seen["argv"] == ["docker", "compose", "ps"] and seen["cwd"] == tmp_path
    assert seen["check"] is False and seen["stdin"] is subprocess.DEVNULL
    assert seen["timeout"] == probes.DOCKER_TIMEOUT


class Connection:

    def __init__(self, data: bytes = b"") -> None:
        self.data, self.received = data, 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def recv(self, size: int) -> bytes:
        self.received += 1
        return self.data


def connecting(monkeypatch, outcome):

    def create_connection(address, timeout=None):
        assert timeout == probes.TCP_TIMEOUT
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(socket, "create_connection", create_connection)


def test_an_accepted_connection_without_a_banner_read_does_not_read(monkeypatch):
    connection = Connection(b"SSH-2.0-x\r\n")
    connecting(monkeypatch, connection)
    assert probes.connect_tcp("127.0.0.1", 22, read_banner=False) == TcpResult(None, "")
    assert connection.received == 0


def test_the_banner_is_the_first_line_the_server_sends(monkeypatch):
    connecting(monkeypatch, Connection(b"SSH-2.0-OpenSSH_9.6\r\nmore"))
    assert probes.connect_tcp("127.0.0.1", 22, read_banner=True) == TcpResult(None, "SSH-2.0-OpenSSH_9.6")


def test_a_server_that_says_nothing_has_an_empty_banner(monkeypatch):
    connecting(monkeypatch, Connection(b""))
    assert probes.connect_tcp("127.0.0.1", 22, read_banner=True) == TcpResult(None, "")


def test_a_refused_connection_carries_the_systems_words(monkeypatch):
    connecting(monkeypatch, ConnectionRefusedError(61, "Connection refused"))
    assert probes.connect_tcp("127.0.0.1", 22, read_banner=False) == TcpResult("Connection refused", "")


def test_a_connection_that_times_out_says_for_how_long(monkeypatch):
    connecting(monkeypatch, TimeoutError())
    result = probes.connect_tcp("127.0.0.1", 22, read_banner=False)
    assert result.error and "no answer within" in result.error


def test_a_transport_given_to_the_probes_is_the_one_the_client_uses():
    transport = httpx.MockTransport(lambda request: httpx.Response(204))
    with Probes(transport=transport).http() as client:
        assert client.get("http://127.0.0.1:1/").status_code == 204


def test_the_real_client_follows_no_redirect_and_has_a_bound():
    with Probes().http() as client:
        assert client.follow_redirects is False
        assert client.timeout == probes.HTTP_TIMEOUT


def test_a_bundle_that_cannot_be_loaded_is_a_probe_error_before_any_request(tmp_path):
    with pytest.raises(TlsProbeError, match="absent.pem"):
        Probes().http(str(tmp_path / "absent.pem"))
