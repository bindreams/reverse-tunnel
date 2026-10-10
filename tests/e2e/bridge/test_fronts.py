"""The bridge's data path under each front: a 4 MB payload through a real frpc, websocat and echo target."""

import os
import ssl
import socket
from pathlib import Path

import pytest
from bridge_support import GOOD_DOMAIN, GOOD_PASSWORD, make_project
from cryptography import x509
from cryptography.x509.oid import NameOID
from front_support import STAGING_HOST, Stack
from pki import ROOT_NAME
from tunnel_support import Hosts, round_trip, websocat_client

from ctl.doctor.frps_api import list_proxies

PAYLOAD = os.urandom(4 * 1024 * 1024)


def assert_echo(stack: Stack, hosts: Hosts, pinned: dict[str, Path], **start) -> None:
    host = hosts.start(stack, **start)
    name = f"{host.label}.{GOOD_DOMAIN}"
    echoed = round_trip(websocat_client(stack, pinned, name), PAYLOAD, ca_file=stack.ca_file if stack.secure else None)
    assert echoed.matches(PAYLOAD), f"sent {len(PAYLOAD)} bytes, got {echoed}"


# Three fronts =========================================================================================================


def test_websocket_echo_survives_the_bare_http_path(bare_stack, hosts, pinned):
    assert_echo(bare_stack, hosts, pinned)


def test_websocket_echo_survives_nginx(nginx_stack, hosts, pinned):
    assert_echo(nginx_stack, hosts, pinned)


def test_websocket_echo_survives_the_traefik_overlay(traefik_stack, hosts, pinned):
    assert_echo(traefik_stack, hosts, pinned)


@pytest.mark.parametrize("front", ["nginx", "traefik"])
def test_a_client_that_does_not_trust_the_test_ca_is_refused(front, request, hosts, pinned):
    """The control for the two tests above: TLS verification is real, so passing them proves the chain validates."""
    stack: Stack = request.getfixturevalue(f"{front}_stack")
    host = hosts.start(stack)
    command = websocat_client(stack, pinned, f"{host.label}.{GOOD_DOMAIN}")
    echoed = round_trip(command, PAYLOAD[:1024], ca_file=None)
    assert echoed.data == b"" and "certificate" in echoed.diagnostics.lower(), echoed


@pytest.mark.parametrize("front", ["nginx", "traefik"])
def test_wss_control_connection_registers_through_the_front(front, request, hosts, pinned):
    stack: Stack = request.getfixturevalue(f"{front}_stack")
    assert_echo(stack, hosts, pinned, through_front=True)


# What the front must preserve =========================================================================================


def assert_tunnel_answers_as_websocat(stack: Stack, label: str) -> None:
    response = stack.request(f"{label}.{GOOD_DOMAIN}")
    assert (response.status_code, response.headers.get("server")) == (400, "websocat"), response.headers


@pytest.mark.parametrize("front", ["bare", "nginx", "traefik"])
def test_a_working_tunnel_answers_a_plain_get_as_websocat_through_every_front(front, request, hosts):
    stack: Stack = request.getfixturevalue(f"{front}_stack")
    assert_tunnel_answers_as_websocat(stack, hosts.start(stack).label)


@pytest.mark.parametrize("front", ["bare", "nginx", "traefik"])
def test_an_unregistered_label_is_frps_own_404_through_every_front(front, request):
    stack: Stack = request.getfixturevalue(f"{front}_stack")
    response = stack.request(f"nobody.{GOOD_DOMAIN}")
    assert response.status_code == 404
    assert response.headers.get("server") != "websocat"


def test_a_front_that_rewrites_the_host_header_404s(host_rewriting_nginx_stack, hosts):
    stack = host_rewriting_nginx_stack
    host = hosts.start(stack)
    registered = list_proxies(stack.admin, GOOD_PASSWORD, user=host.label)
    assert [(proxy.name, proxy.phase) for proxy in registered.items] == [(f"{host.label}.ssh", "online")]
    response = stack.request(f"{host.label}.{GOOD_DOMAIN}")
    assert response.status_code == 404 and response.headers.get("server") != "websocat"


# Published ports ======================================================================================================

CONTROL, VHOST, ADMIN = "17801", "17802", "17803"


def test_published_ports_match_the_env_file(tmp_path):
    """Fixed ports, because the point is that Docker publishes exactly what `.env` says; a busy port fails `up`."""
    project = make_project(tmp_path, RT_CONTROL_PORT=CONTROL, RT_VHOST_PORT=VHOST, RT_ADMIN_PORT=ADMIN)
    try:
        up = project.compose("up", "--detach", "--wait", "--build")
        assert up.returncode == 0, up.stdout + up.stderr

        def published(port: int, protocol: str = "tcp") -> str:
            result = project.compose("port", "--protocol", protocol, "frps", str(port))
            assert result.returncode == 0, result.stderr
            return result.stdout.strip()

        assert published(8001, "tcp").endswith(f":{CONTROL}")
        assert published(8001, "udp").endswith(f":{CONTROL}")
        assert published(8080) == f"127.0.0.1:{VHOST}"
        assert published(7500) == f"127.0.0.1:{ADMIN}"
    finally:
        down = project.compose("down", "--volumes", "--remove-orphans", "--rmi", "local")
        assert down.returncode == 0, down.stderr


# The staging issuer ===================================================================================================


def served_issuer(stack: Stack, server_name: str) -> str:
    """The common name of the issuer of the certificate the front presents for `server_name`, unverified."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((stack.vhost.host, stack.vhost.port)) as sock:
        with context.wrap_socket(sock, server_hostname=server_name) as secured:
            der = secured.getpeercert(binary_form=True)
    assert der is not None
    return str(x509.load_der_x509_certificate(der).issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


@pytest.mark.parametrize("front", ["nginx", "traefik"])
def test_the_front_serves_the_test_ca_for_its_own_names(front, request):
    stack: Stack = request.getfixturevalue(f"{front}_stack")
    assert served_issuer(stack, f"alpha.{GOOD_DOMAIN}") == ROOT_NAME


def test_the_traefik_front_also_serves_a_certificate_whose_issuer_is_staging(traefik_stack):
    assert "STAGING" in served_issuer(traefik_stack, STAGING_HOST)
