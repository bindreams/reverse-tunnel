"""Whether this process can be shown not to run over the tunnel."""

import pytest

from ctl.session import assess


@pytest.mark.parametrize(
    "value", [
        "192.0.2.10 51234 192.0.2.1 22",
        "198.51.100.7 40000 198.51.100.1 22",
        "2001:db8::10 51234 2001:db8::1 22",
        "10.1.2.3 1 10.1.2.4 22",
    ]
)
def test_a_non_loopback_client_is_provably_safe(value):
    assert assess({"SSH_CONNECTION": value}).safe is True


@pytest.mark.parametrize(
    "value", [
        "127.0.0.1 51234 127.0.0.1 22",
        "127.5.5.5 51234 127.0.0.1 22",
        "::1 51234 ::1 22",
        "::ffff:127.0.0.1 51234 ::1 22",
    ]
)
def test_a_loopback_client_is_not(value):
    verdict = assess({"SSH_CONNECTION": value})
    assert verdict.safe is False and "loopback" in verdict.reason and value.split()[0] in verdict.reason


@pytest.mark.parametrize(
    "value", ["", " ", "garbage", "192.0.2.10", "192.0.2.10 1 2", "not-an-address 1 2 3", "192.0.2.10%eth0 1 2 3"]
)
def test_a_value_that_names_no_client_address_is_not(value):
    verdict = assess({"SSH_CONNECTION": value})
    assert verdict.safe is False and "SSH_CONNECTION" in verdict.reason


def test_an_absent_variable_is_not_and_says_why():
    verdict = assess({})
    assert verdict.safe is False
    assert "SSH_CONNECTION is not set" in verdict.reason and "sudo" in verdict.reason and "tmux" in verdict.reason


@pytest.mark.parametrize("value", ["192.0.2.10 51234 192.0.2.10 22", "2001:db8::10 51234 2001:db8::10 22"])
def test_a_client_address_equal_to_the_server_address_is_not_provably_safe(value):
    """The connection was made from this machine to itself, which is how a relay on this machine looks."""
    verdict = assess({"SSH_CONNECTION": value})
    assert verdict.safe is False and "same" in verdict.reason and value.split()[0] in verdict.reason


def test_a_server_address_that_is_not_an_address_is_not_provably_safe():
    assert assess({"SSH_CONNECTION": "192.0.2.10 51234 nonsense 22"}).safe is False
