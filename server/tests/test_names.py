import pytest

from ctl.names import allowed_names, valid_label


def test_label_rule():
    assert valid_label("a")
    assert valid_label("a-b")
    assert valid_label("0")
    assert valid_label("a" * 63)
    assert not valid_label("a" * 64)
    for bad in ["", "-a", "a-", "A", "a_b", "a.b", "a b", "é", "a\n"]:
        assert not valid_label(bad)


def test_allowed_names():
    allowed = allowed_names("mothership", "tunnel.example.test")
    assert allowed("mothership.tunnel.example.test")
    assert allowed("jellyfin.mothership.tunnel.example.test")
    assert not allowed("a.b.mothership.tunnel.example.test")
    assert not allowed("jellyfin.other.tunnel.example.test")
    assert not allowed("mothership.tunnel.example.test.evil")


@pytest.mark.parametrize(
    "name",
    [
        "*.mothership.t.test",
        "mothership.t.test.",
        "Mothership.t.test",
        "",
        "s..mothership.t.test",
        "S.mothership.t.test",
        ".mothership.t.test",
    ],
)
def test_allowed_names_refuses_malformed(name):
    assert not allowed_names("mothership", "t.test")(name)


@pytest.mark.parametrize("host", ["", "Bad", "-x", "a.b", "a" * 64])
def test_allowed_names_refuses_invalid_host(host):
    allowed = allowed_names(host, "t.test")
    assert not allowed(f"{host}.t.test")
    assert not allowed(f"s.{host}.t.test")
