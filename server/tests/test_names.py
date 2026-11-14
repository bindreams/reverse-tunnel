import pytest

from ctl.names import allowed_names, owner_host, valid_domain, valid_label, valid_public_name


def test_label_rule():
    assert valid_label("a")
    assert valid_label("a-b")
    assert valid_label("0")
    assert valid_label("a" * 63)
    assert not valid_label("a" * 64)
    for bad in ["", "-a", "a-", "A", "a_b", "a.b", "a b", "é", "a\n"]:
        assert not valid_label(bad)


def test_label_rule_refuses_reserved_double_hyphen():
    assert valid_label("a--b")
    assert valid_label("a-b--c")
    assert not valid_label("ab--c")
    assert not valid_label("xn--abc")


def test_allowed_names():
    allowed = allowed_names("myhost", "tunnel.example.test")
    assert allowed("myhost.tunnel.example.test")
    assert allowed("jellyfin.myhost.tunnel.example.test")
    assert not allowed("a.b.myhost.tunnel.example.test")
    assert not allowed("jellyfin.other.tunnel.example.test")
    assert not allowed("myhost.tunnel.example.test.evil")


@pytest.mark.parametrize(
    "name",
    [
        "*.myhost.t.test",
        "myhost.t.test.",
        "Myhost.t.test",
        "",
        "s..myhost.t.test",
        "S.myhost.t.test",
        ".myhost.t.test",
    ],
)
def test_allowed_names_refuses_malformed(name):
    assert not allowed_names("myhost", "t.test")(name)


@pytest.mark.parametrize(
    ("name", "host"),
    [
        ("myhost.t.test", "myhost"),
        ("jellyfin.myhost.t.test", "myhost"),
        ("t.test", None),
        ("ab--c.t.test", None),
        ("x.ab--c.t.test", None),
        ("xn--a.myhost.t.test", None),
        (".t.test", None),
    ],
)
def test_owner_host(name, host):
    assert owner_host(name, "t.test") == host


@pytest.mark.parametrize("domain", ["t.test", "tunnel.example.com", "a.b.c.d", "a" * 63 + ".b"])
def test_valid_domain(domain):
    assert valid_domain(domain)


@pytest.mark.parametrize(
    "domain",
    ["", "test", "t.test.", ".t.test", "T.test", "a_b.test", "ab--c.test", "a..b", "a" * 64 + ".b"],
)
def test_invalid_domain(domain):
    assert not valid_domain(domain)


@pytest.mark.parametrize(
    "name",
    ["movies.yourdomain.org", "a.b", "notexample.com", "example.com.yourdomain.org", "myexample.org"],
)
def test_valid_public_name(name):
    assert valid_public_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "localhost",
        "movies.yourdomain.org.",
        "bad`name.yourdomain.org",
        "movies..yourdomain.org",
        "Movies.yourdomain.org",
        "mo_vies.yourdomain.org",
        "ab--c.yourdomain.org",
        "a" * 64 + ".yourdomain.org",
        "1.2.3.4",
        "yourdomain.123",
        ".".join(["a" * 63] * 3 + ["a" * 62]),
        "movies.invalid",
        "movies.test",
        "movies.example",
        "movies.localhost",
        "movies.local",
        "movies.onion",
        "movies.internal",
        "movies.arpa",
        "example.com",
        "example.net",
        "example.org",
        "movies.example.com",
        "a.b.example.net",
        "movies.example.org",
    ],
)
def test_invalid_public_name(name):
    assert not valid_public_name(name)
