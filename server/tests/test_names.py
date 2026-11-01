import pytest

from ctl.names import alias_problem, allowed_names, owner_host, valid_domain, valid_label, valid_public_name


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


def test_allowed_names_refuses_reserved_double_hyphen():
    assert not allowed_names("ab--c", "t.test")("ab--c.t.test")
    assert not allowed_names("ab--c", "t.test")("s.ab--c.t.test")
    assert not allowed_names("mothership", "t.test")("xn--a.mothership.t.test")


@pytest.mark.parametrize(
    ("name", "host"),
    [
        ("mothership.t.test", "mothership"),
        ("jellyfin.mothership.t.test", "mothership"),
        ("a.b.mothership.t.test", None),
        ("t.test", None),
        ("mothership.t.test.", None),
        ("Mothership.t.test", None),
        ("ab--c.t.test", None),
        ("x.ab--c.t.test", None),
        ("xn--a.mothership.t.test", None),
        ("mothership.t.test.evil", None),
        ("", None),
        (".t.test", None),
        ("s..mothership.t.test", None),
    ],
)
def test_owner_host(name, host):
    assert owner_host(name, "t.test") == host


@pytest.mark.parametrize("domain", ["t.test", "tunnel.binarydreams.me", "a.b.c.d", "a" * 63 + ".b"])
def test_valid_domain(domain):
    assert valid_domain(domain)


@pytest.mark.parametrize(
    "domain",
    ["", "test", "t.test.", ".t.test", "T.test", "a_b.test", "ab--c.test", "a..b", "a" * 64 + ".b"],
)
def test_invalid_domain(domain):
    assert not valid_domain(domain)


def test_valid_domain_length_limit():
    assert valid_domain(".".join(["a" * 63] * 3 + ["a" * 61]))  # 253 characters
    assert not valid_domain(".".join(["a" * 63] * 3 + ["a" * 62]))


@pytest.mark.parametrize(
    "name",
    ["movies.binarydreams.me", "a.b", "notexample.com", "example.com.binarydreams.me", "myexample.org"],
)
def test_valid_public_name(name):
    assert valid_public_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "localhost",
        "movies.binarydreams.me.",
        "Movies.binarydreams.me",
        "mo_vies.binarydreams.me",
        "ab--c.binarydreams.me",
        "a" * 64 + ".binarydreams.me",
        "1.2.3.4",
        "binarydreams.123",
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


def test_public_name_length_limit():
    assert valid_public_name(".".join(["a" * 63] * 3 + ["a" * 61]))


def test_alias_problem():
    domain = "t.binarydreams.me"
    assert alias_problem("movies.binarydreams.me", "jellyfin.mothership.t.test", "t.test") is None
    assert "invalid public name" in alias_problem("movies.test", "mothership.t.test", "t.test")
    assert "under the tunnel domain" in alias_problem(f"movies.{domain}", f"mothership.{domain}", domain)
    assert "under the tunnel domain" in alias_problem(domain, f"mothership.{domain}", domain)
    assert "backend" in alias_problem("movies.binarydreams.me", "x.ab--c.t.test", "t.test")
