import json
import re
import subprocess
from pathlib import Path

import pytest

from ctl import config
from ctl.config import (
    EXAMPLE_ADMIN_PASSWORD,
    EXAMPLE_LABEL,
    EXAMPLE_TOKEN,
    OPTIONAL,
    REQUIRED,
    Config,
    ConfigError,
    Role,
)
from ctl.env import EnvError, read, referenced_in_file, tracked_config_files
from scanner_support import GIT_ENV, REPO_ROOT

EXAMPLE_ENV = REPO_ROOT / "example.env"
GOOD_TOKEN = "0123456789abcdef" * 4
GOOD_PASSWORD = "correct-horse-battery_staple"
GOOD_LABEL = "alpha"

# Keys the ctl process consumes itself, which no tracked template references. Permanent.
CTL_ONLY = frozenset({"ROLE", "RT_TOKEN", "RT_SCHEME", "RT_PUBLIC_PORT", "RT_PUBLIC_HOST"})

# TEMPORARY: keys whose referencing template has not landed yet. Task 8 (frpc.toml, goetia.yaml) removes its keys
# from this set as it adds the templates, then deletes the set.
PENDING_TEMPLATE_KEYS = frozenset({
    "RT_LABEL",
    "RT_SERVER_ADDR",
    "RT_SERVER_PORT",
    "RT_PROTOCOL",
    "RT_SSH_PORT",
    "RT_WS_PORT",
    "RT_SERVICE_USER",
})

# Helpers ==============================================================================================================


def example_values() -> dict[str, str]:
    return read(EXAMPLE_ENV)


def valid_values(role: Role, **overrides: str | None) -> dict[str, str]:
    """The shipped example with the three placeholder values replaced; `None` deletes a key."""
    values = example_values()
    values.update(ROLE=role.value, RT_TOKEN=GOOD_TOKEN, RT_ADMIN_PASSWORD=GOOD_PASSWORD, RT_LABEL=GOOD_LABEL)
    for key, value in overrides.items():
        if value is None:
            del values[key]
        else:
            values[key] = value
    return values


def write_env(root: Path, values: dict[str, str]) -> Path:
    path = root / ".env"
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    return path


def load(root: Path, role: Role, **overrides: str | None) -> Config:
    write_env(root, valid_values(role, **overrides))
    return Config.load(root)


def refused(root: Path, role: Role, **overrides: str | None) -> str:
    with pytest.raises(ConfigError) as raised:
        load(root, role, **overrides)
    return str(raised.value)


ROLES = list(Role)
REQUIRED_PAIRS = [pytest.param(role, key, id=f"{role.value}-{key}") for role in ROLES for key in sorted(REQUIRED[role])]

# The example is loadable ==============================================================================================


@pytest.mark.parametrize("role", ROLES)
def test_example_env_with_placeholders_replaced_loads_for_every_role(tmp_path, role):
    assert load(tmp_path, role).role is role


def test_client_loads_from_the_shipped_example_untouched(tmp_path):
    write_env(tmp_path, example_values() | {"ROLE": "client"})
    assert Config.load(tmp_path).role is Role.CLIENT


def test_example_env_itself_obeys_the_dialect():
    assert read(EXAMPLE_ENV)


def test_example_env_ships_every_declared_key():
    declared = {key for role in ROLES for key in REQUIRED[role] | OPTIONAL[role]}
    assert declared <= example_values().keys()


def test_example_env_gives_every_required_key_a_value():
    values = example_values()
    assert all(values[key] for role in ROLES for key in REQUIRED[role])


def test_example_env_has_no_commented_out_assignment():
    commented = [line for line in EXAMPLE_ENV.read_text().splitlines() if re.match(r"#\s*[A-Z][A-Z0-9_]*=", line)]
    assert commented == []


def test_example_env_ships_the_example_token_and_password_and_label():
    values = example_values()
    assert values["RT_TOKEN"] == EXAMPLE_TOKEN
    assert values["RT_ADMIN_PASSWORD"] == EXAMPLE_ADMIN_PASSWORD
    assert values["RT_LABEL"] == EXAMPLE_LABEL


def test_the_example_token_is_deliberately_well_formed():
    assert re.fullmatch(r"[0-9a-f]{64}", EXAMPLE_TOKEN)
    assert re.fullmatch(r"[A-Za-z0-9_-]{16,}", EXAMPLE_ADMIN_PASSWORD)


# The required keys ====================================================================================================


def test_required_keys_are_exactly_the_documented_sets():
    assert REQUIRED == {
        Role.BRIDGE: frozenset({
            "ROLE", "RT_DOMAIN", "RT_TOKEN", "RT_ADMIN_PASSWORD", "RT_CONTROL_PORT", "RT_VHOST_BIND", "RT_VHOST_PORT",
            "RT_ADMIN_PORT"
        }),
        Role.HOST: frozenset({
            "ROLE", "RT_LABEL", "RT_DOMAIN", "RT_SCHEME", "RT_PUBLIC_PORT", "RT_SERVER_ADDR", "RT_SERVER_PORT",
            "RT_PROTOCOL", "RT_TOKEN", "RT_SSH_PORT", "RT_WS_PORT", "RT_SERVICE_USER"
        }),
        Role.CLIENT: frozenset({"ROLE", "RT_DOMAIN", "RT_SCHEME", "RT_PUBLIC_PORT"}),
    }
    assert OPTIONAL == {
        Role.BRIDGE: frozenset({"RT_CONTROL_HOST", "RT_PROXY_NETWORK", "RT_PUBLIC_HOST"}),
        Role.HOST: frozenset(),
        Role.CLIENT: frozenset(),
    }


def test_missing_env_file_is_an_error_naming_the_path(tmp_path):
    with pytest.raises(ConfigError) as raised:
        Config.load(tmp_path)
    assert str(tmp_path / ".env") in str(raised.value)


def test_a_syntax_error_in_env_is_a_config_error_naming_file_and_line(tmp_path):
    (tmp_path / ".env").write_text("ROLE=host\nbroken\n")
    with pytest.raises(ConfigError) as raised:
        Config.load(tmp_path)
    assert f"{tmp_path / '.env'}:2" in str(raised.value)


@pytest.mark.parametrize("role", [None, "", "Host", "HOST", "hosts", "server"])
def test_unknown_role_is_rejected_listing_the_three_valid_roles(tmp_path, role):
    message = refused(tmp_path, Role.HOST, ROLE=role)
    assert "ROLE" in message
    for valid in ("bridge", "host", "client"):
        assert valid in message


@pytest.mark.parametrize("role", ROLES)
def test_each_role_requires_its_own_variables(tmp_path, role):
    for key in sorted(REQUIRED[role] - {"ROLE"}):
        assert key in refused(tmp_path, role, **{key: None})


@pytest.mark.parametrize("role", ROLES)
def test_every_missing_key_is_named_in_sorted_order(tmp_path, role):
    keys = sorted(REQUIRED[role] - {"ROLE"})
    message = refused(tmp_path, role, **{key: None for key in keys[1:]})
    assert keys[1] in message
    assert message.index(keys[1]) < message.index(keys[2])


@pytest.mark.parametrize(("role", "key"), REQUIRED_PAIRS)
def test_a_present_but_empty_required_key_is_rejected(tmp_path, role, key):
    assert key in refused(tmp_path, role, **{key: ""})


@pytest.mark.parametrize("role", ROLES)
def test_a_missing_and_an_empty_key_are_distinguished(tmp_path, role):
    key = "RT_DOMAIN"
    assert refused(tmp_path, role, **{key: None}) != refused(tmp_path, role, **{key: ""})


def test_client_role_does_not_require_rt_label(tmp_path):
    assert "RT_LABEL" not in REQUIRED[Role.CLIENT]
    load(tmp_path, Role.CLIENT, RT_LABEL=None)


def test_unrelated_extra_keys_are_kept_and_tolerated(tmp_path):
    cfg = load(tmp_path, Role.CLIENT, RT_UNKNOWN="x")
    assert cfg.values["RT_UNKNOWN"] == "x"


def test_a_key_of_another_role_is_not_validated(tmp_path):
    load(tmp_path, Role.CLIENT, RT_TOKEN="garbage", RT_LABEL="Bad.Label", RT_SSH_PORT="0")


def test_rt_service_user_is_required_on_posix(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "service_user_required", lambda: True)
    assert "RT_SERVICE_USER" in refused(tmp_path, Role.HOST, RT_SERVICE_USER=None)
    assert "RT_SERVICE_USER" in refused(tmp_path, Role.HOST, RT_SERVICE_USER="")


def test_rt_service_user_is_not_required_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "service_user_required", lambda: False)
    load(tmp_path, Role.HOST, RT_SERVICE_USER=None)
    load(tmp_path, Role.HOST, RT_SERVICE_USER="")


def test_service_user_requirement_follows_the_platform(monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    assert config.service_user_required() is False
    monkeypatch.setattr("sys.platform", "linux")
    assert config.service_user_required() is True
    monkeypatch.setattr("sys.platform", "darwin")
    assert config.service_user_required() is True


# Format rules =========================================================================================================

BAD_HOSTS = [
    "https://x.example.com",
    "ws://x.example.com",
    "x.example.com:80",
    "x.example.com:",
    "x.example.com.",
    "x.example.com/",
    "x.example.com/path",
    "user" + "@" + "x.example.com",  # built apart so the artifact scanner does not read it as an e-mail
    "*.example.com",
    "a..example.com",
    ".example.com",
    "-a.example.com",
    "a-.example.com",
    "a_b.example.com",
    "[::1]:80",
    "[::1]",
    "2001:db8::1:80:x",
    "::1::",
    "fe80::1%eth0",
    "a" * 64 + ".example.com",
    ".".join(["a" * 63] * 4 + ["b"]),
    # Not dotted quads, yet inet_aton (and so getaddrinfo) resolves each to an address.
    "10.0.0.256",
    "999.1.1.1",
    "1.2.3",
    "127.1",
    "010.0.0.1",
    "0x7f.1",
    "0x7f.0x0.0x0.0x1",
    "0X7F.0.0.1",
    "1",
    "2130706433",
    "1.2.3.4.5",
    "127.0.0.1.",
    "example.0x1",
    "example.0x",
    "example.0xg",
    "example.0XG",
    "example.0xfoo",
    "example.123",
]
GOOD_HOSTS = [
    "example.com",
    "a-b.example.com",
    "A.Example.COM",
    "localhost",
    "10.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "2001:db8::1",
    "::1",
    "::ffff:10.0.0.1",
    "xn--bcher-kva.de",
    "a" * 63 + ".example.com",
    "1.example.com",
    "0x.example.com",
    "example.c0m",
    "10.0.0.1.example.com",
]
HOST_KEYS = [
    pytest.param(Role.BRIDGE, "RT_DOMAIN"),
    pytest.param(Role.HOST, "RT_DOMAIN"),
    pytest.param(Role.CLIENT, "RT_DOMAIN"),
    pytest.param(Role.HOST, "RT_SERVER_ADDR"),
    pytest.param(Role.BRIDGE, "RT_CONTROL_HOST"),
    pytest.param(Role.BRIDGE, "RT_PUBLIC_HOST"),
]


@pytest.mark.parametrize(("role", "key"), HOST_KEYS)
def test_every_hostname_key_is_validated(tmp_path, role, key):
    assert key in refused(tmp_path, role, **{key: "https://x.example.com"})
    assert load(tmp_path, role, **{key: "example.com"}).values[key] == "example.com"


@pytest.mark.parametrize("bad", BAD_HOSTS)
def test_a_malformed_hostname_is_rejected(tmp_path, bad):
    assert "RT_SERVER_ADDR" in refused(tmp_path, Role.HOST, RT_SERVER_ADDR=bad)


@pytest.mark.parametrize("good", GOOD_HOSTS)
def test_a_dns_name_or_strict_ip_literal_is_accepted(tmp_path, good):
    assert load(tmp_path, Role.HOST, RT_SERVER_ADDR=good).values["RT_SERVER_ADDR"] == good


OPTIONAL_PAIRS = [pytest.param(key, id=key) for key in ("RT_CONTROL_HOST", "RT_PROXY_NETWORK", "RT_PUBLIC_HOST")]


@pytest.mark.parametrize("key", OPTIONAL_PAIRS)
def test_an_optional_bridge_key_may_be_absent_or_empty(tmp_path, key):
    load(tmp_path, Role.BRIDGE, **{key: None})
    assert load(tmp_path, Role.BRIDGE, **{key: ""}).values[key] == ""


def test_an_optional_key_that_is_set_is_validated(tmp_path):
    assert "RT_CONTROL_HOST" in refused(tmp_path, Role.BRIDGE, RT_CONTROL_HOST="https://x.example.com")


PORT_KEYS = [
    pytest.param(Role.BRIDGE, "RT_CONTROL_PORT"),
    pytest.param(Role.BRIDGE, "RT_VHOST_PORT"),
    pytest.param(Role.BRIDGE, "RT_ADMIN_PORT"),
    pytest.param(Role.HOST, "RT_PUBLIC_PORT"),
    pytest.param(Role.HOST, "RT_SERVER_PORT"),
    pytest.param(Role.HOST, "RT_SSH_PORT"),
    pytest.param(Role.HOST, "RT_WS_PORT"),
    pytest.param(Role.CLIENT, "RT_PUBLIC_PORT"),
]

BAD_PORTS = ["0", "65536", "99999", "-1", "+80", "08080", "00", "80a", "1e3", "0x50", "8.0", "100000"]


@pytest.mark.parametrize(("role", "key"), PORT_KEYS)
def test_every_port_key_is_validated(tmp_path, role, key):
    assert key in refused(tmp_path, role, **{key: "0"})
    assert load(tmp_path, role, **{key: "65535"}).values[key] == "65535"


@pytest.mark.parametrize("bad", BAD_PORTS)
def test_a_port_must_be_an_integer_in_range(tmp_path, bad):
    assert "RT_CONTROL_PORT" in refused(tmp_path, Role.BRIDGE, RT_CONTROL_PORT=bad)


@pytest.mark.parametrize("good", ["1", "80", "443", "65535"])
def test_a_port_accepts_the_range_ends(tmp_path, good):
    assert load(tmp_path, Role.BRIDGE, RT_CONTROL_PORT=good).values["RT_CONTROL_PORT"] == good


@pytest.mark.parametrize("bad", ["Wss", "http", "udp", "ws", "QUIC"])
def test_rt_protocol_is_one_of_four(tmp_path, bad):
    assert "RT_PROTOCOL" in refused(tmp_path, Role.HOST, RT_PROTOCOL=bad)


@pytest.mark.parametrize("good", ["quic", "tcp", "websocket", "wss"])
def test_rt_protocol_accepts_each_of_the_four(tmp_path, good):
    assert load(tmp_path, Role.HOST, RT_PROTOCOL=good).values["RT_PROTOCOL"] == good


@pytest.mark.parametrize("role", [Role.HOST, Role.CLIENT])
@pytest.mark.parametrize("bad", ["http", "https", "WS", "tcp"])
def test_rt_scheme_is_ws_or_wss(tmp_path, role, bad):
    assert "RT_SCHEME" in refused(tmp_path, role, RT_SCHEME=bad)


@pytest.mark.parametrize("good", ["ws", "wss"])
def test_rt_scheme_accepts_ws_and_wss(tmp_path, good):
    assert load(tmp_path, Role.HOST, RT_SCHEME=good).values["RT_SCHEME"] == good


@pytest.mark.parametrize("bad", ["a.b", "a*", "-a", "a-", "A", "a_b", "a/b", "."])
def test_invalid_label_is_rejected(tmp_path, bad):
    assert "RT_LABEL" in refused(tmp_path, Role.HOST, RT_LABEL=bad)


@pytest.mark.parametrize("good", ["a", "a1", "a-b", "0", "alpha-2-x"])
def test_valid_labels_are_accepted(tmp_path, good):
    assert load(tmp_path, Role.HOST, RT_LABEL=good).values["RT_LABEL"] == good


# Secrets and placeholders =============================================================================================


@pytest.mark.parametrize("role", [Role.BRIDGE, Role.HOST])
@pytest.mark.parametrize("bad", ["0" * 63, "0" * 65, "g" * 64, "A" * 64, "0123456789ABCDEF" * 4, "0" * 63 + "-"])
def test_token_must_be_64_lowercase_hex(tmp_path, role, bad):
    message = refused(tmp_path, role, RT_TOKEN=bad)
    assert "RT_TOKEN" in message
    assert bad not in message


@pytest.mark.parametrize("role", [Role.BRIDGE, Role.HOST])
def test_example_token_is_rejected_despite_being_well_formed(tmp_path, role):
    message = refused(tmp_path, role, RT_TOKEN=EXAMPLE_TOKEN)
    assert "RT_TOKEN" in message
    assert "example" in message.lower()


@pytest.mark.parametrize("bad", ["short", "a" * 15, "has space!" * 3, "pw/with/slash/xxxxxxxx", "p@ssword-long-enough"])
def test_admin_password_must_be_16_url_safe_characters(tmp_path, bad):
    message = refused(tmp_path, Role.BRIDGE, RT_ADMIN_PASSWORD=bad)
    assert "RT_ADMIN_PASSWORD" in message
    assert bad not in message


def test_example_admin_password_is_rejected(tmp_path):
    message = refused(tmp_path, Role.BRIDGE, RT_ADMIN_PASSWORD=EXAMPLE_ADMIN_PASSWORD)
    assert "RT_ADMIN_PASSWORD" in message
    assert "example" in message.lower()


def test_example_label_is_rejected_despite_being_well_formed(tmp_path):
    message = refused(tmp_path, Role.HOST, RT_LABEL=EXAMPLE_LABEL)
    assert "RT_LABEL" in message
    assert "example" in message.lower()


def test_the_shipped_example_is_refused_for_a_host_and_a_bridge(tmp_path):
    for role in (Role.HOST, Role.BRIDGE):
        write_env(tmp_path, example_values() | {"ROLE": role.value})
        with pytest.raises(ConfigError):
            Config.load(tmp_path)


def test_a_rejected_secret_never_appears_in_the_message(tmp_path):
    secret = "Z" * 64
    assert secret not in refused(tmp_path, Role.HOST, RT_TOKEN=secret)


# The loader ===========================================================================================================


def test_require_returns_the_value(tmp_path):
    assert load(tmp_path, Role.HOST).require("RT_LABEL") == GOOD_LABEL


@pytest.mark.parametrize("name", ["RT_NOPE", "RT_CONTROL_HOST"])
def test_require_of_an_absent_or_empty_key_is_an_error_naming_it(tmp_path, name):
    cfg = load(tmp_path, Role.HOST, **{"RT_CONTROL_HOST": ""})
    with pytest.raises(ConfigError) as raised:
        cfg.require(name)
    assert name in str(raised.value)


def test_config_carries_the_root_and_cannot_be_mutated(tmp_path):
    cfg = load(tmp_path, Role.HOST)
    assert cfg.root == tmp_path
    with pytest.raises(AttributeError):
        cfg.role = Role.BRIDGE  # ty: ignore[invalid-assignment]
    with pytest.raises(TypeError):
        cfg.values["RT_LABEL"] = "x"  # ty: ignore[invalid-assignment]


# The example.env gates ================================================================================================


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


def referenced_by_tracked_files(root: Path, *, minimum=None) -> set[str]:
    files = tracked_config_files(root) if minimum is None else tracked_config_files(root, minimum=minimum)
    assert files
    return set().union(*(referenced_in_file(f) for f in files))


def undeclared(root: Path, declared: set[str], **kwargs) -> set[str]:
    return referenced_by_tracked_files(root, **kwargs) - declared


def unreferenced(root: Path, declared: set[str], *, ctl_only, pending, **kwargs) -> set[str]:
    return declared - referenced_by_tracked_files(root, **kwargs) - set(ctl_only) - set(pending)


def test_example_env_declares_every_variable_every_tracked_file_references():
    assert undeclared(REPO_ROOT, set(example_values())) == set()


def test_the_declared_gate_catches_an_undeclared_reference(repo):
    (repo / "frps.toml").write_text('subDomainHost = "{{ .Envs.RT_NEW }}"\nport = ${RT_OLD}\n')
    git(repo, "add", "frps.toml")
    assert undeclared(repo, {"RT_OLD"}, minimum=()) == {"RT_NEW"}


def test_the_declared_gate_does_not_see_an_untracked_file(repo):
    (repo / "tracked.toml").write_text("x = 1\n")
    git(repo, "add", "tracked.toml")
    (repo / "untracked.toml").write_text("x = ${RT_NEW}\n")
    assert undeclared(repo, set(), minimum=()) == set()


def test_example_env_declares_nothing_unreferenced():
    keys = set(example_values())
    assert unreferenced(REPO_ROOT, keys, ctl_only=CTL_ONLY, pending=PENDING_TEMPLATE_KEYS) == set()


def test_the_unreferenced_gate_catches_a_stale_key(repo):
    (repo / "frps.toml").write_text("x = ${RT_USED}\n")
    git(repo, "add", "frps.toml")
    declared = {"RT_USED", "RT_STALE", "RT_CTL", "RT_LATER"}
    stale = unreferenced(repo, declared, ctl_only={"RT_CTL"}, pending={"RT_LATER"}, minimum=())
    assert stale == {"RT_STALE"}


def test_the_allowlists_name_only_declared_keys():
    keys = set(example_values())
    assert CTL_ONLY <= keys
    assert PENDING_TEMPLATE_KEYS <= keys


def test_a_key_that_a_template_now_references_must_leave_both_allowlists():
    referenced = referenced_by_tracked_files(REPO_ROOT)
    assert referenced & PENDING_TEMPLATE_KEYS == set()
    assert referenced & CTL_ONLY == set()


def test_the_two_allowlists_do_not_overlap():
    assert CTL_ONLY & PENDING_TEMPLATE_KEYS == set()


# Value rules shared with the bridge entrypoint ========================================================================

VALUE_RULES = json.loads((REPO_ROOT / "tests" / "value_rules.corpus").read_text(encoding="utf-8"))


@pytest.mark.parametrize("value", VALUE_RULES["domain"]["accepted"])
def test_rt_domain_accepts_the_corpus(tmp_path, value):
    assert config.is_dns_name(value)
    assert load(tmp_path, Role.BRIDGE, RT_DOMAIN=value).values["RT_DOMAIN"] == value


@pytest.mark.parametrize("value", VALUE_RULES["domain"]["rejected"])
def test_rt_domain_rejects_the_corpus(tmp_path, value):
    assert not config.is_dns_name(value)
    if "\n" not in value:  # a newline cannot be written into a `.env` value at all
        with pytest.raises((ConfigError, EnvError)):
            load(tmp_path, Role.BRIDGE, RT_DOMAIN=value)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("address", ["10.0.0.1", "::1", "2001:db8::1"])
def test_rt_domain_refuses_an_ip_address_because_tunnels_are_subdomains(tmp_path, role, address):
    assert "RT_DOMAIN" in refused(tmp_path, role, RT_DOMAIN=address)


@pytest.mark.parametrize("value", VALUE_RULES["admin_password"]["accepted"])
def test_the_admin_password_accepts_the_corpus(tmp_path, value):
    assert config.ADMIN_PASSWORD.fullmatch(value)
    assert load(tmp_path, Role.BRIDGE, RT_ADMIN_PASSWORD=value).values["RT_ADMIN_PASSWORD"] == value


@pytest.mark.parametrize("value", VALUE_RULES["admin_password"]["rejected"])
def test_the_admin_password_rejects_the_corpus(tmp_path, value):
    assert not config.ADMIN_PASSWORD.fullmatch(value)
    if "\n" not in value:
        with pytest.raises((ConfigError, EnvError)):
            load(tmp_path, Role.BRIDGE, RT_ADMIN_PASSWORD=value)
