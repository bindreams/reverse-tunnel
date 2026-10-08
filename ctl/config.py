# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Role-aware, fail-closed configuration loaded from `.env`.

Declares which keys each role needs and what shape they take; holds no defaults. `example.env` is the single source
of values, because goetia reads `.env` itself and would not see a default that only `ctl` knew.
"""

import dataclasses
import enum
import ipaddress
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from ctl.env import EnvError, read


class Role(enum.StrEnum):
    BRIDGE = "bridge"
    HOST = "host"
    CLIENT = "client"


class ConfigError(Exception):
    """The deployment's configuration is missing, malformed, or still holds a shipped placeholder."""


REQUIRED: Mapping[Role, frozenset[str]] = {
    Role.BRIDGE: frozenset({
        "ROLE",
        "RT_DOMAIN",
        "RT_TOKEN",
        "RT_ADMIN_PASSWORD",
        "RT_CONTROL_PORT",
        "RT_VHOST_BIND",
        "RT_VHOST_PORT",
        "RT_ADMIN_PORT",
    }),
    Role.HOST: frozenset({
        "ROLE",
        "RT_LABEL",
        "RT_DOMAIN",
        "RT_SCHEME",
        "RT_PUBLIC_PORT",
        "RT_SERVER_ADDR",
        "RT_SERVER_PORT",
        "RT_PROTOCOL",
        "RT_TOKEN",
        "RT_SSH_PORT",
        "RT_WS_PORT",
        "RT_SERVICE_USER",
    }),
    Role.CLIENT: frozenset({"ROLE", "RT_DOMAIN", "RT_SCHEME", "RT_PUBLIC_PORT"}),
}
# May be absent or empty; validated when set.
OPTIONAL: Mapping[Role, frozenset[str]] = {
    Role.BRIDGE: frozenset({"RT_CONTROL_HOST", "RT_PROXY_NETWORK", "RT_PUBLIC_HOST"}),
    Role.HOST: frozenset(),
    Role.CLIENT: frozenset(),
}

# Placeholders `example.env` ships. Each is well-formed on purpose, so only an identity check can refuse it.
EXAMPLE_TOKEN = "0" * 64
EXAMPLE_ADMIN_PASSWORD = "example-admin-password"
EXAMPLE_LABEL = "example"

PROTOCOLS = ("quic", "tcp", "websocket", "wss")
SCHEMES = ("ws", "wss")
TOKEN = re.compile(r"[0-9a-f]{64}", re.ASCII)
ADMIN_PASSWORD = re.compile(r"[A-Za-z0-9_-]{16,}", re.ASCII)
LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", re.ASCII)
DNS_LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", re.ASCII)
PORT = re.compile(r"[1-9][0-9]{0,4}", re.ASCII)
MAX_DNS_NAME_LENGTH = 253
MAX_PORT = 65535
HOST_KEYS = frozenset({"RT_DOMAIN", "RT_SERVER_ADDR", "RT_CONTROL_HOST", "RT_PUBLIC_HOST"})


def service_user_required() -> bool:
    """Only the systemd and launchd blocks of the manifest read `RT_SERVICE_USER`; Windows pins its account."""
    return sys.platform != "win32"


def _required_keys(role: Role) -> frozenset[str]:
    keys = REQUIRED[role]
    return keys if service_user_required() else keys - {"RT_SERVICE_USER"}


# Validation ===========================================================================================================


def _is_dns_name_or_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return "%" not in value  # a scope id is not part of an address another machine can resolve
    return len(value) <= MAX_DNS_NAME_LENGTH and all(DNS_LABEL.fullmatch(label) for label in value.split("."))


def _check_port(value: str) -> bool:
    return bool(PORT.fullmatch(value)) and int(value) <= MAX_PORT


def _check_shape(key: str, value: str) -> str | None:
    """What is wrong with `value` for `key`, or None. Never repeats the value."""
    if key == "RT_TOKEN":
        if not TOKEN.fullmatch(value):
            return "must be 64 lowercase hexadecimal characters"
        if value == EXAMPLE_TOKEN:
            return "is still the example token from example.env; generate your own"
    elif key == "RT_ADMIN_PASSWORD":
        if not ADMIN_PASSWORD.fullmatch(value):
            return "must be at least 16 characters from A-Z, a-z, 0-9, `_` and `-`"
        if value == EXAMPLE_ADMIN_PASSWORD:
            return "is still the example password from example.env; choose your own"
    elif key == "RT_LABEL":
        if not LABEL.fullmatch(value):
            return "must be lowercase letters, digits and `-`, starting and ending with a letter or digit"
        if value == EXAMPLE_LABEL:
            return "is still the example label from example.env; pick one unique to this host"
    elif key == "RT_PROTOCOL":
        if value not in PROTOCOLS:
            return f"must be one of {', '.join(PROTOCOLS)}"
    elif key == "RT_SCHEME":
        if value not in SCHEMES:
            return f"must be one of {', '.join(SCHEMES)}"
    elif key in HOST_KEYS:
        if not _is_dns_name_or_ip(value):
            return "must be a DNS name or IP address, without a scheme, port, path or trailing dot"
    elif key.endswith("_PORT") and not _check_port(value):
        return f"must be an integer from 1 to {MAX_PORT}"
    return None


def _validate(role: Role, values: Mapping[str, str]) -> None:
    required = _required_keys(role)
    missing = sorted(required - values.keys())
    if missing:
        raise ConfigError(f"missing required variable(s): {', '.join(missing)}; see example.env")
    empty = sorted(key for key in required if not values[key])
    if empty:
        raise ConfigError(f"required variable(s) set to nothing: {', '.join(empty)}")
    for key in sorted(required | OPTIONAL[role]):
        value = values.get(key, "")
        problem = _check_shape(key, value) if value else None
        if problem:
            raise ConfigError(f"{key} {problem}")


def _parse_role(values: Mapping[str, str]) -> Role:
    try:
        return Role(values["ROLE"])
    except (KeyError, ValueError):
        choices = ", ".join(role.value for role in Role)
        raise ConfigError(f"ROLE must be one of: {choices}") from None


# Loading ==============================================================================================================


@dataclasses.dataclass(frozen=True)
class Config:
    root: Path
    role: Role
    values: Mapping[str, str]

    @classmethod
    def load(cls, root: Path) -> "Config":
        """Read `<root>/.env` and validate it for its role. Read-only: it never repairs permissions."""
        path = root / ".env"
        try:
            values = read(path)
        except EnvError as exc:
            raise ConfigError(str(exc)) from exc
        role = _parse_role(values)
        _validate(role, values)
        return cls(root=root, role=role, values=MappingProxyType(dict(values)))

    def require(self, name: str) -> str:
        """The non-empty value of `name`, or a `ConfigError` naming it."""
        value = self.values.get(name, "")
        if not value:
            raise ConfigError(f"{name} is not set")
        return value
