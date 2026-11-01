import re
from collections.abc import Callable

_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_SPECIAL_USE_TLDS = {"invalid", "test", "example", "localhost", "local", "onion", "internal", "arpa"}
_SPECIAL_USE_DOMAINS = ("example.com", "example.net", "example.org")


def valid_label(s: str) -> bool:
    """One DNS label: lowercase letters, digits and inner hyphens, at most 63 characters.

    Hyphens at the third and fourth position are reserved (`xn--` and kin), which ACME CAs refuse.
    """
    return len(s) <= 63 and _LABEL.fullmatch(s) is not None and s[2:4] != "--"


def valid_domain(domain: str) -> bool:
    """A tunnel domain: at least two valid labels, at most 253 characters, no trailing dot."""
    labels = domain.split(".")
    return len(labels) >= 2 and len(domain) <= 253 and all(valid_label(label) for label in labels)


def owner_host(name: str, domain: str) -> str | None:
    """The host label of a valid `host.domain` or `service.host.domain`, else None."""
    suffix = f".{domain}"
    if not name.endswith(suffix):
        return None
    labels = name.removesuffix(suffix).split(".")
    if len(labels) > 2 or not all(valid_label(label) for label in labels):
        return None
    return labels[-1]


def allowed_names(host: str, domain: str) -> Callable[[str], bool]:
    """The predicate for names a host may claim under tunnel domain `domain`: `host.domain` or `label.host.domain`."""
    return lambda name: owner_host(name, domain) == host


def valid_public_name(name: str) -> bool:
    """Whether the name is a host an ACME CA can issue for."""
    labels = name.split(".")
    return (
        len(labels) >= 2
        and len(name) <= 253
        and all(valid_label(label) for label in labels)
        and not labels[-1].isdigit()
        and labels[-1] not in _SPECIAL_USE_TLDS
        and not any(name == d or name.endswith(f".{d}") for d in _SPECIAL_USE_DOMAINS)
    )


def alias_problem(public: str, backend: str, domain: str) -> str | None:
    """Why `public -> backend` is not a valid alias under tunnel domain `domain`, or None."""
    if not valid_public_name(public):
        return f"invalid public name {public!r}"
    if public == domain or public.endswith(f".{domain}"):
        return f"public name {public!r} is under the tunnel domain"
    if owner_host(backend, domain) is None:
        return f"backend {backend!r} is not a name under the tunnel domain"
    return None
