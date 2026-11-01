import re
from collections.abc import Callable

_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def valid_label(s: str) -> bool:
    """One DNS label: lowercase letters, digits and inner hyphens, at most 63 characters.

    Hyphens at the third and fourth position are reserved (`xn--` and kin), which ACME CAs refuse.
    """
    return len(s) <= 63 and _LABEL.fullmatch(s) is not None and s[2:4] != "--"


def allowed_names(host: str, domain: str) -> Callable[[str], bool]:
    """The predicate for names a host may claim under tunnel domain `domain`: `host.domain` or `label.host.domain`."""
    if not valid_label(host):
        return lambda name: False
    base = f"{host}.{domain}"

    def allowed(name: str) -> bool:
        if name == base:
            return True
        label, _, rest = name.partition(".")
        return rest == base and valid_label(label)

    return allowed
