# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Whether the session running `ctl install` can be shown not to ride the tunnel it is about to restart.

Hosts are reachable only through the tunnel, and restarting websocat cuts a session that arrived that way. Such a
session reaches sshd from loopback, since websocat dials `127.0.0.1`, so the proof asked for is a client address that
is not loopback. Proof of danger would be wrong: `sudo` resets the environment and strips `SSH_CONNECTION`, and a
reattached tmux session has lost it, so "refuse when it shows loopback" never fires in the documented invocation.
"""

import dataclasses
import ipaddress
import os
from collections.abc import Mapping

VARIABLE = "SSH_CONNECTION"


@dataclasses.dataclass(frozen=True)
class Verdict:
    safe: bool
    reason: str  # which part of the proof failed, or what was shown


def _is_loopback(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or (mapped is not None and mapped.is_loopback)


def assess(environ: Mapping[str, str] | None = None) -> Verdict:
    environ = os.environ if environ is None else environ
    value = environ.get(VARIABLE)
    if value is None:
        return Verdict(
            False,
            f"{VARIABLE} is not set, so this session cannot be shown to be off the tunnel (sudo and a reattached tmux "
            "session both drop it)",
        )
    fields = value.split()
    try:
        if len(fields) != 4:
            raise ValueError
        address, server = ipaddress.ip_address(fields[0]), ipaddress.ip_address(fields[2])
    except ValueError:
        return Verdict(
            False, f"{VARIABLE} is {value!r}, which is not `client-address client-port server-address server-port`"
        )
    if _is_loopback(address):
        return Verdict(
            False,
            f"the ssh client address is loopback ({fields[0]}), which is how a session through the tunnel arrives"
        )
    if address == server:
        return Verdict(
            False,
            f"the ssh client and server addresses are the same ({fields[0]}): the connection was made from this machine "
            "to itself, which is how a relay on it looks",
        )
    return Verdict(True, f"the ssh client address is {fields[0]}, not loopback")
