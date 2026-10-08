"""Decides whether this process is in a mount namespace where mounting cannot reach the machine.

A mount made in a namespace whose mounts are `shared` propagates to its peers, and a mount in PID 1's namespace is the
machine's own. Either is how a test's mount ends up on a real host, so the `mount` tests run only after both are ruled
out, on top of the explicit opt-in.
"""

import os
from collections.abc import Mapping
from pathlib import Path

OPT_IN = "RT_PRIVATE_MOUNT_NS"
SEPARATOR = "-"
MOUNT_POINT_FIELD = 4
FIRST_OPTIONAL_FIELD = 6


def private_namespace_problems(
    environ: Mapping[str, str], mountinfo: str, own_namespace: str, init_namespace: str | None
) -> list[str]:
    """Everything that makes mounting here unsafe; empty when it is safe. `init_namespace` is None when unreadable."""
    problems: list[str] = []
    if environ.get(OPT_IN) != "1":
        problems.append(f"{OPT_IN}=1 is not set; start the run with `unshare --mount --propagation private`")
    for line in mountinfo.splitlines():
        fields = line.split()
        if SEPARATOR not in fields or fields.index(SEPARATOR) <= FIRST_OPTIONAL_FIELD - 1:
            problems.append(f"cannot read a line of /proc/self/mountinfo: {line!r}")
            continue
        optional = fields[FIRST_OPTIONAL_FIELD:fields.index(SEPARATOR)]
        if any(field.startswith("shared:") for field in optional):
            problems.append(f"{fields[MOUNT_POINT_FIELD]} is a shared mount, so a mount here propagates to its peers")
    if init_namespace is not None and own_namespace == init_namespace:
        problems.append("this is the mount namespace of PID 1, so a mount here is the machine's own")
    return problems


def current_problems() -> list[str]:
    """`private_namespace_problems` for this process."""
    try:
        mountinfo = Path("/proc/self/mountinfo").read_text()
        own = os.readlink("/proc/self/ns/mnt")
    except OSError as exc:
        return [f"cannot inspect this process's mount namespace ({exc.strerror or exc}); mount tests need Linux"]
    try:
        init = os.readlink("/proc/1/ns/mnt")
    except OSError:
        init = None
    return private_namespace_problems(os.environ, mountinfo, own, init)
