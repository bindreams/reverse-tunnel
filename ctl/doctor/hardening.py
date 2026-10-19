# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The allow-list `container_hardening` holds a live bridge container to: what `compose.yaml` produces, field by field.

Nothing here asks how the container was started. An override file, `docker run` and a hand edit weaken it the same way,
and each shows in `docker inspect`. A field that is null or absent reads as empty (an empty list or map, `""`, false),
and the rule then applies, so a required value that is missing fails and nothing raises. Environment values are never
reported, only names: the variables an `env_file` adds include the token.
"""

import json
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

TOKEN_TARGET, CONFIG_TARGET = "/rt/secrets/token", "/rt/bridge/frps.toml"
TMPFS = "/run/rt"
ENVIRONMENT = frozenset({"RT_DOMAIN", "RT_ADMIN_PASSWORD"})
CAPABILITY = "DAC_READ_SEARCH"
NO_NEW_PRIVILEGES = "no-new-privileges"
# What Go's strconv.ParseBool reads as true, which is how Docker reads the value after `:` or `=`.
GO_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})
ADMIN_PORT, LOOPBACK = "7500/tcp", "127.0.0.1"
# Each is empty in compose.yaml; the name is what the message points at.
EMPTY_STRINGS = ("PidMode", "UsernsMode", "UTSMode")
EMPTY_COLLECTIONS = ("Devices", "Sysctls", "DeviceCgroupRules", "DeviceRequests")


def listing(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def shown(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def capability(name: Any) -> str:
    name = text(name).upper()
    return name.removeprefix("CAP_")


def sets_no_new_privileges(option: str) -> bool:
    """Whether Docker reads the security option as `no-new-privileges` on: bare, or with a true value after `:` or `=`."""
    name, separator, value = option.partition("=") if "=" in option else option.partition(":")
    return name == NO_NEW_PRIVILEGES and (not separator or value in GO_TRUE)


def shares(mode: str) -> bool:
    """`host`, or another container's namespace: the container then sees what that one sees."""
    return mode == "host" or mode.startswith("container:")


def same_path(found: str, wanted: Path) -> bool:
    """Equal once both are resolved, as the mount is the same file whatever route compose reached it by."""
    if not found:
        return False
    try:
        return Path(found).resolve() == wanted.resolve()
    except (OSError, RuntimeError):
        return Path(found) == wanted


def violations(container: Mapping[str, Any], *, image_env: Collection[str], runtime: str, root: Path) -> list[str]:
    """Every way the `docker inspect` document `container` departs from compose.yaml's security settings.

    `image_env` is the variable names the image itself declares and `runtime` the daemon's default runtime.
    """
    host, config = container.get("HostConfig"), container.get("Config")
    problems = []
    if isinstance(host, dict):
        problems += host_violations(host, runtime=runtime)
    else:
        problems.append("`docker inspect` has no HostConfig for the container, so its settings cannot be confirmed")
    if isinstance(config, dict):
        problems += config_violations(config, image_env)
    else:
        problems.append("`docker inspect` has no Config for the container, so its settings cannot be confirmed")
    return problems + mount_violations(container.get("Mounts"), root)


def host_violations(host: Mapping[str, Any], *, runtime: str) -> list[str]:
    problems = []

    def check(field: str, holds: bool, wanted: str, found: Any = None) -> None:
        if not holds:
            problems.append(f"HostConfig.{field} is {shown(host.get(field) if found is None else found)}; {wanted}")

    check(
        "CapDrop", "ALL" in {capability(name)
                             for name in listing(host.get("CapDrop"))}, "compose.yaml sets cap_drop: [ALL]"
    )
    added = sorted({capability(name) for name in listing(host.get("CapAdd"))})
    check("CapAdd", added == [CAPABILITY], f"compose.yaml sets cap_add: [{CAPABILITY}] and nothing more", added)
    check("Privileged", not host.get("Privileged"), "compose.yaml does not set privileged")
    options = [text(option) for option in listing(host.get("SecurityOpt"))]
    check(
        "SecurityOpt",
        len(options) == 1 and sets_no_new_privileges(options[0]),
        "compose.yaml sets security_opt: [no-new-privileges:true] and nothing more",
    )
    check("ReadonlyRootfs", host.get("ReadonlyRootfs") is True, "compose.yaml sets read_only: true")
    network = text(host.get("NetworkMode"))
    check(
        "NetworkMode",
        network != "none" and not shares(network),
        "compose.yaml uses a network of its own, not the host's, none or another container's",
    )
    check("IpcMode", not shares(text(host.get("IpcMode"))), "compose.yaml shares no IPC namespace")
    for field in EMPTY_STRINGS:
        check(field, text(host.get(field)) == "", "compose.yaml sets none")
    for field in EMPTY_COLLECTIONS:
        check(field, not host.get(field), "compose.yaml sets none")
    tmpfs = sorted(mapping(host.get("Tmpfs")))
    check("Tmpfs", tmpfs == [TMPFS], f"compose.yaml sets exactly tmpfs: [{TMPFS}]", tmpfs)
    check(
        "CgroupnsMode",
        host.get("CgroupnsMode") == "private",
        "compose.yaml sets cgroup: private, because a daemon's default may be the host's namespace",
    )
    check("Runtime", text(host.get("Runtime")) == runtime, f"compose.yaml uses the daemon's default runtime, {runtime}")
    published = listing(mapping(host.get("PortBindings")).get(ADMIN_PORT))
    exposed = [text(mapping(entry).get("HostIp")) for entry in published]
    if any(address != LOOPBACK for address in exposed):
        problems.append(
            f"HostConfig.PortBindings[{ADMIN_PORT}] publishes on {shown(exposed)}; compose.yaml publishes the admin "
            f"port on {LOOPBACK} only"
        )
    return problems


def config_violations(config: Mapping[str, Any], image_env: Collection[str]) -> list[str]:
    problems = []
    if text(config.get("User")) != "":
        problems.append(f"Config.User is {shown(config.get('User'))}; compose.yaml sets no user")
    names = {text(entry).partition("=")[0] for entry in listing(config.get("Env"))}
    extra = sorted(names - ENVIRONMENT - set(image_env))
    if extra:
        problems.append(
            f"Config.Env carries {', '.join(extra)}, which neither the image nor compose.yaml sets (compose.yaml sets "
            f"only {', '.join(sorted(ENVIRONMENT))}; an `env_file` would hand the container the whole of .env)"
        )
    return problems


def mount_violations(mounts: Any, root: Path) -> list[str]:
    wanted = {TOKEN_TARGET: root / "secrets" / "token", CONFIG_TARGET: root / "bridge" / "frps.toml"}
    both = f"compose.yaml mounts only {TOKEN_TARGET} and {CONFIG_TARGET}, read-only, from this deployment"
    problems, seen = [], set()
    for mount in map(mapping, listing(mounts)):
        target, kind = text(mount.get("Destination")), text(mount.get("Type"))
        source = text(mount.get("Source")) or text(mount.get("Name"))
        if kind != "bind" or target not in wanted or target in seen:
            problems.append(f"Mounts has a {kind or 'mount'} of {source or 'nothing'} at {target}; {both}")
            continue
        seen.add(target)
        if mount.get("RW"):
            problems.append(f"Mounts has {target} writable; {both}")
        if not same_path(source, wanted[target]):
            problems.append(
                f"Mounts has {target} coming from {source or 'nothing'}; compose.yaml mounts {wanted[target]}"
            )
    problems += [f"Mounts has no {target}; {both}" for target in wanted if target not in seen]
    return problems
