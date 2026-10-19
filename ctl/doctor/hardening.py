# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Inspects the live container, not how it was started: an override file, `docker run` and a hand edit all show in
`docker inspect`. It fails on what lets the container reach past itself (host access, network exposure, secret
exposure), not on its interior: a writable root or a tmpfs of its own is the operator's to have. A null or absent field
reads as empty, so a missing required value fails rather than raises.
"""

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

TOKEN_TARGET, CONFIG_TARGET = "/rt/secrets/token", "/rt/bridge/frps.toml"
# Where compose.yaml mounts them from, relative to the deployment.
TOKEN_SOURCE, CONFIG_SOURCE = "secrets/token", "bridge/frps.toml"
ENVIRONMENT = frozenset({"RT_DOMAIN", "RT_ADMIN_PASSWORD"})
CAPABILITY = "DAC_READ_SEARCH"
NO_NEW_PRIVILEGES = "no-new-privileges"
# What Go's strconv.ParseBool reads as true, which is how Docker reads the value after `:` or `=`.
GO_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})
ADMIN_PORT, LOOPBACK = "7500/tcp", "127.0.0.1"
VOLUME_DRIVER = "local"
# compose.yaml pins both: a daemon's default for either may be the host's namespace.
CGROUPNS_MODE = IPC_MODE = "private"
# Docker's default masked and read-only paths for an unprivileged container (moby `daemon/pkg/oci/defaults.go`). Compose
# turns `systempaths=unconfined` into empty lists here and drops it from SecurityOpt. Only the long-standing entries are
# required: `/proc/interrupts`, `/sys/devices/virtual/powercap` and the per-CPU `thermal_throttle` are missing from an
# older daemon's default.
MASKED_PATHS = frozenset({
    "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi",
    "/proc/timer_list", "/proc/timer_stats", "/sys/firmware"
})
READONLY_PATHS = frozenset({"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"})
# Each is empty in compose.yaml.
EMPTY_STRINGS = ("PidMode", "UsernsMode", "UTSMode")
EMPTY_COLLECTIONS = ("Devices", "Sysctls", "DeviceCgroupRules", "DeviceRequests", "GroupAdd")


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


def mismatch(found: str, wanted: Path) -> str | None:
    """How a mount's source differs from `wanted`, or None if it is the same file whatever route compose reached it by."""
    if not found:
        return "coming from nothing"
    try:
        if Path(found).resolve() == wanted.resolve():
            return None
    except (OSError, RuntimeError) as exc:
        return f"coming from {found}, which cannot be resolved ({exc})"
    return f"coming from {found}"


def violations(
    container: Mapping[str, Any],
    *,
    image: Mapping[str, Any],
    runtime: str,
    root: Path,
    volume: Callable[[str], Mapping[str, Any]],
) -> list[str]:
    """What in the `docker inspect` document `container` lets it reach past itself: the host, the network, a secret.
    Settings of its interior (a writable root, extra tmpfs mounts, the image and command it runs) are not checked.
    `image` is the image's own `Config`, whose `Env` names the variables the container may carry besides compose.yaml's;
    `runtime` the daemon's default runtime; `volume` the `docker volume inspect` document of a named volume, which
    holds the driver options that `Mounts` does not show."""
    host, config = container.get("HostConfig"), container.get("Config")
    problems = []
    if isinstance(host, dict):
        problems += host_violations(host, runtime=runtime)
    else:
        problems.append("`docker inspect` has no HostConfig for the container, so its settings cannot be confirmed")
    if isinstance(config, dict):
        problems += config_violations(config, image)
    else:
        problems.append("`docker inspect` has no Config for the container, so its settings cannot be confirmed")
    # An exited container may report no ports; a running one that reports none is not shown to publish loopback only.
    running = mapping(container.get("State")).get("Running") is not False
    return problems + network_violations(container.get("NetworkSettings"),
                                         running=running) + mount_violations(container.get("Mounts"), root, volume)


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
    network = text(host.get("NetworkMode"))
    check(
        "NetworkMode",
        network != "none" and not shares(network),
        "compose.yaml uses a network of its own, not the host's, none or another container's",
    )
    check("IpcMode", host.get("IpcMode") == IPC_MODE, f"compose.yaml sets ipc: {IPC_MODE}")
    for field, defaults in (("MaskedPaths", MASKED_PATHS), ("ReadonlyPaths", READONLY_PATHS)):
        missing = sorted(defaults - {text(path) for path in listing(host.get(field))})
        check(
            field, not missing,
            f"it lacks {', '.join(missing)}, which Docker applies by default; compose.yaml sets no `systempaths=unconfined`"
        )
    for field in EMPTY_STRINGS:
        check(field, text(host.get(field)) == "", "compose.yaml sets none")
    for field in EMPTY_COLLECTIONS:
        check(field, not host.get(field), "compose.yaml sets none")
    check(
        "CgroupnsMode",
        host.get("CgroupnsMode") == CGROUPNS_MODE,
        f"compose.yaml sets cgroup: {CGROUPNS_MODE}, because a daemon's default may be the host's namespace",
    )
    check("Runtime", text(host.get("Runtime")) == runtime, f"compose.yaml uses the daemon's default runtime, {runtime}")
    # `docker run -P` publishes every EXPOSEd port with no entry in PortBindings.
    check("PublishAllPorts", not host.get("PublishAllPorts"), "compose.yaml does not publish every exposed port")
    problems += admin_binding_violations("HostConfig.PortBindings", mapping(host.get("PortBindings")))
    return problems


def network_violations(network: Any, *, running: bool) -> list[str]:
    """The ports the daemon actually published, which `HostConfig` alone does not show."""
    return admin_binding_violations("NetworkSettings.Ports", mapping(mapping(network).get("Ports")), required=running)


def admin_binding_violations(field: str, bindings: Mapping[str, Any], *, required: bool = True) -> list[str]:
    exposed = [text(mapping(entry).get("HostIp")) for entry in listing(bindings.get(ADMIN_PORT))]
    if not exposed:
        if not required:
            return []
        return [f"{field}[{ADMIN_PORT}] is not published; compose.yaml publishes the admin port on {LOOPBACK} only"]
    if all(address == LOOPBACK for address in exposed):
        return []
    return [
        f"{field}[{ADMIN_PORT}] publishes on {shown(exposed)}; compose.yaml publishes the admin port on {LOOPBACK} only"
    ]


def config_violations(config: Mapping[str, Any], image: Mapping[str, Any]) -> list[str]:
    problems = []
    if text(config.get("User")) != "":
        problems.append(f"Config.User is {shown(config.get('User'))}; compose.yaml sets no user")
    names = {text(entry).partition("=")[0] for entry in listing(config.get("Env"))}
    image_env = {text(entry).partition("=")[0] for entry in listing(image.get("Env"))}
    extra = sorted(names - ENVIRONMENT - image_env)
    if extra:
        problems.append(
            f"Config.Env carries {', '.join(extra)}, which neither the image nor compose.yaml sets (compose.yaml sets "
            f"only {', '.join(sorted(ENVIRONMENT))}; an `env_file` would hand the container the whole of .env)"
        )
    return problems


def mount_violations(mounts: Any, root: Path, volume: Callable[[str], Mapping[str, Any]]) -> list[str]:
    """The two required binds, exactly; any other bind reaches the host; a volume must be plain Docker-managed
    storage; a tmpfs stays in memory; any other type is unknown, so it fails."""
    wanted = {TOKEN_TARGET: root / TOKEN_SOURCE, CONFIG_TARGET: root / CONFIG_SOURCE}
    both = f"compose.yaml mounts {TOKEN_TARGET} and {CONFIG_TARGET}, read-only, from this deployment"
    problems, seen = [], set()
    for mount in map(mapping, listing(mounts)):
        target, kind = text(mount.get("Destination")), text(mount.get("Type"))
        name = text(mount.get("Name"))
        source = text(mount.get("Source")) or name
        found = f"Mounts has a {kind or 'mount'} of {source or 'nothing'} at {target}"
        if target in wanted:
            if kind != "bind" or target in seen:
                problems.append(f"{found}; {both}")
                continue
            seen.add(target)
            if mount.get("RW") is not False:
                problems.append(f"Mounts has {target} not read-only (RW is {shown(mount.get('RW'))}); {both}")
            different = mismatch(source, wanted[target])
            if different:
                problems.append(f"Mounts has {target} {different}; compose.yaml mounts {wanted[target]}")
        elif kind == "bind":
            problems.append(f"{found}, which reaches the host; {both}, and no other bind")
        elif kind == "volume":
            problems += volume_violations(f"Mounts has a volume of {name or 'nothing'} at {target}", name, volume)
        elif kind != "tmpfs":
            problems.append(f"{found}, a mount type this check does not know; {both}")
    problems += [f"Mounts has no {target}; {both}" for target in wanted if target not in seen]
    return problems


def volume_violations(found: str, name: str, volume: Callable[[str], Mapping[str, Any]]) -> list[str]:
    """A volume is plain Docker-managed storage only if its driver is `local` and it has no driver options: with
    options `local` mounts a host path (`o=bind`) or another machine (`type=nfs`), and another driver is unknown."""
    if not name:
        return [f"{found}, whose driver options cannot be read without its name"]
    document = volume(name)
    driver, options = document.get("Driver"), document.get("Options")
    if driver != VOLUME_DRIVER:
        return [
            f"{found}, which uses the driver {shown(driver)}; only Docker's own `{VOLUME_DRIVER}` storage is allowed"
        ]
    if options:
        return [f"{found}, which has driver options {shown(options)} that can reach a host path or another machine"]
    return []
