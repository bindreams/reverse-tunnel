# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The client role: the `ssh_config` block that reaches a host, and the one binary it needs.

A client has no daemon. `ssh` runs websocat as its `ProxyCommand`, so installing a client is fetching websocat.
"""

import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from ctl import perms
from ctl.binaries import bundle_for, load_lock, pins_for, tools_for_role
from ctl.config import MAX_DNS_NAME_LENGTH, Config, ConfigError, Role, validate_label
from ctl.download import Fetcher, describe_install, record_digests
from ctl.removal import remove_directory

DEFAULT_PORTS = {"ws": 80, "wss": 443}
WEBSOCAT = "websocat.exe" if sys.platform == "win32" else "websocat"
BIN_MODE = 0o755

# ssh_config ===========================================================================================================


def _websocat_command(root: Path) -> str:
    """The websocat `ctl install` put in `bin/`, quoted for the shell ssh runs it in; else whatever is on `PATH`."""
    installed = root / "bin" / WEBSOCAT
    if not installed.is_file():
        return "websocat"
    return subprocess.list2cmdline([str(installed)]) if sys.platform == "win32" else shlex.quote(str(installed))


def render_ssh_config(config: Config, label: str) -> str:
    """The `ssh_config` stanza that reaches host `label`, ready to paste.

    `%h` is the `HostName`, so the stanza names the host once. The port follows the scheme's default (80 for `ws`, 443
    for `wss`) and appears only when `RT_PUBLIC_PORT` differs, because websocat takes the port from the scheme.
    """
    if config.role is Role.BRIDGE:
        raise ConfigError("client-config needs ROLE=client (or host); this deployment is a bridge")
    validate_label(label)
    hostname = f"{label}.{config.require('RT_DOMAIN')}"
    if len(hostname) > MAX_DNS_NAME_LENGTH:
        raise ConfigError(f"{hostname} is longer than the {MAX_DNS_NAME_LENGTH} characters a DNS name can be")
    scheme, port = config.require("RT_SCHEME"), int(config.require("RT_PUBLIC_PORT"))
    authority = "%h" if port == DEFAULT_PORTS[scheme] else f"%h:{port}"
    return (
        f"Host {label}\n"
        f"  HostName {hostname}\n"
        f"  ProxyCommand {_websocat_command(config.root)} --binary {scheme}://{authority}/\n"
        "  # Required, not cosmetic: the front proxy and frps on the path can each drop a session that sits idle.\n"
        "  ServerAliveInterval 10\n"
    )


# Install ==============================================================================================================


def install_client(config: Config, *, lock_path: Path, platform: str, fetcher: Callable[[], Fetcher]) -> None:
    """Fetch the client's pinned binaries into `bin/`, record their digests, and tighten `.env`. No elevation."""
    root, bin_dir = config.root, config.root / "bin"
    lock = load_lock(lock_path)
    wanted = [(pin, bundle_for(lock, tool)) for tool in tools_for_role(config.role)
              for pin in pins_for(lock, tool, platform)]
    perms.converge_dir(bin_dir, None, BIN_MODE, frozenset(), isolate=False, root=root)
    with fetcher() as fetch:
        for pin, bundle in wanted:
            print(describe_install(pin, fetch.fetch(pin, bin_dir, bundle)))
    record_digests(bin_dir, [pin for pin, _ in wanted])
    perms.harden_file(root / ".env", None, frozenset(), root=root)


def uninstall_client(config: Config) -> None:
    removed = remove_directory(config.root, "bin")
    print("removed bin/" if removed else "bin/ is already absent")
