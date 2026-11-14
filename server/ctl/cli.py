"""The bridge operator's commands (`uv run ctl <command>`)."""

import argparse
import contextlib
import secrets
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from dotenv import dotenv_values

from ctl import certs, compose
from ctl.generate import render_compose
from ctl.joincode import encode_join, is_token_hash
from ctl.names import alias_problem, valid_domain, valid_label
from ctl.registry import (
    RegistryError,
    atomic_write,
    locked,
    put,
    read_aliases,
    read_hosts,
    write_aliases,
    write_hosts,
)

STATE = Path("state")
TLS = Path("tls")
GENERATED = Path("compose.generated.yaml")
ENV = Path(".env")
COMPOSE_FILE = "compose.yaml:compose.generated.yaml"
RESTART_HINT = (
    "The host's current session continues until it reconnects. To cut it now, run\n"
    "  docker compose restart reverse-tunnel-frps\n"
    "which drops every tunnel once; hosts reconnect on their own."
)


class CtlError(Exception):
    pass


def resolve(name: str) -> bool:
    try:
        socket.getaddrinfo(name, None)
    except socket.gaierror:
        return False
    return True


def _create(path: Path, data: bytes, mode: int) -> None:
    """Create `path` at `mode` unless it is already present."""
    with contextlib.suppress(FileExistsError):
        atomic_write(path, data, mode, exclusive=True)


def _init(env: dict) -> None:
    """Check the deployment and create what is missing; `.env` only ever gains the lines it lacks."""
    domain = env["TUNNEL_DOMAIN"]
    if env.get("COMPOSE_FILE", COMPOSE_FILE) != COMPOSE_FILE:
        raise CtlError(f"COMPOSE_FILE in .env is {env['COMPOSE_FILE']!r}, not {COMPOSE_FILE!r}: edit or remove it")
    if not compose.network_exists("gateway"):
        raise CtlError("docker network 'gateway' does not exist")
    for name in (domain, f"rt-dns-check.rt-dns-check.{domain}"):
        if not resolve(name):
            raise CtlError(f"cannot resolve {name}")
    try:
        certs.ensure(domain, TLS)
    except certs.CertError as e:
        raise CtlError(str(e)) from e
    missing = {"FRPS_TOKEN": secrets.token_hex(32), "COMPOSE_FILE": COMPOSE_FILE}
    lines = [f"{key}={value}\n" for key, value in missing.items() if key not in env]
    if lines:
        text = ENV.read_text()
        if not text.endswith("\n"):
            text += "\n"
        atomic_write(ENV, (text + "".join(lines)).encode(), 0o600)  # it holds the frps token
    _create(TLS / "trust.pem", (TLS / "frps.crt").read_bytes(), 0o644)
    _create(STATE / "hosts.yaml", b"", 0o644)
    _create(STATE / "aliases.yaml", b"", 0o644)


def _add(args, hosts, aliases, env):
    if not valid_label(args.host):
        raise CtlError(f"invalid host name {args.host!r}")
    if not is_token_hash(args.hash):
        raise CtlError(f"invalid hash {args.hash!r}")
    if hosts.get(args.host, args.hash) != args.hash:
        raise CtlError(f"{args.host} is registered with another hash; revoke it first")
    put(hosts, args.host, args.hash)


def _revoke(args, hosts, aliases, env):
    if hosts.pop(args.host, None) is None:
        raise CtlError(f"{args.host} is not registered")
    return RESTART_HINT


def _alias(args, hosts, aliases, env):
    if problem := alias_problem(args.public, args.backend, env["TUNNEL_DOMAIN"]):
        raise CtlError(problem)
    put(aliases, args.public, args.backend)


def _unalias(args, hosts, aliases, env):
    if aliases.pop(args.public, None) is None:
        raise CtlError(f"{args.public} is not an alias")


def _list(args, hosts, aliases, env):
    lines = [f"host {host} {digest}" for host, digest in hosts.items()]
    return "\n".join(lines + [f"alias {public} {backend}" for public, backend in aliases.items()])


def _join_code(args, hosts, aliases, env):
    if not env.get("FRPS_TOKEN"):
        raise CtlError("FRPS_TOKEN is missing or empty in .env; run 'ctl init'")
    return encode_join(env["TUNNEL_DOMAIN"], env["FRPS_TOKEN"], (TLS / "trust.pem").read_text())


def _init_report(args, hosts, aliases, env):
    return (
        "Join code for this bridge. Paste it into `reverse-tunnel install` on each host (the same code works for\n"
        "every host); `uv run ctl join-code` shows it again:\n" + _join_code(args, hosts, aliases, env)
    )


FRPS_KEPT = (
    "reverse-tunnel-frps was left running. To apply a change to its image, compose.yaml or .env, which drops every "
    "tunnel once, run `docker compose up -d --build reverse-tunnel-frps`."
)


class Command(NamedTuple):
    # Edits the registries in place and returns text to print: before the bring-up, or after it for `bootstrap`.
    handler: Callable
    help: str
    arguments: dict[str, str]  # the help of each argument
    # The command that makes a folder a bridge: it runs in a folder with no `state/`, builds the images, and prints its
    # text last, below docker's output.
    bootstrap: bool = False


COMMANDS = {
    "init": Command(
        _init_report,
        "Check this folder, create what is missing (the token, the certificate, the registries), start the bridge, "
        "and print the join code. Safe to run again.",
        {},
        bootstrap=True,
    ),
    "add": Command(
        _add,
        "Register a host, so the bridge lets it in. Run the line that `reverse-tunnel install` printed on the host.",
        {
            "host": "the host's name, the first word after `ctl add` in the line `reverse-tunnel install` printed",
            "hash": "the host's token hash, `sha256:` and 64 hex digits, the last word of the same line",
        },
    ),
    "revoke": Command(
        _revoke,
        "Stop letting a host in: remove it from the registry. Its current session lasts until it reconnects.",
        {"host": "the name of a registered host, as `ctl list` shows it"},
    ),
    "alias": Command(
        _alias,
        "Give an HTTP service a public name of your own, for what a host publishes under the tunnel domain.",
        {
            "public": "the name to serve, outside the tunnel domain, whose DNS points at this server",
            "backend": "the published name it forwards to, `<service>.<host>.<tunnel domain>`; the host's config.yaml "
            "lists its services",
        },
    ),
    "unalias": Command(
        _unalias,
        "Remove a public name that `ctl alias` made.",
        {"public": "the public name, as `ctl list` shows it after `alias`"},
    ),
    "list": Command(_list, "Show the registered hosts and the aliases.", {}),
    "join-code": Command(
        _join_code,
        "Print the join code, which every host needs once: paste it into `reverse-tunnel install` on the host.",
        {},
    ),
}


def _registry(call, path, *args):
    try:
        return call(path, *args)
    except RegistryError as e:
        raise CtlError(f"{path}: {e}") from e


def _run(args) -> None:
    command = COMMANDS[args.command]
    if command.bootstrap:
        if not ENV.is_file():
            raise CtlError(f"no {ENV} here: run from the bridge folder, with .env.example copied to .env")
        with contextlib.suppress(FileExistsError):
            STATE.mkdir()
            STATE.chmod(0o755)  # the plugin container reads it as another uid, whatever the umask
    elif not STATE.is_dir():
        raise CtlError("no state/ here: run from the bridge folder, after 'ctl init'")
    with locked(STATE):
        env = dotenv_values(ENV)
        domain = env.get("TUNNEL_DOMAIN")
        if not domain:
            raise CtlError("TUNNEL_DOMAIN is not set in .env")
        if not valid_domain(domain):
            raise CtlError(f"TUNNEL_DOMAIN {domain!r} is not a valid tunnel domain")
        if command.bootstrap:
            _init(env)
            env = dotenv_values(ENV)
        hosts = _registry(read_hosts, STATE / "hosts.yaml")
        aliases = _registry(read_aliases, STATE / "aliases.yaml", domain)
        old_hosts = dict(hosts)
        old_aliases = dict(aliases)
        out = command.handler(args, hosts, aliases, env)
        if hosts != old_hosts:
            _registry(write_hosts, STATE / "hosts.yaml", hosts)
        if aliases != old_aliases:
            _registry(write_aliases, STATE / "aliases.yaml", aliases, domain)
        if out and not command.bootstrap:
            print(out)  # after the write, which may fail; before the reload, which may too
        try:
            atomic_write(GENERATED, render_compose(hosts, aliases, domain).encode(), 0o644)
            frps_running = compose.compose_up(Path.cwd(), build=command.bootstrap)
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            updated = "the registry is updated but " if (hosts, aliases) != (old_hosts, old_aliases) else ""
            retry = (
                "rerun `uv run ctl init` to retry, then it prints the join code"
                if command.bootstrap
                else "rerun any ctl command to retry"
            )
            raise CtlError(f"{updated}the bridge was not brought up ({e}); {retry}") from e
        if command.bootstrap:
            if frps_running:
                print(FRPS_KEPT)
            if out:
                print(out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctl", description="Manage the reverse-tunnel bridge.")
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="command")
    for name, command in COMMANDS.items():
        subparser = subparsers.add_parser(name, help=command.help, description=command.help)
        for argument, argument_help in command.arguments.items():
            subparser.add_argument(argument, help=argument_help)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        _run(build_parser().parse_args(argv))
    except (CtlError, OSError) as e:
        print(f"ctl: {e}", file=sys.stderr)
        return 1
    return 0
