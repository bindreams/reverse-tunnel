"""The bridge operator's commands (`uv run ctl <command>`)."""

import argparse
import contextlib
import secrets
import socket
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

from ctl import certs, compose
from ctl.generate import render_compose
from ctl.joincode import encode_join, is_token_hash
from ctl.names import alias_problem, valid_domain, valid_label
from ctl.registry import RegistryError, atomic_write, locked, read_aliases, read_hosts, write_aliases, write_hosts

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
    _create(STATE / "hosts", b"", 0o644)
    _create(STATE / "aliases", b"", 0o644)


def _add(args, hosts, aliases, env):
    if not valid_label(args.host):
        raise CtlError(f"invalid host name {args.host!r}")
    if not is_token_hash(args.hash):
        raise CtlError(f"invalid hash {args.hash!r}")
    if hosts.setdefault(args.host, args.hash) != args.hash:
        raise CtlError(f"{args.host} is registered with another hash; revoke it first")


def _revoke(args, hosts, aliases, env):
    if hosts.pop(args.host, None) is None:
        raise CtlError(f"{args.host} is not registered")
    return RESTART_HINT


def _alias(args, hosts, aliases, env):
    if problem := alias_problem(args.public, args.backend, env["TUNNEL_DOMAIN"]):
        raise CtlError(problem)
    aliases[args.public] = args.backend


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


# command -> (handler, arguments); a handler edits the registries in place and returns text to print after the reload
COMMANDS = {
    "init": (_join_code, []),
    "add": (_add, ["host", "hash"]),
    "revoke": (_revoke, ["host"]),
    "alias": (_alias, ["public", "backend"]),
    "unalias": (_unalias, ["public"]),
    "list": (_list, []),
    "join-code": (_join_code, []),
}


def _registry(call, path, *args):
    try:
        return call(path, *args)
    except RegistryError as e:
        raise CtlError(f"{path}: {e}") from e


def _run(args) -> None:
    if args.command == "init":
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
        if args.command == "init":
            _init(env)
            env = dotenv_values(ENV)
        hosts = _registry(read_hosts, STATE / "hosts")
        aliases = _registry(read_aliases, STATE / "aliases", domain)
        old_hosts = dict(hosts)
        old_aliases = dict(aliases)
        out = COMMANDS[args.command][0](args, hosts, aliases, env)
        if hosts != old_hosts:
            _registry(write_hosts, STATE / "hosts", hosts)
        if aliases != old_aliases:
            _registry(write_aliases, STATE / "aliases", aliases, domain)
        if out:
            print(out)  # after the write, which may fail; before the reload, which may too
        try:
            atomic_write(GENERATED, render_compose(hosts, aliases, domain).encode(), 0o644)
            compose.compose_up_plugin(Path.cwd())
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            updated = "the registry is updated but " if (hosts, aliases) != (old_hosts, old_aliases) else ""
            raise CtlError(f"{updated}the plugin was not reloaded ({e}); rerun any ctl command to retry") from e


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ctl", description="Manage the reverse-tunnel bridge.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, (_, arguments) in COMMANDS.items():
        subparser = subparsers.add_parser(name)
        for argument in arguments:
            subparser.add_argument(argument)
    try:
        _run(parser.parse_args(argv))
    except (CtlError, OSError) as e:
        print(f"ctl: {e}", file=sys.stderr)
        return 1
    return 0
