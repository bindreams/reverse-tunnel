"""The bridge operator's commands, run as `uv run ctl <command>` in the bridge folder."""

import argparse
import contextlib
import secrets
import socket
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values, set_key

from ctl import certs, compose
from ctl.generate import render_compose
from ctl.joincode import encode_join, is_token_hash
from ctl.names import alias_problem, valid_domain, valid_label
from ctl.registry import RegistryError, atomic_write, locked, read_aliases, read_hosts, write_aliases, write_hosts

STATE, TLS, GENERATED = Path("state"), Path("tls"), Path("compose.generated.yaml")
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
    """Check the deployment and create what is missing; `.env` is changed only for `FRPS_TOKEN` and `COMPOSE_FILE`."""
    domain, crt, key = env["TUNNEL_DOMAIN"], TLS / "frps.crt", TLS / "frps.key"
    if not compose.network_exists("gateway"):
        raise CtlError("docker network 'gateway' does not exist")
    for name in (domain, f"rt-dns-check.rt-dns-check.{domain}"):
        if not resolve(name):
            raise CtlError(f"cannot resolve {name}")
    present = crt.exists() and key.exists()  # a certificate without its key counts as missing
    if present and certs.dns_names(crt.read_bytes()) != [domain]:
        raise CtlError(f"{crt} is not for {domain}; follow the certificate rotation procedure in the README")
    if not env.get("FRPS_TOKEN"):
        set_key(".env", "FRPS_TOKEN", secrets.token_hex(32), quote_mode="never")
    if env.get("COMPOSE_FILE") != COMPOSE_FILE:
        set_key(".env", "COMPOSE_FILE", COMPOSE_FILE, quote_mode="never")
    TLS.mkdir(exist_ok=True)
    if not present:
        cert_pem, key_pem = certs.make_cert(domain)
        atomic_write(key, key_pem.encode(), 0o600)  # the key first: no certificate is ever published without it
        atomic_write(crt, cert_pem.encode(), 0o644)
    _create(TLS / "trust.pem", crt.read_bytes(), 0o644)
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
        raise CtlError("FRPS_TOKEN is not set in .env; run 'ctl init'")
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


def _load(path, read, *args):
    try:
        return read(path, *args)
    except RegistryError as e:
        raise CtlError(f"{path}: {e}") from e


def _run(args) -> str | None:
    if args.command == "init":
        STATE.mkdir(exist_ok=True)
    elif not STATE.is_dir():
        raise CtlError("no state/ here: run from the bridge folder, after 'ctl init'")
    with locked(STATE):
        env = dotenv_values(".env")
        domain = env.get("TUNNEL_DOMAIN")
        if not domain:
            raise CtlError("TUNNEL_DOMAIN is not set in .env")
        if not valid_domain(domain):
            raise CtlError(f"TUNNEL_DOMAIN {domain!r} is not a valid tunnel domain")
        if args.command == "init":
            _init(env)
            env = dotenv_values(".env")
        hosts, aliases = _load(STATE / "hosts", read_hosts), _load(STATE / "aliases", read_aliases, domain)
        before = dict(hosts), dict(aliases)
        out = COMMANDS[args.command][0](args, hosts, aliases, env)
        if hosts != before[0]:
            write_hosts(STATE / "hosts", hosts)
        if aliases != before[1]:
            write_aliases(STATE / "aliases", aliases, domain)
        try:
            atomic_write(GENERATED, render_compose(hosts, aliases, domain).encode(), 0o644)
            compose.compose_up_plugin(Path.cwd())
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            msg = f"the registries are updated but the plugin was not reloaded ({e}); rerun any ctl command to retry"
            raise CtlError(msg) from e
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ctl", description="Manage the reverse-tunnel bridge.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, (_, arguments) in COMMANDS.items():
        subparser = subparsers.add_parser(name)
        for argument in arguments:
            subparser.add_argument(argument)
    try:
        out = _run(parser.parse_args(argv))
    except (CtlError, OSError, ValueError) as e:
        print(f"ctl: {e}", file=sys.stderr)
        return 1
    if out:
        print(out)
    return 0
