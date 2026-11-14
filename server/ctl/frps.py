"""Asks frps's admin API which hosts are online. Run inside the plugin container, `python -m ctl.frps`: the API is
reachable only on the bridge's Docker network. Prints a JSON object, host name to the epoch second its session began."""

import base64
import json
import os
import sys
import urllib.request

# `webServer` in etc/frps.toml, and the frps service's name in compose.yaml.
API = "http://reverse-tunnel-frps:7500"
ANSWER_WITHIN = 10  # seconds; a failure bound for the request, not a synchronisation


def online(clients: list[dict]) -> dict[str, int]:
    """Each host with a session open, to when it began: the earliest, if the host has more than one."""
    since: dict[str, int] = {}
    for client in clients:
        if client["online"]:
            since[client["user"]] = min(client["lastConnectedAt"], since.get(client["user"], client["lastConnectedAt"]))
    return since


def fetch(user: str, password: str) -> list[dict]:
    request = urllib.request.Request(f"{API}/api/clients")
    request.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode())
    with urllib.request.urlopen(request, timeout=ANSWER_WITHIN) as response:
        return json.load(response)


def main() -> int:
    try:
        user, password = os.environ["FRPS_API_USER"], os.environ["FRPS_API_PASSWORD"]
    except KeyError as e:
        print(f"{e.args[0]} is not set: run `uv run ctl init`", file=sys.stderr)
        return 1
    try:
        since = online(fetch(user, password))
    except (OSError, ValueError, KeyError) as e:
        print(f"frps's API gave no usable answer at {API}: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(since))
    return 0


if __name__ == "__main__":
    sys.exit(main())
