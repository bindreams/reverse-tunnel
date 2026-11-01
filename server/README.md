# reverse-tunnel bridge

The server side of reverse-tunnel: `frps` accepts one QUIC connection per host, and a small plugin lets in only
registered hosts and only their own names. Traefik, already running on the Docker network `gateway`, serves the public
side. Hosts are set up with the `reverse-tunnel` binary from the main repository.

Needs Docker with Compose, [uv](https://docs.astral.sh/uv/), and on `gateway` a Traefik that selects containers with
`traefik.expose=true`, has the entrypoint `websecure`, and has a `letsencrypt` resolver using the DNS-01 challenge
(host certificates are wildcards).

## Bring-up

All commands run in this folder.

1. DNS: `tunnel.binarydreams.me` (your tunnel domain, `T` below) and `*.T` point at this server. Open `7000/tcp` and
   `7000/udp` in its firewall.
2. `cp .env.example .env`, and set `TUNNEL_DOMAIN` if it is not `tunnel.binarydreams.me`.
3. `uv run ctl init` checks the network and DNS, creates the token, the certificate (`tls/`) and the registries
   (`state/`), and prints the join code. `uv run ctl join-code` prints it again.
4. `docker compose up -d --build`.

Joining a host and publishing a service: see the main README. The commands are `uv run ctl add`, `revoke`, `alias`,
`unalias`, `list`.

## Verify

- `docker compose ps` lists `reverse-tunnel-frps` and `reverse-tunnel-plugin` running.
- `docker compose logs reverse-tunnel-frps` ends with `frps started successfully` and no plugin errors.
- `docker compose config` prints the frps router rule ending in `T$$`.
- A joined host's `reverse-tunnel status` shows a successful login. "host not registered" means `uv run ctl add` has
  not been run for it.

## Teardown

`docker compose down` removes the containers and the private network; `.env`, `tls/` and `state/` stay, so
`docker compose up -d` brings the same bridge back. To remove it for good, delete this folder as well. Hosts then
retry forever; uninstall them with `reverse-tunnel uninstall`.

## Footguns

- Recreating `reverse-tunnel-frps` (`git pull` then `up -d --build`, or `restart`) drops every tunnel once. Hosts
  reconnect on their own.
- Every host trusts the certificate in `tls/trust.pem`. Deleting `tls/` or replacing the certificate outside the
  procedure below locks every host out; `ctl` refuses to regenerate it.
- `tls/frps.key` and `.env` (the shared frps token) are secrets, and so are backups of this folder.
- `compose.generated.yaml` is rewritten by `ctl`; don't edit it. `.env` selects it through `COMPOSE_FILE`.
- The plugin reads `state/` as a directory mount. Don't change it to a file mount: `ctl` replaces files, and a file
  mount keeps pointing at the old one.
- If the plugin is down, connected tunnels keep running, and logins and new names are refused until it is back.
- `ctl revoke` does not cut the host's current session; it prints the command that does.
- frps rewrites `X-Forwarded-Proto` to `http` on every request it forwards.

## Layout

| Path | What |
|---|---|
| `compose.yaml` | `reverse-tunnel-frps` and `reverse-tunnel-plugin`; the frps router is its labels |
| `compose.generated.yaml` | the plugin's labels (certificates and aliases), generated; gitignored |
| `Dockerfile` | target `frps` (the pinned release, checked by SHA-256) and target `plugin` |
| `etc/frps.toml` | frps config; names no host and no service |
| `ctl/`, `pyproject.toml`, `uv.lock` | the plugin and `uv run ctl` |
| `tls/` | `frps.crt`, `frps.key`, and `trust.pem`, the certificates hosts trust; gitignored |
| `state/` | `hosts` and `aliases` registries, the only thing the plugin container mounts; gitignored |
| `.env` | `TUNNEL_DOMAIN`, `FRPS_TOKEN`, `COMPOSE_FILE`; gitignored |

## Rotating the certificate

Hosts verify frps against `bridge.pem`, which may hold several certificates, so a rotation stages the new one and
nobody is locked out.

1. Make the new pair, and trust it first:

   ```sh
   (umask 077; uv run python -c 'import sys; from ctl.certs import make_cert; c, k = make_cert(sys.argv[1]); open("tls/new.crt", "w").write(c); open("tls/new.key", "w").write(k)' tunnel.binarydreams.me)
   cat tls/new.crt >> tls/trust.pem
   ```

2. `uv run ctl join-code`, and re-run `reverse-tunnel install` with the new code on every host (or put the new
   `bridge.pem` on each and restart its service). Do not go on until every host has it.
3. Switch frps: `mv tls/new.key tls/frps.key && mv tls/new.crt tls/frps.crt && chmod 644 tls/frps.crt`, then
   `docker compose restart reverse-tunnel-frps`. Hosts reconnect; check their `status`.
4. Delete the old certificate from `tls/trust.pem`, leaving the new one. New join codes carry only that.
