# reverse-tunnel

Reach machines behind NAT through a bridge you run. Each host keeps one outbound connection to the bridge, with no
inbound ports on the host. Its SSH and HTTP services become reachable at `<service>.<host>.<tunnel domain>`: SSH
through a WebSocket proxy, HTTP in a browser. The bridge is a server running frps, Traefik and a small plugin that
lets in only registered hosts; see [server/README.md](server/README.md) to run one.

Below, `T` is the bridge's tunnel domain (for example `tunnel.binarydreams.me`), and the bridge folder is `server/`
of this repository on the bridge's server.

## Set up a host

You need the bridge's **join code**: in the bridge folder, `uv run ctl join-code` prints it. It is the same for every
host.

On RHEL and Fedora, `sudo` does not look in `/usr/local/bin`, so `sudo reverse-tunnel` is "command not found": there,
write `sudo /usr/local/bin/reverse-tunnel` wherever this README says `sudo reverse-tunnel`.

**Linux** (with systemd) and **macOS**: download the binary for your system, then install.

```sh
# Linux, x86_64 or aarch64
curl -fL -o reverse-tunnel "https://github.com/bindreams/reverse-tunnel/releases/latest/download/reverse-tunnel-$(uname -m)-unknown-linux-gnu"
# macOS, Apple silicon
curl -fL -o reverse-tunnel https://github.com/bindreams/reverse-tunnel/releases/latest/download/reverse-tunnel-aarch64-apple-darwin
# macOS, Intel
curl -fL -o reverse-tunnel https://github.com/bindreams/reverse-tunnel/releases/latest/download/reverse-tunnel-x86_64-apple-darwin
```

```sh
chmod +x reverse-tunnel
sudo ./reverse-tunnel install
```

`install` asks for the join code (paste it, press Enter; or pass it as `--join CODE`) and names the host after the
machine (lowercased); to choose a name, add `--host NAME`. A host with a `config.yaml` keeps its name, and `--host` with
another name fails; to rename, uninstall and install again, register the new name and revoke the old. It installs and starts the service, and prints a line:

```
Register this host on the bridge by running:
    uv run ctl add mothership sha256:...
```

Run that line in the bridge folder. Until you do, the host is refused ("host not registered" in its `frpc.log`) and
retries on its own; once you have, it connects with no restart. You may delete the downloaded file; `install` put a
copy in place and linked it as `reverse-tunnel` on the `PATH`.

By default the host publishes SSH (port 22): the host is reachable at `<host>.T`. `install` is safe to run again; it
changes only what differs.

**Windows**: download the binary, then run `install` and the other commands that say `sudo` from an elevated prompt, without
`sudo`. The service runs as `NT SERVICE\reverse-tunnel`, the host's files are in `%ProgramFiles%\reverse-tunnel` and
`%ProgramData%\reverse-tunnel`, and `install` puts `%ProgramFiles%\reverse-tunnel` on the system `PATH`: open a new shell
to run `reverse-tunnel` (on the desktop, sign out and in; an SSH session sees it at once). `install` edits the `PATH` as
every installer does, by reading it and writing it back: another program that edits it at the same moment can lose one of
the two edits, and running that program's installer again restores its entry. `install` refuses a Program Files folder
whose path contains `%`, which Windows reads as a variable in the commands that finish `uninstall` and in the system
`PATH`. `restart` and `install` check `config.yaml` as the caller, not as the service account. `upgrade` is not available
yet: to change the binary, uninstall and install again.

```powershell
Invoke-WebRequest -Uri https://github.com/bindreams/reverse-tunnel/releases/latest/download/reverse-tunnel-x86_64-pc-windows-msvc.exe -OutFile reverse-tunnel.exe
.\reverse-tunnel.exe install
```

## Set up a client

Clients need [websocat](https://github.com/vi/websocat) on their `PATH`: a binary from its
[releases](https://github.com/vi/websocat/releases), `brew install websocat`, or `cargo install websocat`. Then add
this to `~/.ssh/config`, with the host's name in place of `mothership` and the tunnel domain in place of
`tunnel.binarydreams.me`:

```ssh-config
Host mothership
    HostName mothership.tunnel.binarydreams.me
    ProxyCommand websocat --binary wss://%h/
```

`ssh mothership` now reaches the host's sshd. Any other TCP service the host publishes (`type: tcp`, below) is
reached the same way, at its own `<service>.<host>.T`.

## Publish another service

Services are listed in the host's `config.yaml`. `install` writes it with SSH:

```yaml
host: mothership
bridge: tunnel.binarydreams.me
default: ssh
services:
  ssh:
    port: 22
    type: tcp
```

Add a service under `services:`, with its local port and a `type`: `http` for a web service, which a browser reaches,
or `tcp` for anything else, which needs websocat on the connecting side. A service `jellyfin` on this host is
published at `jellyfin.<host>.T`; the `default` service also at `<host>.T`.

```yaml
  jellyfin:
    port: 8096
    type: http
```

Edit `config.yaml`, then `sudo reverse-tunnel restart`: it checks the file first, as the service's account, and works
over the tunnel. The service's account is `reverse-tunnel` on Linux and `_reverse-tunnel` on macOS. That account must
be able to read each file the service reads and search (`x`) each directory above it, as owner, primary group, an ACL
entry for it, or everyone; access only through another group makes `restart` refuse a configuration that works.

To give an `http` service a public name, run this in the bridge folder; the public name must not be under `T`, its DNS
must point at the server that runs the bridge's Traefik, and Traefik's `letsencrypt` resolver (DNS-01; see
[server/README.md](server/README.md)) must be able to answer the public name's challenge, to issue its certificate:
either it can write the public name's zone, or that zone delegates `_acme-challenge.<public name>` by CNAME to one it
can.

```sh
uv run ctl alias movies.binarydreams.me jellyfin.mothership.tunnel.binarydreams.me
```

`uv run ctl unalias <public name>` removes it, and `uv run ctl list` shows the hosts and aliases.

### Jellyfin

Jellyfin builds absolute links from the request, and behind the tunnel it sees the wrong address. In Jellyfin's
environment set the address people use:

```
JELLYFIN_PublishedServerUrl=https://movies.binarydreams.me
```

The bridge always forwards `X-Forwarded-Proto: http`, even over HTTPS, so Jellyfin does not take its scheme from it.
Jellyfin also sees every viewer connect from frpc, so it counts them as local. To make it count them as remote, list
the two proxies in `KnownProxies` (Dashboard, Networking, "Known proxies"; or `network.xml`): the address frpc
connects to Jellyfin from (`127.0.0.1` when both run on the host directly, the Docker gateway address when Jellyfin
is in a container), and Traefik's address on the bridge's `gateway` Docker network. List only these two addresses, not
the whole subnet: Jellyfin trusts what a listed proxy puts in `X-Forwarded-For`, and every other container on `gateway`
could set it. Docker may give Traefik another address when it restarts, and another container could then get the old
one, so pin Traefik's: a static `ipv4_address` on `gateway` in Traefik's compose file. That needs `gateway` to have a
configured subnet (`docker network inspect gateway` lists it under `IPAM.Config`); a network made without one has to
be recreated with `--subnet`. Jellyfin then reads the viewer's address from `X-Forwarded-For`.

## Operate a host

| Command | What it does |
|---|---|
| `reverse-tunnel status` | What the service is doing, the host name, the tunnel domain, and which bridge it trusts: one `certificate:` line per certificate in `bridge.pem`, two during a rotation. No `sudo`. |
| `sudo reverse-tunnel stop` | Stops the service; it starts again at boot. Over the tunnel it ends your session. |
| `sudo reverse-tunnel start` | Starts the service; it reads `config.yaml` when it starts. |
| `sudo reverse-tunnel restart` | Checks `config.yaml` as the service's account, then restarts the service so it reads it again. Works over the tunnel. |
| `sudo reverse-tunnel upgrade` | Downloads the latest release, checks it against the release's `SHA256SUMS`, and installs it. |
| `sudo reverse-tunnel uninstall` | Removes the service, its files and its account. |

A host replaces `bridge.pem` only when `install` runs with a join code, so after a rotation it keeps both
certificates, and trusts the retired one, until it is reinstalled with a join code that has only the new one; the steps
to run are in [server/README.md](server/README.md#rotating-the-certificate).

`status` prints, for example:

```
service: running (pid 1234), enabled at boot
host: mothership
bridge: tunnel.binarydreams.me
certificate: SHA-256 AB:CD:...
```

The files:

| | Linux | macOS |
|---|---|---|
| `config.yaml`, `bridge.pem` | `/etc/reverse-tunnel/` | `/Library/Application Support/reverse-tunnel/` |
| Logs | `/var/log/reverse-tunnel/` | `/Library/Logs/reverse-tunnel/` |
| Binary, frpc | `/usr/local/lib/reverse-tunnel/` | `/usr/local/lib/reverse-tunnel/` |

The service creates its logs under the service manager's umask (022 by default, set by systemd's `UMask=` or launchd's
`Umask`), so anyone on the machine can read them, for example `less /var/log/reverse-tunnel/frpc.log` on Linux or
`less /Library/Logs/reverse-tunnel/frpc.log` on macOS; where that umask is stricter, read them with `sudo`.
`frpc.log` is the tunnel's: `login to server success` means the host is connected, and a refusal says why ("host not
registered", "token mismatch"). `supervisor.log` is the service's own, with one local time stamp per line. Each log is
rotated at 10 MB to `<name>.1`, replacing the previous one.

### Upgrade

`sudo reverse-tunnel upgrade` replaces the binary and restarts the service, and it works over the tunnel: your session
ends when the service restarts, and the host reconnects on the new version. Before it replaces anything it checks the
new version against this host's settings, and a failure leaves the old version running. It prints the registration
line again; the host is already registered, so ignore it. A version that passes the check and cannot carry SSH locks a
tunnel-only host out until someone is at the machine.

### Uninstall

`sudo reverse-tunnel uninstall` (on Windows, see below) prints the line to run in the bridge folder,
`uv run ctl revoke <host>`, then removes everything, and prints "Removed." The removal continues if your session ends.
Revoking does not cut the host's current connection; `ctl revoke` prints the command that does.

**Windows**: `uninstall` also takes `%ProgramFiles%\reverse-tunnel` off the system `PATH`. `uninstall` refuses to run in
a shell whose working directory is inside a folder it deletes: change to another directory first. A removal that cannot
delete a running file (the binary, say) moves it to `%ProgramFiles%\.reverse-tunnel.*` and deletes it once it has
exited; after a failed removal those files are deleted by the next successful one. The task deletes itself from Task
Scheduler, but its `cmd.exe`, running as SYSTEM, stays until those files have exited and been deleted, then ends. A
failed removal's message says why and names the command to finish it; its log is
`%ProgramFiles%\reverse-tunnel-uninstall\uninstall.log`. A process that keeps one of the files `install` or `uninstall`
deletes open without letting others delete it (an antivirus scan, a program that watches files, a shell whose working
directory is in the install folder) makes them wait until it closes the file: they print one line that names the file,
or the folder that holds it, and go on by themselves when it is closed. `install` prints the line on the console, and so
does `uninstall` when the folder an earlier removal left, `%ProgramFiles%\reverse-tunnel-uninstall`, is held; a line
about the install folder is in the removal log, whose path `uninstall` prints. The removal that `uninstall` starts waits
for that folder the same way and prints nothing: if it does not finish, look for a process that holds a file in that
folder (one that runs a file from it holds it as long as it runs) and stop it.

- On Linux and macOS, if the removal is stopped while it runs (`systemctl stop` on its `reverse-tunnel-uninstall-*`
  unit, or a shutdown), `uninstall` may still print "Removed."; run `sudo reverse-tunnel uninstall` again to finish it.
  A partial removal may have deleted the `reverse-tunnel` link on the `PATH`: then run it through the installed binary,
  `sudo /usr/local/lib/reverse-tunnel/reverse-tunnel uninstall`, or with any other `reverse-tunnel` binary, such as the
  one you downloaded, if you kept it. If neither the link, the installed binary nor the download is left, download the
  binary again with the commands in "Set up a host", and run `sudo ./reverse-tunnel uninstall` with it.
- On Linux a failed removal's output is in the journal (`journalctl -u 'reverse-tunnel-uninstall-*'`); on a host whose
  journal is not persistent it is lost at reboot, and rerunning `uninstall` shows it again. On macOS it is
  `/Library/Logs/reverse-tunnel/uninstall.log`.
