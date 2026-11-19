# reverse-tunnel

Reach machines behind NAT through a bridge you run. Each host keeps one outbound connection to the bridge, with no
inbound ports on the host. Its SSH and HTTP services become reachable at `<service>.<host>.<tunnel domain>`: SSH
through a WebSocket proxy, HTTP in a browser. The bridge is a server running frps, Traefik and a small plugin that
lets in only registered hosts; see [server/README.md](server/README.md) to run one.

Below, `T` is the bridge's tunnel domain, and the bridge folder is `server/` of this repository on the bridge's
server. The names in the examples (`tunnel.example.com`, `myhost`, `yourdomain.tld`) are placeholders: use your own.

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

`install` asks for the host name and the join code, prints where the config is saved, and ends with the line that says
it is installed:

```
$ sudo ./reverse-tunnel install
Setting up a system-wide reverse tunnel service.
  Config is saved to: /etc/reverse-tunnel/config.yaml
Hostname [minicooper]:
Join code (run `uv run ctl join-code` on the bridge; an empty line gives up):
Downloading frpc v0.71.1...
Applying the changes; if you are connected through this tunnel, the connection drops now...
Reverse-tunnel v0.1.1 has been installed!
```

Each step that can take a while, such as the download of frpc, is announced by a line ending in `...` before it starts.
So is applying the changes, by `install`, `upgrade` and `reverse-tunnel restart`: the service is killed for its
service manager to start again, or started if it is not running, and the line says the connection through the tunnel
drops. An `install` that changed nothing says `Starting the service...` only if it finds the service not running. Over
the tunnel the connection drops at the restart, so the lines after the notice may not reach you.

Enter takes the machine's name (its first part, lowercased) as the host name; a name typed is lowercased too. The join
code may be pasted wrapped over several lines. On a host that already has a `config.yaml`, `install` asks no host name
and prints neither the "Setting up" lines nor `Hostname:`; it asks for the join code only if the bridge's files are
missing. A host keeps its name: `--host` with another name fails; to rename, uninstall and install again, accept the
new name and revoke the old.

For a script, pass `--host NAME` and `--join CODE`: a value given is not asked for. `install` asks only if stdin and
stderr are both terminals; otherwise a value that is needed and missing is an error that names the flags and gives the
command to run, and `install` does not wait for input. It installs and starts the service.

Register the host on the bridge: in the bridge folder run `uv run ctl add HOST HASH`, with the `host` and `hash` that
`reverse-tunnel status` shows (the hash is no secret; the token it comes from is never shown). The
`hash` is what `install` last recorded, so a token you replaced by hand shows its old hash until `install` runs again.
[Set up a client](#set-up-a-client) is the next step. Until you register it, the host is refused ("host not
registered" in its `frpc.log`) and retries on its own; once you have, it connects with no restart. A host installed
by an earlier version has no `hash` yet: `status` says so, and the next `install` or `upgrade` records it. You may
delete the downloaded file; `install` put a copy in place and linked it as `reverse-tunnel` on the `PATH`.

By default the host publishes SSH (port 22): the host is reachable at `<host>.T`. `install` is safe to run again; it
changes only what differs.

**Windows**: download the binary, then run `install` and the other commands that say `sudo` from an administrator
terminal (right-click Terminal or PowerShell, "Run as administrator"), without `sudo`: Windows' `sudo` opens a new window
that closes before the output can be read. The service runs as `NT SERVICE\reverse-tunnel`, the host's files are in `%ProgramFiles%\reverse-tunnel` and
`%ProgramData%\reverse-tunnel`, and `install` puts `%ProgramFiles%\reverse-tunnel` on the system `PATH`: open a new shell
to run `reverse-tunnel` (on the desktop, sign out and in; an SSH session sees it at once). `install` edits the `PATH` as
every installer does, by reading it and writing it back: another program that edits it at the same moment can lose one of
the two edits, and running that program's installer again restores its entry. `install` and `uninstall` match an entry
only if it equals the folder's full path exactly: one written another way (other case, a trailing backslash,
`%ProgramFiles%`) is not ours, so `install` adds ours beside it and `uninstall` leaves it. `install` refuses a Program
Files folder whose path contains `%`, which Windows reads as a variable in the commands that finish `uninstall` and in
the system `PATH`. `install` and `restart` reset the ACLs of what `run` reads (the binaries, `config.yaml`,
`bridge.pem`, the two token files), the other files in the install folder, and the four folders (install, data,
`secrets`, `logs`) to the ones `install` gives, so a hand edit of them does not outlast either. A deny ACE or a protected
DACL you put by hand on a file inside `logs\` is not reset, and the service then fails to open it: delete the file and
the service makes it again.

```powershell
Invoke-WebRequest -Uri https://github.com/bindreams/reverse-tunnel/releases/latest/download/reverse-tunnel-x86_64-pc-windows-msvc.exe -OutFile reverse-tunnel.exe
.\reverse-tunnel.exe install
```

## Set up a client

Clients need [websocat](https://github.com/vi/websocat) on their `PATH`: a binary from its
[releases](https://github.com/vi/websocat/releases), `brew install websocat`, or `cargo install websocat`. Then add
this to `~/.ssh/config`, with the host's name in place of `myhost` and the tunnel domain in place of
`tunnel.example.com`:

```ssh-config
Host myhost
    HostName ssh.myhost.tunnel.example.com
    ProxyCommand websocat --binary wss://%h/
```

`ssh myhost` now reaches the host's sshd, at its `ssh` service (when it is `type: tcp`, whatever its port). Any other
TCP service the host publishes (`type: tcp`, below) is reached the same way, at its own `<service>.<host>.T`.

## Publish another service

Services are listed in the host's `config.yaml`. `install` writes it with SSH:

```yaml
host: myhost
bridge: tunnel.example.com
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
uv run ctl alias movies.yourdomain.tld jellyfin.myhost.tunnel.example.com
```

`uv run ctl unalias <public name>` removes it, and `uv run ctl list` shows the hosts and aliases, then a `presence` line
per host: `online since` when, `offline` at the bridge, or `unknown` with the reason on stderr.

### Jellyfin

Jellyfin builds absolute links from the request, and behind the tunnel it sees the wrong address. In Jellyfin's
environment set the address people use:

```
JELLYFIN_PublishedServerUrl=https://movies.yourdomain.tld
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
| `reverse-tunnel status` | What the service is doing, the host name, its token's hash (the `hash` for `ctl add`), the tunnel domain, which bridge it trusts (one `certificate:` line per certificate in `bridge.pem`, two during a rotation), and the last 10 lines of `frpc.log`, or `no log yet`; a service that is not running says they are from its last run. No `sudo`. |
| `reverse-tunnel logs` | Prints `frpc.log`, or with `-n N` its last N lines. With `-f`, it starts with the last 10 lines (or N), then keeps showing lines as they are appended, across a rotation, until you interrupt it; it waits for the log if the service has not made it yet. Lines written to a log it never opened (rotated away while its output stalled, or before it found the log) are not shown, as with `tail -F`; `frpc.log.1` may have them. No `sudo`. |
| `sudo reverse-tunnel stop` | Stops the service; it starts again at boot. Over the tunnel it ends your session. |
| `sudo reverse-tunnel start` | Starts the service; it reads `config.yaml` when it starts. |
| `sudo reverse-tunnel restart` | Checks `config.yaml` as the service's account, then says the connection through the tunnel drops and kills the service for its service manager to start again with the new settings, and says so (a service that was not running is started). Works over the tunnel. |
| `sudo reverse-tunnel upgrade` | Downloads the latest release, checks it against the release's `SHA256SUMS`, and installs it. |
| `sudo reverse-tunnel uninstall` | Removes the service, its files and its account. |

A host replaces `bridge.pem` only when `install` runs with a join code, so after a rotation it keeps both
certificates, and trusts the retired one, until it is reinstalled with a join code that has only the new one; the steps
to run are in [server/README.md](server/README.md#rotating-the-certificate).

`status` prints, for example:

```
service: running (pid 1234), enabled at boot
host: myhost
hash: sha256:...
bridge: tunnel.example.com
certificate: SHA-256 AB:CD:...
frpc log (last 10 lines; `reverse-tunnel logs` shows it all):
[...] login to server success, get run id [...]
...
```

`status` does not interpret the log: `login to server success` in it means the host is connected, and a refusal says why
("host not registered", "token mismatch").

The files:

| | Linux | macOS |
|---|---|---|
| `config.yaml`, `bridge.pem` | `/etc/reverse-tunnel/` | `/Library/Application Support/reverse-tunnel/` |
| Logs | `/var/log/reverse-tunnel/` | `/Library/Logs/reverse-tunnel/` |
| Binary, frpc | `/usr/local/lib/reverse-tunnel/` | `/usr/local/lib/reverse-tunnel/` |

Anyone on the machine can read the logs, with `reverse-tunnel logs` or directly (`less /var/log/reverse-tunnel/frpc.log`
on Linux, `less /Library/Logs/reverse-tunnel/frpc.log` on macOS): nothing secret is in them. `frpc.log` is the tunnel's;
`supervisor.log` is the service's own, with one local time stamp per line, and `reverse-tunnel logs` does not show it.
On a host upgraded from v0.1.0, logs it made under a restrictive umask stay readable only by root until they rotate.
Each log is rotated at 10 MB to `<name>.1`, replacing the previous one; `logs` shows only the current file.

### Upgrade

`sudo reverse-tunnel upgrade` replaces the binary and restarts the service, and it works over the tunnel: `install` says,
before it restarts the service, that a connection through this tunnel will drop. Over the tunnel your
session drops at the restart, and that line may not reach you; the host reconnects on the new version, and
`reverse-tunnel status` shows the result once you are back. Before it replaces anything it checks the new version
against this host's settings, and a failure leaves the old version running. It prints a line before the steps that take
a while, then runs `install`, which on a host that is set up asks nothing, and whose output is the
whole of what `upgrade` ends with:

```
$ sudo reverse-tunnel upgrade
Checking for a new version...
Downloading v0.1.1...
Applying the changes; if you are connected through this tunnel, the connection drops now...
Reverse-tunnel v0.1.1 has been installed!
```

A version that passes the check and cannot carry SSH locks a tunnel-only host out until someone is at the machine.

**Windows**: run `reverse-tunnel upgrade` from an elevated prompt, without `sudo`. Windows will not overwrite or delete a
running program, so each build is installed as a file of its own, `%ProgramFiles%\reverse-tunnel\reverse-tunnel-<SHA-256
of the build>.exe`; `install` moves the service onto the new one and the restart runs it. The next `install` or `upgrade`
deletes the earlier builds' files once the processes that run them have exited. The command you ran, on the `PATH`
(`reverse-tunnel.exe`), and the downloaded copy `install` runs from, may be running too: Windows lets a running program
be renamed, so they are renamed to `%ProgramFiles%\.reverse-tunnel.*` and deleted the same way. `uninstall` deletes all
of them.

### Uninstall

`sudo reverse-tunnel uninstall` (on Windows, see below) prints the line to run in the bridge folder,
`uv run ctl revoke <host>`, then removes everything, and prints "Removed." The removal continues if your session ends.
Revoking does not cut the host's current connection; `ctl revoke` prints the command that does.

**Windows**: `uninstall` also takes `%ProgramFiles%\reverse-tunnel` off the system `PATH`. `uninstall` refuses to run in
a shell whose working directory is inside a folder it deletes: change to another directory first. A removal that cannot
delete a running file (the binary, say) moves it to `%ProgramFiles%\.reverse-tunnel.*` and deletes it once it has
exited; after a failed removal those files are deleted by the next successful one. A removal that succeeds also
asks Windows to delete them at the next boot, in case the machine restarts first; if that request fails, the files stay
until deleted by hand. The task deletes itself from Task Scheduler, but its `cmd.exe`, running as SYSTEM, stays until
those files have exited and been deleted, then ends. If the machine restarts before `uninstall` returns,
`%ProgramFiles%\reverse-tunnel-uninstall` and the task `reverse-tunnel-uninstall` may remain; running `uninstall`
again, with any `reverse-tunnel` binary (the installed one may already be gone), removes them. A
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
