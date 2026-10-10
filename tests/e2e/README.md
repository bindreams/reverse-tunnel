# End-to-end tests

These start containers and publish ports, so they run only in a throwaway Linux VM or on CI, never on a development machine. Each test fails unless `RT_E2E_SANDBOX=1` is set and Docker answers `docker info`.

| Directory | Covers                                                                                           |
| --------- | ------------------------------------------------------------------------------------------------ |
| `bridge/` | The frps image, the compose stack, `ctl` install and uninstall, and the data path under 3 fronts |

The helpers shared with other end-to-end directories live beside this file:

- `logwait.py`: `LineTail`, the only way a test waits. It blocks on a log line, never on the clock; `after=` is mandatory.
- `echo_target.py`: a TCP echo server standing in for sshd.
- `pki.py`: a throwaway CA, with a `STAGING` intermediate, for the TLS fronts.
- `pinned.py`: frpc, frps and websocat from `binaries.lock.toml`, fetched and verified by `ctl`'s own downloader (it needs the network).

In a throwaway VM with Docker, Compose and `uv` installed (for example `orb create ubuntu <name>`; `orb delete <name>` afterwards), copy the repository in rather than mounting it, then:

```sh
RT_E2E_SANDBOX=1 uv run pytest tests/unit tests/e2e/bridge
```

There is no per-test timeout: a line that never arrives blocks until the CI job's own limit.
