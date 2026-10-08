# End-to-end tests

These start containers and publish ports, so they run only in a throwaway Linux VM or on CI, never on a development machine. Each test fails unless `RT_E2E_SANDBOX=1` is set and Docker answers `docker info`.

| Directory | Covers                                        |
| --------- | --------------------------------------------- |
| `bridge/` | The frps image, the compose stack, the checks |

In a throwaway VM with Docker, Compose and `uv` installed (for example `orb create ubuntu <name>`; `orb delete <name>` afterwards), copy the repository in rather than mounting it, then:

```sh
RT_E2E_SANDBOX=1 uv run pytest tests/unit tests/e2e/bridge
```
