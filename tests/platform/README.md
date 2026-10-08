# Platform tests

Tests that only mean something on one operating system live in a directory for it, so no test uses `skipif`.

| Directory  | Runs on         | Notes                                                  |
| ---------- | --------------- | ------------------------------------------------------ |
| `posix/`   | Linux and macOS | `-m "not root"` opts out of the tests that need uid 0. |
| `windows/` | Windows         |                                                        |

- A bare `pytest` collects `tests/unit` plus this OS's directory; `conftest.py` at the repository root ignores the other.
- Each CI job runs its directory by path. An empty collection is exit code 5, so a renamed or emptied directory turns the job red instead of passing quietly.
- A test marked `root` chowns to other accounts, so it fails without uid 0 and never skips. Run it in a throwaway container or on CI, never on a development machine and never under `sudo` there. The machine needs an unprivileged account named `rt-test-svc`; the CI jobs and the container recipe create it.
- A test marked `mount` changes the mount table, so it fails without root and without a private mount namespace (`RT_PRIVATE_MOUNT_NS=1`, set after `unshare --mount --propagation private`) and never skips. It runs in a throwaway container started with `--cap-add SYS_ADMIN`, or in the CI step that wraps pytest in `unshare`. Linux only: the macOS job passes `-m "not mount"`.
