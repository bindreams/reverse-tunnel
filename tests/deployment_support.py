"""Deployment trees for the install tests: a `.env` built from the shipped example, written the way a user leaves it."""

from pathlib import Path

from ctl.config import Config, Role
from ctl.env import read

REPO_ROOT = Path(__file__).resolve().parent.parent
GOOD_TOKEN = "0123456789abcdef" * 4
OTHER_TOKEN = "fedcba9876543210" * 4
GOOD_PASSWORD = "correct-horse-battery_staple"


def write_env(root: Path, role: Role, **overrides: str) -> Config:
    """Write `<root>/.env` (world-readable, as a fresh clone leaves it) for `role` and load it."""
    values = read(REPO_ROOT / "example.env")
    values.update(ROLE=role.value, RT_TOKEN=GOOD_TOKEN, RT_ADMIN_PASSWORD=GOOD_PASSWORD, RT_LABEL="alpha")
    values.update(overrides)
    path = root / ".env"
    path.write_bytes("".join(f"{key}={value}\n" for key, value in values.items()).encode())
    path.chmod(0o644)
    return Config.load(root)


def tree(root: Path) -> dict[str, str]:
    """Every path under `root`, relative and `/`-separated, mapped to its kind; links are listed, never followed."""
    kinds: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        kind = "link" if path.is_symlink() else "dir" if path.is_dir() else "file"
        kinds[path.relative_to(root).as_posix()] = kind
    return kinds
