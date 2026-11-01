import fcntl
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from ctl.names import valid_label

_HASH = re.compile(r"sha256:[0-9a-f]{64}")


class RegistryError(Exception):
    def __init__(self, line_no: int, msg: str):
        super().__init__(f"line {line_no}: {msg}")
        self.line_no = line_no


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Replace `path` with `data` at `mode`: temp file beside it, fsync, rename, fsync the directory."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)  # before the data lands, and independent of the umask
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


@contextmanager
def locked(state_dir: Path) -> Iterator[None]:
    """Hold the exclusive state lock, waiting for as long as another holder keeps it."""
    with open(state_dir / "lock", "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def _read(path: Path, problem: Callable[[str, str], str | None]) -> dict[str, str]:
    entries = {}
    text = path.read_bytes().decode("utf-8-sig", errors="replace")
    for line_no, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2:
            raise RegistryError(line_no, "expected two fields")
        key, value = fields
        if msg := problem(key, value):
            raise RegistryError(line_no, msg)
        if key in entries:
            raise RegistryError(line_no, f"duplicate entry {key}")
        entries[key] = value
    return entries


def _write(path: Path, entries: dict[str, str]) -> None:
    lines = "".join(f"{key} {value}\n" for key, value in sorted(entries.items()))
    atomic_write(path, lines.encode(), 0o644)


def _is_backend(name: str, domain: str) -> bool:
    """Whether `name` is `host.domain` or `label.host.domain`."""
    labels = name.removesuffix(f".{domain}").split(".")
    return name.endswith(f".{domain}") and len(labels) <= 2 and all(valid_label(label) for label in labels)


def read_hosts(path: Path) -> dict[str, str]:
    def problem(host: str, digest: str) -> str | None:
        if not valid_label(host):
            return f"invalid host name {host!r}"
        if not _HASH.fullmatch(digest):
            return f"invalid hash {digest!r}"

    return _read(path, problem)


def write_hosts(path: Path, hosts: dict[str, str]) -> None:
    _write(path, hosts)


def read_aliases(path: Path, domain: str) -> dict[str, str]:
    """Read `<public> <backend>` lines; `domain` is the tunnel domain the backends must lie under."""

    def problem(public: str, backend: str) -> str | None:
        labels = public.split(".")
        if not all(valid_label(label) for label in labels) or len(public) > 253:
            return f"invalid public name {public!r}"
        if public == domain or public.endswith(f".{domain}"):
            return f"public name {public!r} is under the tunnel domain"
        if not _is_backend(backend, domain):
            return f"backend {backend!r} is not a name under the tunnel domain"

    return _read(path, problem)


def write_aliases(path: Path, aliases: dict[str, str]) -> None:
    _write(path, aliases)
