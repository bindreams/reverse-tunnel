import contextlib
import fcntl
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from ctl.joincode import is_token_hash
from ctl.names import alias_problem, valid_label


class RegistryError(Exception):
    def __init__(self, line_no: int, msg: str):
        super().__init__(f"line {line_no}: {msg}")
        self.line_no = line_no


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Durably replace `path` with `data` at `mode`."""
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as f:
        try:
            os.fchmod(f.fileno(), mode)  # independent of the umask
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            os.replace(f.name, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(f.name)
            raise
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _open_lock(path: Path) -> int:
    """Open the lock file read-only, first creating it at 0644 if missing: linked into place, so it never appears
    at another mode, and an existing file (any mode, any owner) is left alone."""
    try:
        return os.open(path, os.O_RDONLY)
    except FileNotFoundError:
        pass
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.") as tmp:
        os.fchmod(tmp.fileno(), 0o644)
        with contextlib.suppress(FileExistsError):
            os.link(tmp.name, path)
    return os.open(path, os.O_RDONLY)


@contextmanager
def locked(state_dir: Path) -> Iterator[None]:
    """Hold the exclusive state lock, waiting for as long as another holder keeps it."""
    fd = _open_lock(state_dir / "lock")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _read(path: Path, problem: Callable[[str, str], str | None]) -> dict[str, str]:
    entries = {}
    text = path.read_bytes().decode("utf-8-sig", errors="replace")
    for line_no, line in enumerate(text.split("\n"), 1):
        line = line.strip(" \t\r\n")
        if not line or line.startswith("#"):
            continue
        fields = re.split(r"[ \t]+", line)
        if len(fields) != 2:
            raise RegistryError(line_no, "expected two fields")
        key, value = fields
        if msg := problem(key, value):
            raise RegistryError(line_no, msg)
        if key in entries:
            raise RegistryError(line_no, f"duplicate entry {key}")
        entries[key] = value
    return entries


def _write(path: Path, entries: dict[str, str], problem: Callable[[str, str], str | None]) -> None:
    lines = []
    for line_no, (key, value) in enumerate(sorted(entries.items()), 1):
        if msg := problem(key, value):
            raise RegistryError(line_no, msg)
        lines.append(f"{key} {value}\n")
    atomic_write(path, "".join(lines).encode(), 0o644)


def _host_problem(host: str, digest: str) -> str | None:
    if not valid_label(host):
        return f"invalid host name {host!r}"
    if not is_token_hash(digest):
        return f"invalid hash {digest!r}"
    return None


def read_hosts(path: Path) -> dict[str, str]:
    return _read(path, _host_problem)


def write_hosts(path: Path, hosts: dict[str, str]) -> None:
    _write(path, hosts, _host_problem)


def read_aliases(path: Path, domain: str) -> dict[str, str]:
    """Read `<public> <backend>` lines; `domain` is the tunnel domain the backends must lie under."""
    return _read(path, lambda public, backend: alias_problem(public, backend, domain))


def write_aliases(path: Path, aliases: dict[str, str], domain: str) -> None:
    _write(path, aliases, lambda public, backend: alias_problem(public, backend, domain))
