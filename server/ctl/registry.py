import contextlib
import fcntl
import os
import re
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from ctl.names import allowed_names, valid_label

_HASH = re.compile(r"sha256:[0-9a-f]{64}")


class RegistryError(Exception):
    def __init__(self, line_no: int, msg: str):
        super().__init__(f"line {line_no}: {msg}")
        self.line_no = line_no


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Replace `path` with `data` at `mode`: temp file beside it, fsync, rename, fsync the directory."""
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as f:
        try:
            os.fchmod(f.fileno(), mode)  # before the data lands, and independent of the umask
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


def _write(path: Path, entries: dict[str, str]) -> None:
    lines = "".join(f"{key} {value}\n" for key, value in sorted(entries.items()))
    atomic_write(path, lines.encode(), 0o644)


def _is_hostname(labels: list[str]) -> bool:
    """Whether the labels name a host an ACME CA can issue for: not a bare label, not an IP-like all-digit TLD."""
    return len(labels) >= 2 and all(valid_label(label) for label in labels) and not labels[-1].isdigit()


def read_hosts(path: Path) -> dict[str, str]:
    def problem(host: str, digest: str) -> str | None:
        if not valid_label(host):
            return f"invalid host name {host!r}"
        if not _HASH.fullmatch(digest):
            return f"invalid hash {digest!r}"
        return None

    return _read(path, problem)


def write_hosts(path: Path, hosts: dict[str, str]) -> None:
    _write(path, hosts)


def read_aliases(path: Path, domain: str) -> dict[str, str]:
    """Read `<public> <backend>` lines; `domain` is the tunnel domain the backends must lie under."""

    def problem(public: str, backend: str) -> str | None:
        labels = public.split(".")
        if not _is_hostname(labels) or len(public) > 253:
            return f"invalid public name {public!r}"
        if public == domain or public.endswith(f".{domain}"):
            return f"public name {public!r} is under the tunnel domain"
        host = backend.removesuffix(f".{domain}").rsplit(".", 1)[-1]
        if not allowed_names(host, domain)(backend):
            return f"backend {backend!r} is not a name under the tunnel domain"
        return None

    return _read(path, problem)


def write_aliases(path: Path, aliases: dict[str, str]) -> None:
    _write(path, aliases)
