import contextlib
import fcntl
import io
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scanner import ScannerError

from ctl.joincode import is_token_hash
from ctl.names import alias_problem, valid_label


class RegistryError(Exception):
    def __init__(self, line_no: int | None, msg: str):
        super().__init__(msg if line_no is None else f"line {line_no}: {msg}")
        self.line_no = line_no


def atomic_write(path: Path, data: bytes, mode: int, *, exclusive: bool = False) -> None:
    """Durably replace `path` with `data` at `mode`; with `exclusive`, raise FileExistsError instead if it exists."""
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as f:
        try:
            os.fchmod(f.fileno(), mode)  # independent of the umask
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            if exclusive:
                os.link(f.name, path)
                os.unlink(f.name)
            else:
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


def _yaml() -> YAML:
    """A round-trip, YAML 1.2 loader and dumper; one per call, since an instance is not thread-safe."""
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 2**31  # an entry is never wrapped onto a second line
    yaml.emitter.MAX_SIMPLE_KEY_LENGTH = 1024  # nor a long name turned into a `? key` / `: value` pair
    return yaml


def _load(text: str) -> CommentedMap:
    """The registry's YAML, comments and all; an empty document or one of only comments becomes an empty mapping."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")  # so a rewrite is LF throughout
    yaml = _yaml()
    try:
        doc = yaml.load(text)
        if doc is None:
            doc = yaml.load(text + "\n{}\n")  # the comments stay with the mapping
    except Exception as e:  # ruamel raises more than YAMLError: ValueError, TypeError, RecursionError
        mark = getattr(e, "problem_mark", None)
        if isinstance(e, ScannerError):
            mark = e.context_mark or mark  # where the broken key or string starts, not where the scanner gave up
        line_no = mark.line + 1 if mark else text.count("\n", 0, getattr(e, "position", 0)) + 1
        raise RegistryError(line_no, getattr(e, "problem", None) or str(e)) from e
    if not isinstance(doc, CommentedMap):
        raise RegistryError(1, "expected a mapping of names to values")
    doc.fa.set_block_style()
    return doc


def _problem(key, value, problem: Callable[[str, str], str | None]) -> str | None:
    if not isinstance(key, str):
        return f"key {key!r} is not a string: put it in quotes"
    if not isinstance(value, str):
        return f"{key}: the value is a {type(value).__name__}, not a string: put it in quotes"
    return problem(key, value)


def _read(path: Path, problem: Callable[[str, str], str | None]) -> CommentedMap:
    doc = _load(path.read_bytes().decode("utf-8-sig", errors="replace"))
    if doc.merge:
        raise RegistryError(doc.merge[0].lc.line + 1, "merge keys (<<) are not allowed: give each entry its own line")
    for key, value in doc.items():
        if msg := _problem(key, value, problem):
            raise RegistryError(doc.lc.key(key)[0] + 1, msg)
    return doc


def _write(path: Path, doc: dict, problem: Callable[[str, str], str | None]) -> None:
    for key, value in doc.items():
        if msg := _problem(key, value, problem):
            raise RegistryError(None, f"{key}: {msg}")
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        data = b""
    try:
        data.decode("utf-8-sig")  # the reader replaced bad bytes, which a rewrite would keep replaced
    except UnicodeDecodeError as e:
        line_no = data.count(b"\n", 0, e.start) + 1
        raise RegistryError(line_no, "not UTF-8; fix it by hand before ctl rewrites the file") from e
    out = io.StringIO()
    _yaml().dump(doc, out)
    atomic_write(path, out.getvalue().encode(), 0o644)


def put(doc: CommentedMap, key: str, value: str) -> None:
    """Set `doc[key]`; a new key goes before the first key that sorts after it, beside the comments already there."""
    if key in doc:
        doc[key] = value
        return
    position = next((i for i, existing in enumerate(doc) if existing > key), len(doc))
    doc.insert(position, key, value)


def _host_problem(host: str, digest: str) -> str | None:
    if not valid_label(host):
        return f"invalid host name {host!r}"
    if not is_token_hash(digest):
        return f"invalid hash {digest!r}"
    return None


def read_hosts(path: Path) -> CommentedMap:
    return _read(path, _host_problem)


def write_hosts(path: Path, hosts: dict[str, str]) -> None:
    """Write `hosts`, a mapping from `read_hosts` edited in place (a plain dict is written in its order)."""
    _write(path, hosts, _host_problem)


def read_aliases(path: Path, domain: str) -> CommentedMap:
    """Read `<public>: <backend>` entries; `domain` is the tunnel domain the backends must lie under."""
    return _read(path, lambda public, backend: alias_problem(public, backend, domain))


def write_aliases(path: Path, aliases: dict[str, str], domain: str) -> None:
    _write(path, aliases, lambda public, backend: alias_problem(public, backend, domain))
