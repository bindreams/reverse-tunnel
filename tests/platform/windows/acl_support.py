"""Reading and comparing ACLs, shared by the Windows platform tests."""

import subprocess
from collections.abc import Callable
from pathlib import Path

from ctl import _winfile as winfile
from ctl import perms_windows, winacl
from ctl.perms import SID_LOCAL_SERVICE

OBJECT_INHERIT_ACE = winacl.OBJECT_INHERIT_ACE
CONTAINER_INHERIT_ACE = winacl.CONTAINER_INHERIT_ACE
INHERIT_ONLY_ACE = winacl.INHERIT_ONLY_ACE
INHERITED_ACE = winacl.INHERITED_ACE
INHERITING = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE

Shape = set[tuple[str, int, int]]  # (sid, mask, flags)


def icacls(*arguments: str) -> None:
    subprocess.run(["icacls", *arguments], check=True, capture_output=True)


def whole_entries(path: Path) -> tuple[list[winacl.Entry], bool]:
    """Every ACE of `path` in stored order, inherit-only ones included, and whether its inheritance is broken."""
    with perms_windows._handle(path, directory=path.is_dir(), access=winfile.READ_CONTROL) as handle:
        return winacl.read_entries(handle)


def entries_of(path: Path) -> list[winacl.Entry]:
    return whole_entries(path)[0]


def snapshot(*paths: Path) -> dict[Path, tuple[list[winacl.Entry], bool]]:
    """`whole_entries` of each path and, for a directory, of everything under it."""
    found = {}
    for top in paths:
        for path in [top, *(top.rglob("*") if top.is_dir() else [])]:
            found[path] = whole_entries(path)
    return found


def shape_of(path: Path) -> tuple[Shape, bool]:
    """The ACEs of `path` as (sid, mask, flags), and whether its inheritance is broken."""
    entries, protected = whole_entries(path)
    return {(e.sid, e.mask, e.flags) for e in entries}, protected


def owned_shape(root: Path, service_mask: int, flags: int) -> Shape:
    """The ACEs install gives a directory it owns (`flags`: its own inheritance) or a file in it (`INHERITED_ACE`)."""
    return {
        (winacl.SID_ADMINISTRATORS, winacl.FULL, flags),
        (perms_windows.operator_sid(root), winacl.FULL, flags),
        (SID_LOCAL_SERVICE, service_mask, flags),
    }


def after_each_write(monkeypatch, observe: Callable[[], object]) -> list:
    """Call `observe()` after every `winacl.set_dacl` and collect what it returns."""
    real = winacl.set_dacl
    seen = []

    def recording(handle, entries, *, protected):
        real(handle, entries, protected=protected)
        seen.append(observe())

    monkeypatch.setattr(winacl, "set_dacl", recording)
    return seen
