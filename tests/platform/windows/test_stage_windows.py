"""`stage` and `apply` on a repository an earlier install left: no interruption strands the service, a rerun converges.

The service's access is judged by `ctl.authz` (see `service_access`). It reads: the repository root, `bin` and every
file in it but the record `.digests.json` (only `ctl` reads that, as the operator), `host` and `host/frpc.toml`,
`secrets/token`, and it writes into `logs`.
"""

import os
import subprocess
from pathlib import Path

import pytest
from tests.platform.windows.service_access import descriptor_of, service_token
from tests.unit.host_support import HostTree, build_host

from ctl import _winfile as winfile
from ctl import binaries, host, perms_windows, winacl
from ctl.download import DIGESTS
from ctl.perms import SID_LOCAL_SERVICE, AccountMode
from ctl.services import Services

OBJECT_INHERIT_ACE = winacl.OBJECT_INHERIT_ACE
INHERIT_ONLY_ACE = winacl.INHERIT_ONLY_ACE
INHERITED_ACE = winacl.INHERITED_ACE
READ_EXECUTE = winacl.READ_EXECUTE

PLATFORM = "windows-x86_64"
# The rights each kind of object is asked for. The service starts `bin/*.exe`, reads its configuration and the token,
# lists the directories on the way, and appends to its logs.
FILE_LIST_DIRECTORY, FILE_ADD_FILE, FILE_WRITE_DATA, FILE_APPEND_DATA = 0x1, 0x2, 0x2, 0x4
FILE_TRAVERSE, FILE_READ_ATTRIBUTES, SYNCHRONIZE = 0x20, 0x80, 0x100000
LIST = FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE
EXECUTE = 0x1 | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE  # FILE_READ_DATA | FILE_EXECUTE
READ = winacl.READ
ADD_TO = LIST | FILE_ADD_FILE
APPEND = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE


class Interrupted(Exception):
    """Stands for a kill, a power loss or Ctrl-C that lands right at one of the events below."""


def acls(root: Path) -> dict[Path, tuple[list[winacl.Entry], bool]]:
    """Every ACE, in stored order, and the inheritance state of `root` and everything under it, by relative path."""
    found = {}
    for path in [root, *root.rglob("*")]:
        with perms_windows._handle(path, directory=path.is_dir(), access=winfile.READ_CONTROL) as handle:
            found[path.relative_to(root)] = winacl.read_entries(handle)
    return found


# A host to install into ===============================================================================================


def build(variant: str, base: Path, monkeypatch) -> HostTree:
    """A repository as the three installs leave it: never installed, installed, and installed by the earlier version.

    The earlier version put an inheritable `(OI)(CI)(RX)` ACE for the service on the repository root.
    """
    base.mkdir()
    tree = build_host(base, monkeypatch, platform=PLATFORM)
    if variant == "installed":
        install(tree)
    elif variant == "earlier":
        tree.write_binaries()
        tree.record()
        (tree.root / "logs").mkdir()
        (tree.root / "logs" / "frpc.log").write_bytes(b"")
        subprocess.run(["icacls", str(tree.root), "/grant", f"*{SID_LOCAL_SERVICE}:(OI)(CI)(RX)"],
                       check=True,
                       capture_output=True)
    return tree


def plan_of(tree: HostTree) -> host.Plan:
    """What `preflight` would decide for a host where every binary is to be replaced and both daemons converged."""
    lock = binaries.load_lock(tree.services.lock_path)
    pins = tuple(tree.pins[f"{name}.exe"] for name in host.HOST_BINARIES)
    return host.Plan(
        binaries_to_replace=tuple(pin.install_name for pin in pins),
        daemons_to_converge=host.IDS,
        mode=AccountMode.SEPARATE,
        platform=PLATFORM,
        pins=pins,
        bundle=binaries.bundle_for(lock, "goetia"),
        installed=(),
        detach=False,
        inputs=host.input_digests(tree.config),
        reasons={daemon_id: "test"
                 for daemon_id in host.IDS},
    )


def install(tree: HostTree) -> None:
    """The install without its preflight and its lock: `stage` then `apply`, with goetia faked."""
    plan = plan_of(tree)
    services: Services = tree.services
    host.stage(tree.config, plan, services=services)
    host.apply(tree.config, plan, services=services)


# What the service needs ===============================================================================================


def needed(root: Path) -> dict[Path, int]:
    """The objects of the install that exist now that the service opens, each with the rights it is asked for."""
    wanted: dict[Path, int] = {Path("."): LIST}
    for directory, access in (("bin", LIST), ("host", LIST), ("secrets", LIST), ("logs", ADD_TO)):
        if (root / directory).is_dir():
            wanted[Path(directory)] = access
    for directory, access in (("bin", EXECUTE), ("logs", APPEND)):
        if (root / directory).is_dir():
            for entry in sorted((root / directory).iterdir()):
                if entry.is_file() and entry.name != DIGESTS:
                    wanted[entry.relative_to(root)] = access
    for name, access in (("host/frpc.toml", READ), ("secrets/token", READ)):
        if (root / name).is_file():
            wanted[Path(name)] = access
    return wanted


def readable(root: Path) -> set[Path]:
    """The relative paths among `needed` that the service is granted, as the kernel decides it."""
    with service_token() as token:
        return {path for path, access in needed(root).items() if token.grants(descriptor_of(root / path), access)}


def service_aces(found: dict[Path, tuple[list[winacl.Entry], bool]], name: str) -> list[tuple[int, int]]:
    """The service's ACEs on the relative path `name` as (mask, flags), in a fixed order."""
    entries, _ = found[Path(name)]
    return sorted((e.mask, e.flags) for e in entries if e.sid == SID_LOCAL_SERVICE)


def test_one_install_converges_a_repository_an_earlier_install_granted_and_a_second_changes_nothing(
    tmp_path, monkeypatch
):
    tree = build("earlier", tmp_path / "earlier", monkeypatch)
    install(tree)
    first = acls(tree.root)
    for name in (".", "bin", "bin/frpc.exe"):  # nothing the root or bin hold for the service is inheritable
        assert service_aces(first, name) == [(READ_EXECUTE, 0)], name
    assert service_aces(first, "host") == sorted([(READ_EXECUTE, 0),
                                                  (READ_EXECUTE, OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)])
    assert service_aces(first, "host/frpc.toml") == [(READ_EXECUTE, INHERITED_ACE)]
    install(tree)
    assert acls(tree.root) == first


# Events ===============================================================================================================


class Events:
    """Counts the DACL writes and the renames of an install; raises `Interrupted` at the `stop_at`-th event.

    A DACL write is an event after it has been made, a rename is two: just before and just after.
    """

    def __init__(self, monkeypatch, stop_at: int | None = None) -> None:
        self.count = 0
        self.stop_at = stop_at
        real_set, real_rename, real_replace = winacl.set_dacl, winfile.rename_over, os.replace

        def set_dacl(handle, entries, *, protected):
            real_set(handle, entries, protected=protected)
            self.tick()

        def rename_over(*args, **kwargs):
            self.tick()
            real_rename(*args, **kwargs)
            self.tick()

        def replace(*args, **kwargs):
            self.tick()
            real_replace(*args, **kwargs)
            self.tick()

        monkeypatch.setattr(winacl, "set_dacl", set_dacl)
        monkeypatch.setattr(winfile, "rename_over", rename_over)
        monkeypatch.setattr(os, "replace", replace)

    def tick(self) -> None:
        self.count += 1
        if self.count == self.stop_at:
            raise Interrupted


# Comparing ============================================================================================================


def unprotected(entries: list[winacl.Entry]) -> list[winacl.Entry]:
    """`entries` as NTFS leaves them on a child it protects: what it inherited is explicit now. Order is kept."""
    return [e._replace(flags=e.flags & ~INHERITED_ACE) for e in entries]


def differences(got, want) -> list[Path]:
    """The paths whose ACL, ACE by ACE in stored order, differs. The one tolerated difference is a child that NTFS
    protected when its directory gained an inheritable ACE and an interruption left so: its ACEs are the reference's,
    written as explicit ones."""
    differing = []
    for path in sorted(got.keys() | want.keys()):
        if got.get(path) == want.get(path):
            continue
        if path in got and path in want:
            (own, protected), (expected, expected_protected) = got[path], want[path]
            if protected and not expected_protected and own == unprotected(expected):
                continue
        differing.append(path)
    return differing


@pytest.mark.parametrize("variant", ["fresh", "installed", "earlier"])
def test_no_interruption_of_an_install_takes_the_service_read_from_what_it_needs_and_the_next_run_converges(
    tmp_path, monkeypatch, variant
):
    reference = build(variant, tmp_path / "reference", monkeypatch)
    with monkeypatch.context() as patch:
        events = Events(patch)
        install(reference)
    total = events.count
    assert total > 1
    expected = acls(reference.root)
    assert readable(reference.root) == set(needed(reference.root)), "the finished install leaves the service short"
    for number in range(1, total + 1):
        tree = build(variant, tmp_path / f"after-{number}", monkeypatch)
        before = readable(tree.root)
        with monkeypatch.context() as patch:
            Events(patch, stop_at=number)
            with pytest.raises(Interrupted):
                install(tree)
        held = readable(tree.root)
        assert before <= held, f"event {number}: the service lost {sorted(before - held)}"
        install(tree)  # the rerun converges in one run
        missing = set(needed(tree.root)) - readable(tree.root)
        assert not missing, f"after the rerun of event {number} the service cannot open {sorted(missing)}"
        assert differences(acls(tree.root), expected) == [], f"rerun after event {number}"
