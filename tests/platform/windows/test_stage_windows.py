"""`stage` and `apply` on a repository an earlier install left: no interruption strands the service, a rerun converges.

The service's access is judged by Windows' own access check (see `service_access`). It reads: `bin` and every file in
it, `host` and `host/frpc.toml`, `secrets/token`, and it writes into `logs`. The repository root is not on the list.
"""

import os
import subprocess
from pathlib import Path

import pytest
from tests.platform.windows.acl_support import owned_shape
from tests.platform.windows.service_access import descriptor_of, service_token
from tests.unit.host_support import HostTree, build_host

from ctl import _winfile as winfile
from ctl import binaries, host, perms_windows, winacl
from ctl.perms import SID_LOCAL_SERVICE, AccountMode
from ctl.services import Services

OBJECT_INHERIT_ACE = winacl.OBJECT_INHERIT_ACE
CONTAINER_INHERIT_ACE = winacl.CONTAINER_INHERIT_ACE
INHERIT_ONLY_ACE = winacl.INHERIT_ONLY_ACE
INHERITED_ACE = winacl.INHERITED_ACE
INHERITING = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE

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
VARIANTS = ["fresh", "installed", "earlier", "previous"]


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


def add_service_aces(path: Path, *added: winacl.Entry) -> None:
    """`path` with `added` among its explicit ACEs; every other ACE and the inheritance state are kept."""
    with perms_windows._handle(path, directory=path.is_dir(), access=perms_windows.ACL_ACCESS) as handle:
        entries, protected = winacl.read_entries(handle)
        winacl.set_dacl(handle, winacl.canonical(entries + list(added)), protected=protected)


def write_previous_shape(root: Path) -> None:
    """What the previous version of the install wrote: the service's read-and-execute, explicit, on the root, on `bin`
    and each file in it, and on `host`, which also holds an ACE that its files inherit."""
    allow = winacl.ACCESS_ALLOWED_ACE_TYPE

    def service(flags: int) -> winacl.Entry:
        return winacl.Entry(allow, flags, winacl.READ_EXECUTE, SID_LOCAL_SERVICE)

    add_service_aces(root, service(0))
    for directory in (root / "bin", root / "host"):
        add_service_aces(
            directory, service(0), *([service(OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)] * (directory.name == "host"))
        )
    for path in sorted((root / "bin").iterdir()):
        add_service_aces(path, service(0))
    with perms_windows._handle(root / "host", directory=True, access=winfile.READ_CONTROL) as handle:
        parent, _ = winacl.read_entries(handle)
    for path in sorted((root / "host").iterdir()):
        with perms_windows._handle(path, directory=False, access=perms_windows.ACL_ACCESS) as handle:
            entries, protected = winacl.read_entries(handle)
            inherited = winacl.inherited_for(parent, directory=False)
            winacl.set_dacl(handle, winacl.canonical(winacl.explicit(entries) + inherited), protected=protected)


def build(variant: str, base: Path, monkeypatch) -> HostTree:
    """A repository in one of four states: never installed, installed, and installed by either earlier version.

    The oldest put an inheritable `(OI)(CI)(RX)` ACE for the service on the repository root; the one before this put
    explicit, mostly non-inheritable ACEs on the root, `bin`, `host` and their files (`write_previous_shape`).
    """
    base.mkdir()
    tree = build_host(base, monkeypatch, platform=PLATFORM)
    (tree.root / "ctl").mkdir()
    (tree.root / "ctl" / "module.py").write_bytes(b"")
    if variant == "installed":
        install(tree)
    elif variant in ("earlier", "previous"):
        tree.write_binaries()
        tree.record()
        (tree.root / "logs").mkdir()
        (tree.root / "logs" / "frpc.log").write_bytes(b"")
        if variant == "earlier":
            subprocess.run(["icacls", str(tree.root), "/grant", f"*{SID_LOCAL_SERVICE}:(OI)(CI)(RX)"],
                           check=True,
                           capture_output=True)
        else:
            write_previous_shape(tree.root)
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
    wanted: dict[Path, int] = {}
    for directory, access in (("bin", LIST), ("host", LIST), ("secrets", LIST), ("logs", ADD_TO)):
        if (root / directory).is_dir():
            wanted[Path(directory)] = access
    for directory, access in (("bin", EXECUTE), ("logs", APPEND)):
        if (root / directory).is_dir():
            for entry in sorted((root / directory).iterdir()):
                if entry.is_file():
                    wanted[entry.relative_to(root)] = access
    for name, access in (("host/frpc.toml", READ), ("secrets/token", READ)):
        if (root / name).is_file():
            wanted[Path(name)] = access
    return wanted


def readable(root: Path) -> set[Path]:
    """The relative paths among `needed` that the service is granted, as the kernel decides it."""
    with service_token() as token:
        return {path for path, access in needed(root).items() if token.grants(descriptor_of(root / path), access)}


# The shape of the result ==============================================================================================


def shape(found: dict[Path, tuple[list[winacl.Entry], bool]], name: str) -> tuple[set[tuple[str, int, int]], bool]:
    """The ACEs on the relative path `name` as (sid, mask, flags), and whether its inheritance is broken."""
    entries, protected = found[Path(name)]
    return {(e.sid, e.mask, e.flags) for e in entries}, protected


@pytest.mark.parametrize("variant", VARIANTS)
def test_one_install_gives_the_owned_directories_their_fixed_acls_and_a_second_changes_nothing(
    tmp_path, monkeypatch, variant
):
    tree = build(variant, tmp_path / variant, monkeypatch)
    install(tree)
    first = acls(tree.root)
    for directory, mask, files in ((
        "bin", winacl.READ_EXECUTE, ("frpc.exe", "websocat.exe", "goetia-shim.exe", "goetia.exe", ".digests.json")
    ), ("host", winacl.READ_EXECUTE, ("frpc.toml", )), ("logs", winacl.MODIFY, ())):
        assert shape(first, directory) == (owned_shape(tree.root, mask, INHERITING), True), directory
        for name in files:
            assert shape(first, f"{directory}/{name}") == (owned_shape(tree.root, mask, INHERITED_ACE), False), name
    install(tree)
    assert acls(tree.root) == first


@pytest.mark.parametrize("variant", VARIANTS)
def test_the_service_holds_no_ace_on_the_repository_root_after_an_install(tmp_path, monkeypatch, variant):
    tree = build(variant, tmp_path / variant, monkeypatch)
    install(tree)
    entries, _ = acls(tree.root)[Path(".")]
    assert [e for e in entries if e.sid == SID_LOCAL_SERVICE] == []


@pytest.mark.parametrize("variant", VARIANTS)
def test_the_other_children_of_the_root_keep_their_whole_acls_through_an_install(tmp_path, monkeypatch, variant):
    """A file and a directory `ctl` never opens, whichever ACE the root loses."""
    tree = build(variant, tmp_path / variant, monkeypatch)
    names = [Path("goetia.yaml"), Path("ctl"), Path("ctl/module.py")]
    before = {name: acls(tree.root)[name] for name in names}
    install(tree)
    assert {name: acls(tree.root)[name] for name in names} == before


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


def differences(got, want) -> list[str]:
    """The paths whose ACL differs, ACE by ACE in stored order, duplicates included, each with both ACLs."""
    return [
        f"{path}: got {got.get(path)}, want {want.get(path)}" for path in sorted(got.keys() | want.keys())
        if got.get(path) != want.get(path)
    ]


@pytest.mark.parametrize("variant", VARIANTS)
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
        in_bin = {path for path in needed(tree.root) if path.parts[0] == "bin"}
        assert in_bin <= held, f"event {number}: a file in bin exists without the service's access: {sorted(in_bin - held)}"
        install(tree)  # the rerun converges in one run
        missing = set(needed(tree.root)) - readable(tree.root)
        assert not missing, f"after the rerun of event {number} the service cannot open {sorted(missing)}"
        assert differences(acls(tree.root), expected) == [], f"rerun after event {number}"
