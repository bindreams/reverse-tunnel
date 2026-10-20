"""`stage` on a repository an earlier install left: one run converges it, and no interruption strands the service."""

import subprocess
from pathlib import Path

import pytest
from tests.platform.windows.service_access import can_open
from tests.unit.deployment_support import write_env

from ctl import host, perms_windows, winacl
from ctl.config import Config, Role
from ctl.perms import SID_LOCAL_SERVICE, AccountMode
from ctl.services import Services

OBJECT_INHERIT_ACE = winacl.OBJECT_INHERIT_ACE
INHERIT_ONLY_ACE = winacl.INHERIT_ONLY_ACE
INHERITED_ACE = winacl.INHERITED_ACE
READ_EXECUTE = winacl.READ_EXECUTE


class Interrupted(Exception):
    """Stands for a kill, a power loss or Ctrl-C that lands right after a DACL write."""


def acls(root: Path) -> dict[Path, tuple[list[winacl.Entry], bool]]:
    """Every ACE, in stored order, and the inheritance state of `root` and everything under it, by relative path."""
    found = {}
    for path in [root, *root.rglob("*")]:
        with perms_windows._handle(path, directory=path.is_dir(), access=perms_windows.winfile.READ_CONTROL) as handle:
            found[path.relative_to(root)] = winacl.read_entries(handle)
    return found


def layout(base: Path, *, installed_before: bool = True) -> Config:
    """A clone with the files the service reads; with `installed_before`, also the `bin` and `logs` an install made."""
    repo = base / "repo"
    names = ("bin", "host", "logs") if installed_before else ("host", )
    for name in names:
        (repo / name).mkdir(parents=True)
    if installed_before:
        (repo / "bin" / "frpc.exe").write_bytes(b"")
        (repo / "logs" / "frpc.log").write_bytes(b"")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    return write_env(repo, Role.HOST)


def previous_install(tmp_path: Path) -> Config:
    """A host as the install that wrote an inheritable service ACE on the root left it, with logs it wrote."""
    config = layout(tmp_path)
    grant = f"*{SID_LOCAL_SERVICE}:(OI)(CI)(RX)"
    subprocess.run(["icacls", str(config.root), "/grant", grant], check=True, capture_output=True)
    return config


def stage(config: Config) -> None:
    plan = host.Plan(
        binaries_to_replace=(),
        daemons_to_converge=(),
        mode=AccountMode.SEPARATE,
        platform="windows-x86_64",
        pins=(),
        bundle=None,
        installed=(),
        detach=False,
        inputs={},
        reasons={},
    )
    host.stage(config, plan, services=Services())


def service_aces(found: dict[Path, tuple[list[winacl.Entry], bool]], name: str) -> list[tuple[int, int]]:
    """The service's ACEs on the relative path `name` as (mask, flags), in a fixed order."""
    entries, _ = found[Path(name)]
    return sorted((e.mask, e.flags) for e in entries if e.sid == SID_LOCAL_SERVICE)


def test_one_stage_converges_a_repository_an_earlier_install_granted(tmp_path):
    config = previous_install(tmp_path)
    stage(config)
    first = acls(config.root)
    for name in (".", "bin", "bin/frpc.exe"):  # nothing the root or bin hold for the service is inheritable
        assert service_aces(first, name) == [(READ_EXECUTE, 0)], name
    assert service_aces(first, "host") == sorted([(READ_EXECUTE, 0),
                                                  (READ_EXECUTE, OBJECT_INHERIT_ACE | INHERIT_ONLY_ACE)])
    assert service_aces(first, "host/frpc.toml") == [(READ_EXECUTE, INHERITED_ACE)]
    stage(config)
    assert acls(config.root) == first


# An interruption at any point =========================================================================================


def build(variant: str, base: Path) -> Config:
    """A repository as the three installs leave it: never installed, installed, and installed by the earlier version."""
    if variant == "fresh":
        return layout(base, installed_before=False)
    if variant == "installed":
        config = layout(base)
        stage(config)
        return config
    return previous_install(base)


def needed(root: Path) -> list[Path]:
    """The files the service opens that exist now: the binaries and the frpc configuration."""
    return [path for path in [*sorted((root / "bin").glob("*.exe")), root / "host" / "frpc.toml"] if path.exists()]


def readable(root: Path) -> set[Path]:
    """The relative paths of what the service can open, as the kernel decides it."""
    return {path.relative_to(root) for path in needed(root) if can_open(path)}


def count_writes(monkeypatch, action) -> int:
    """Run `action` and return how many times it called `winacl.set_dacl`."""
    real = winacl.set_dacl
    calls = []

    def counting(handle, entries, *, protected):
        calls.append(handle)
        real(handle, entries, protected=protected)

    monkeypatch.setattr(winacl, "set_dacl", counting)
    action()
    return len(calls)


def interrupt_after(monkeypatch, number: int) -> None:
    """Make the `number`-th call to `winacl.set_dacl` raise `Interrupted` once it has written."""
    real = winacl.set_dacl
    calls = []

    def interrupting(handle, entries, *, protected):
        real(handle, entries, protected=protected)
        calls.append(handle)
        if len(calls) == number:
            raise Interrupted

    monkeypatch.setattr(winacl, "set_dacl", interrupting)


def shape(entries: list[winacl.Entry]) -> frozenset[tuple[int, int, int, str]]:
    return frozenset((e.ace_type, e.flags & ~INHERITED_ACE, e.mask, e.sid) for e in entries)


def differences(root: Path, got, want) -> list[Path]:
    """The paths whose ACL differs. A file NTFS made protected may stay so, holding the same ACEs as explicit ones."""
    differing = []
    for path in sorted(got.keys() | want.keys()):
        if path in got and path in want and got[path] != want[path]:
            (own, protected), (expected, expected_protected) = got[path], want[path]
            if (root / path).is_file() and protected and not expected_protected and shape(own) == shape(expected):
                continue
        if got.get(path) != want.get(path):
            differing.append(path)
    return differing


@pytest.mark.parametrize("variant", ["fresh", "installed", "earlier"])
def test_no_interruption_of_stage_takes_the_service_read_from_a_file_and_the_next_run_converges(
    tmp_path, monkeypatch, variant
):
    reference = build(variant, tmp_path / "reference")
    with monkeypatch.context() as patch:
        total = count_writes(patch, lambda: stage(reference))
    assert total > 1
    expected = acls(reference.root)
    held_before = None
    for number in range(1, total + 1):
        config = build(variant, tmp_path / f"after-{number}")
        before = readable(config.root)
        with monkeypatch.context() as patch:
            interrupt_after(patch, number)
            with pytest.raises(Interrupted):
                stage(config)
        held = readable(config.root)
        assert before <= held, f"after write {number} the service lost {sorted(before - held)}"
        assert held_before is None or held_before <= held, f"after write {number} the service lost something"
        held_before = held
        stage(config)  # the rerun converges in one run
        assert differences(config.root, acls(config.root), expected) == [], f"rerun after write {number}"
