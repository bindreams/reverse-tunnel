"""The directories `ctl install` owns outright on Windows: `bin`, `host` and `logs`.

Each is protected, holds a fixed DACL (the operator and Administrators in full, the service with what it needs, no
deny) and rewrites every entry in it to inherit from it. Nothing outside them is written, and the repository root loses
the service's ACE an earlier install gave it.
"""

import contextlib
import ctypes
import os
import shutil
import signal
from pathlib import Path

import pytest
from tests.platform.windows.acl_support import (
    INHERITED_ACE,
    INHERITING,
    after_each_write,
    entries_of,
    icacls,
    Shape,
    owned_shape,
    shape_of,
    snapshot,
    whole_entries,
)
from tests.platform.windows.service_access import can_open

from ctl import perms_windows, winacl
from ctl.perms import SID_LOCAL_SERVICE, Account, PermsError, converge_owned, converge_tree, revoke_root

LOCAL_SERVICE = Account("LocalService", None, None)
LIST = 0x1 | 0x20 | 0x100000
ADD_TO = LIST | 0x2
READ = winacl.READ
EXECUTE = 0x1 | 0x20 | 0x80 | 0x100000
KINDS = {"bin": winacl.READ_EXECUTE, "host": winacl.READ_EXECUTE, "logs": winacl.MODIFY}
NON_BMP = "\U0001d4b3"


def repo_with(tmp_path: Path) -> Path:
    """A repository with a file in each owned directory and two children of the root that `ctl` never opens."""
    repo = tmp_path / "repo"
    for name in KINDS:
        (repo / name).mkdir(parents=True)
    (repo / "bin" / "frpc.exe").write_bytes(b"")
    (repo / "host" / "frpc.toml").write_bytes(b"")
    (repo / "logs" / "frpc.log").write_bytes(b"")
    (repo / "ctl").mkdir()
    (repo / "ctl" / "module.py").write_bytes(b"")
    (repo / "goetia.yaml").write_bytes(b"")
    return repo


def add_nested(repo: Path, name: str) -> list[Path]:
    """Two levels of subdirectory in an owned directory, each holding a file; the paths below `name`, parents first."""
    top, deeper = repo / name / "old", repo / name / "old" / "deeper"
    deeper.mkdir(parents=True)
    files = [top / "leftover", deeper / "leftover"]
    for file in files:
        file.write_bytes(b"")
    return [top, files[0], deeper, files[1]]


def inherited_shape(repo: Path, name: str, path: Path) -> tuple[Shape, bool]:
    """What an entry of an owned directory holds: what it inherits, not protected; a directory passes it on."""
    flags = (INHERITING | INHERITED_ACE) if path.is_dir() else INHERITED_ACE
    return owned_shape(repo, KINDS[name], flags), False


def converge(repo: Path, name: str) -> None:
    if name == "logs":
        converge_tree(repo / "logs", LOCAL_SERVICE, 0o750, root=repo)
    else:
        converge_owned(repo / name, LOCAL_SERVICE, root=repo)


def converge_all(repo: Path) -> None:
    for name in KINDS:
        converge(repo, name)


def count_writes(monkeypatch) -> list:
    return after_each_write(monkeypatch, lambda: None)


# The fixed DACL =======================================================================================================


@pytest.mark.parametrize("name", KINDS)
def test_an_owned_directory_holds_exactly_the_fixed_acl_and_inherits_nothing(tmp_path, name):
    repo = repo_with(tmp_path)
    converge(repo, name)
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)


@pytest.mark.parametrize("name", KINDS)
def test_a_file_in_an_owned_directory_holds_exactly_what_it_inherits_and_is_not_protected(tmp_path, name):
    repo = repo_with(tmp_path)
    converge(repo, name)
    (file, ) = [p for p in (repo / name).iterdir()]
    assert shape_of(file) == (owned_shape(repo, KINDS[name], INHERITED_ACE), False)


@pytest.mark.parametrize("name", KINDS)
def test_no_ace_of_an_owned_directory_or_its_files_is_a_deny(tmp_path, name):
    repo = repo_with(tmp_path)
    converge(repo, name)
    for path in [repo / name, *(repo / name).iterdir()]:
        assert [e for e in entries_of(path) if e.ace_type != winacl.ACCESS_ALLOWED_ACE_TYPE] == [], path


def test_the_service_may_list_and_run_bin_and_read_host_and_write_logs(tmp_path):
    repo = repo_with(tmp_path)
    converge_all(repo)
    assert can_open(repo / "bin", LIST) and can_open(repo / "bin" / "frpc.exe", EXECUTE)
    assert can_open(repo / "host", LIST) and can_open(repo / "host" / "frpc.toml", READ)
    assert can_open(repo / "logs", ADD_TO)


@pytest.mark.parametrize("name", KINDS)
def test_a_missing_owned_directory_is_created_with_the_fixed_acl(tmp_path, name):
    repo = tmp_path / "repo"
    repo.mkdir()
    converge(repo, name)
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)


@pytest.mark.parametrize("name", KINDS)
def test_converging_again_writes_nothing(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    converge(repo, name)
    first = snapshot(repo / name)
    writes = count_writes(monkeypatch)
    converge(repo, name)
    assert writes == [] and snapshot(repo / name) == first


# Whole, not additive ==================================================================================================


@pytest.mark.parametrize("name", KINDS)
def test_an_ace_anyone_added_to_the_directory_or_a_file_in_it_is_dropped(tmp_path, name):
    repo = repo_with(tmp_path)
    (file, ) = list((repo / name).iterdir())
    icacls(str(repo / name), "/grant", f"*{winacl.SID_USERS}:(OI)(CI)(R)")
    icacls(str(file), "/grant", f"*{winacl.SID_EVERYONE}:(R)")
    converge(repo, name)
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)
    assert shape_of(file) == (owned_shape(repo, KINDS[name], INHERITED_ACE), False)


@pytest.mark.parametrize("name", KINDS)
def test_a_deny_on_the_directory_or_a_file_in_it_is_dropped_and_the_service_can_open_them(tmp_path, name):
    repo = repo_with(tmp_path)
    (file, ) = list((repo / name).iterdir())
    for sid in (SID_LOCAL_SERVICE, winacl.SID_EVERYONE, winacl.SID_USERS):
        icacls(str(repo / name), "/deny", f"*{sid}:(X)")
        icacls(str(file), "/deny", f"*{sid}:(X)")
    converge(repo, name)
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)
    assert shape_of(file) == (owned_shape(repo, KINDS[name], INHERITED_ACE), False)
    assert can_open(repo / name, LIST) and can_open(file, READ)


def make_protected(path: Path) -> None:
    """What NTFS leaves a child whose directory gains an inheritable ACE: explicit, protected copies of its ACEs."""
    entries, _ = whole_entries(path)
    copies = [e._replace(flags=e.flags & ~INHERITED_ACE) for e in entries]
    with perms_windows._handle(path, directory=path.is_dir(), access=perms_windows.ACL_ACCESS) as handle:
        winacl.set_dacl(handle, copies, protected=True)


@pytest.mark.parametrize("name", KINDS)
def test_a_file_that_is_protected_is_made_to_inherit_again(tmp_path, name):
    repo = repo_with(tmp_path)
    (file, ) = list((repo / name).iterdir())
    make_protected(file)
    assert whole_entries(file)[1]
    converge(repo, name)
    assert shape_of(file) == (owned_shape(repo, KINDS[name], INHERITED_ACE), False)


@pytest.mark.parametrize("name", ["bin", "host"])
def test_a_file_moved_in_from_elsewhere_keeps_its_old_acl_until_the_directory_is_converged(tmp_path, name):
    repo = repo_with(tmp_path)
    converge(repo, name)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    icacls(str(elsewhere), "/inheritance:r", "/grant:r", f"*{winacl.SID_ADMINISTRATORS}:(OI)(CI)(F)")
    moved = elsewhere / "moved.toml"
    moved.write_bytes(b"")
    os.rename(moved, repo / name / "moved.toml")
    assert not can_open(repo / name / "moved.toml", READ)
    converge(repo, name)
    assert shape_of(repo / name / "moved.toml") == (owned_shape(repo, KINDS[name], INHERITED_ACE), False)
    assert can_open(repo / name / "moved.toml", READ)


# Subdirectories =======================================================================================================


@pytest.mark.parametrize("name", KINDS)
def test_every_entry_at_every_depth_holds_exactly_what_it_inherits_and_is_not_protected(tmp_path, name):
    repo = repo_with(tmp_path)
    nested = add_nested(repo, name)
    converge(repo, name)
    for path in nested:
        assert shape_of(path) == inherited_shape(repo, name, path), path


@pytest.mark.parametrize("name", KINDS)
def test_the_service_may_open_what_lies_deep_in_a_subdirectory(tmp_path, name):
    repo = repo_with(tmp_path)
    nested = add_nested(repo, name)
    converge(repo, name)
    assert all(can_open(path, LIST if path.is_dir() else READ) for path in nested)


@pytest.mark.parametrize("name", KINDS)
def test_converging_again_writes_nothing_with_subdirectories_present(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    add_nested(repo, name)
    converge(repo, name)
    first = snapshot(repo / name)
    writes = count_writes(monkeypatch)
    converge(repo, name)
    assert writes == [] and snapshot(repo / name) == first


@pytest.mark.parametrize("name", KINDS)
def test_an_ace_or_a_deny_added_to_a_subdirectory_or_a_file_in_it_is_dropped(tmp_path, name):
    repo = repo_with(tmp_path)
    nested = add_nested(repo, name)
    for path in nested:
        icacls(str(path), "/deny", f"*{winacl.SID_USERS}:(X)")
        icacls(str(path), "/grant", f"*{winacl.SID_EVERYONE}:(R)")
    converge(repo, name)
    for path in nested:
        assert shape_of(path) == inherited_shape(repo, name, path), path


@pytest.mark.parametrize("name", KINDS)
def test_a_protected_subdirectory_or_file_deep_in_the_tree_is_made_to_inherit_again(tmp_path, name):
    repo = repo_with(tmp_path)
    nested = add_nested(repo, name)
    for path in nested:
        make_protected(path)
    converge(repo, name)
    for path in nested:
        assert shape_of(path) == inherited_shape(repo, name, path), path


@pytest.mark.parametrize("name", KINDS)
def test_a_file_created_in_a_subdirectory_afterwards_holds_the_service_access(tmp_path, name):
    repo = repo_with(tmp_path)
    add_nested(repo, name)
    converge(repo, name)
    created = repo / name / "old" / "deeper" / "created"
    created.write_bytes(b"")
    assert can_open(created, READ)


@pytest.mark.parametrize("name", KINDS)
def test_nothing_outside_the_owned_directory_is_written_when_it_holds_subdirectories(tmp_path, name):
    repo = repo_with(tmp_path)
    add_nested(repo, name)
    others = [p for p in repo.iterdir() if p.name != name]
    before = snapshot(*others)
    converge(repo, name)
    assert snapshot(*others) == before


# Files created afterwards =============================================================================================


@pytest.mark.parametrize("name", KINDS)
def test_a_file_created_in_an_owned_directory_afterwards_holds_the_service_access(tmp_path, name):
    """Git replaces `host/frpc.toml` with a new file; `ctl` replaces a binary the same way."""
    repo = repo_with(tmp_path)
    converge(repo, name)
    created = repo / name / "created"
    created.write_bytes(b"")
    assert shape_of(created) == (owned_shape(repo, KINDS[name], INHERITED_ACE), False)
    assert can_open(created, READ)


def test_a_file_git_recreates_in_host_is_readable_by_the_service(tmp_path):
    repo = repo_with(tmp_path)
    converge(repo, "host")
    config = repo / "host" / "frpc.toml"
    config.unlink()
    config.write_bytes(b"new")
    assert can_open(config, READ)


# What reaches the directory from above ================================================================================


@pytest.mark.parametrize("name", KINDS)
def test_an_inheritable_deny_above_the_repository_does_not_reach_an_owned_directory(tmp_path, name):
    repo = repo_with(tmp_path)
    icacls(str(tmp_path), "/deny", f"*{winacl.SID_EVERYONE}:(OI)(CI)(X)")
    converge(repo, name)
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)
    assert can_open(repo / name, LIST)
    created = repo / name / "created"
    created.write_bytes(b"")
    assert can_open(created, READ)


def test_an_inheritable_ace_the_operator_adds_to_the_root_does_not_reach_an_owned_directory(tmp_path):
    repo = repo_with(tmp_path)
    converge_all(repo)
    before = snapshot(repo / "bin", repo / "host", repo / "logs")
    icacls(str(repo), "/grant", f"*{winacl.SID_USERS}:(OI)(CI)(R)")
    assert snapshot(repo / "bin", repo / "host", repo / "logs") == before


@pytest.mark.parametrize("sid", ["S-1-3-2", "S-1-3-3"])
def test_an_unsupported_inheritable_ace_on_the_parent_is_no_obstacle_because_nothing_is_inherited(tmp_path, sid):
    repo = repo_with(tmp_path)
    icacls(str(repo), "/grant:r", f"*{sid}:(OI)(CI)(F)")
    before = whole_entries(repo)
    converge_all(repo)
    assert whole_entries(repo) == before
    assert shape_of(repo / "bin")[0] == owned_shape(repo, winacl.READ_EXECUTE, INHERITING)


# What it refuses ======================================================================================================


def refuses(repo: Path, name: str, *foreign: Path) -> PermsError:
    before = snapshot(repo, *foreign)
    with pytest.raises(PermsError) as raised:
        converge(repo, name)
    assert snapshot(repo, *foreign) == before
    return raised.value


@pytest.mark.parametrize("name", KINDS)
def test_a_hard_linked_file_is_refused_and_the_other_name_is_left_alone(tmp_path, name):
    repo = repo_with(tmp_path)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"")
    os.link(foreign, repo / name / "linked")
    assert "hard link" in str(refuses(repo, name, foreign))


@pytest.mark.parametrize("name", KINDS)
def test_a_symlink_is_refused_and_its_target_is_left_alone(tmp_path, name):
    repo = repo_with(tmp_path)
    target = tmp_path / "target"
    target.write_bytes(b"")
    (repo / name / "link").symlink_to(target)
    error = refuses(repo, name, target)
    assert str(repo / name / "link") in str(error) and "remove it" in str(error)


@pytest.mark.parametrize("name", KINDS)
def test_a_junction_is_refused_and_its_target_is_left_alone(tmp_path, name):
    import _winapi

    repo = repo_with(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside").write_bytes(b"")
    _winapi.CreateJunction(str(target), str(repo / name / "junction"))
    assert "reparse point" in str(refuses(repo, name, target))


@pytest.mark.parametrize("name", KINDS)
def test_the_directory_itself_as_a_reparse_point_is_refused_and_its_target_is_left_alone(tmp_path, name):
    repo = repo_with(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    shutil.rmtree(repo / name)
    (repo / name).symlink_to(target, target_is_directory=True)
    before = snapshot(target)
    with pytest.raises(PermsError) as raised:
        converge(repo, name)
    assert str(repo / name) in str(raised.value)
    assert snapshot(target) == before


def test_an_entry_whose_name_is_outside_the_bmp_is_opened(tmp_path):
    repo = repo_with(tmp_path)
    (repo / "bin" / f"tool-{NON_BMP}.exe").write_bytes(b"")
    converge(repo, "bin")
    assert shape_of(repo / "bin" / f"tool-{NON_BMP}.exe"
                    ) == (owned_shape(repo, winacl.READ_EXECUTE, INHERITED_ACE), False)


def test_a_junction_whose_name_is_outside_the_bmp_is_refused_by_name_not_skipped(tmp_path):
    import _winapi

    repo = repo_with(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    _winapi.CreateJunction(str(target), str(repo / "bin" / NON_BMP))
    error = refuses(repo, "bin", target)
    assert NON_BMP in str(error) and "reparse point" in str(error)


@pytest.mark.parametrize("name", KINDS)
def test_a_hard_linked_file_deep_in_a_subdirectory_is_refused_and_nothing_is_changed(tmp_path, name):
    repo = repo_with(tmp_path)
    add_nested(repo, name)
    foreign = tmp_path / "foreign"
    foreign.write_bytes(b"")
    os.link(foreign, repo / name / "old" / "deeper" / "linked")
    error = refuses(repo, name, foreign)
    assert "hard link" in str(error) and str(repo / name / "old" / "deeper" / "linked") in str(error)


@pytest.mark.parametrize("name", KINDS)
def test_a_symlink_deep_in_a_subdirectory_is_refused_and_its_target_is_left_alone(tmp_path, name):
    repo = repo_with(tmp_path)
    add_nested(repo, name)
    target = tmp_path / "target"
    target.write_bytes(b"")
    (repo / name / "old" / "deeper" / "link").symlink_to(target)
    error = refuses(repo, name, target)
    assert str(repo / name / "old" / "deeper" / "link") in str(error) and "reparse point" in str(error)


@pytest.mark.parametrize("name", KINDS)
def test_a_junction_to_a_directory_in_a_subdirectory_is_refused_and_its_target_is_left_alone(tmp_path, name):
    import _winapi

    repo = repo_with(tmp_path)
    add_nested(repo, name)
    target = tmp_path / "target"
    target.mkdir()
    (target / "inside").write_bytes(b"")
    _winapi.CreateJunction(str(target), str(repo / name / "old" / "junction"))
    assert "reparse point" in str(refuses(repo, name, target))


# Entries that vanish ==================================================================================================


def vanish_after_listing(monkeypatch, victim: Path) -> None:
    """The listing of the directory holding `victim` is followed by `victim` being deleted, as a daemon rotating a log
    or git cleaning up would."""
    real = perms_windows.winfile.list_names

    def listing(directory):
        names = real(directory)
        if victim.name in names and victim.exists():
            if victim.is_dir():
                victim.rmdir()
            else:
                victim.unlink()
        return names

    monkeypatch.setattr(perms_windows.winfile, "list_names", listing)


@pytest.mark.parametrize("name", KINDS)
def test_a_file_deleted_between_listing_and_opening_is_skipped(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    (repo / name / "rotated").write_bytes(b"")
    kept = [p for p in (repo / name).iterdir() if p.name != "rotated"]
    vanish_after_listing(monkeypatch, repo / name / "rotated")
    converge(repo, name)
    assert not (repo / name / "rotated").exists()
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)
    for path in kept:
        assert shape_of(path) == inherited_shape(repo, name, path)


@pytest.mark.parametrize("name", KINDS)
def test_a_file_deleted_from_a_subdirectory_between_listing_and_opening_is_skipped(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    nested = add_nested(repo, name)
    victim = repo / name / "old" / "deeper" / "rotated"
    victim.write_bytes(b"")
    vanish_after_listing(monkeypatch, victim)
    converge(repo, name)
    assert not victim.exists()
    for path in nested[:3]:
        assert shape_of(path) == inherited_shape(repo, name, path), path


@pytest.mark.parametrize("name", KINDS)
def test_a_subdirectory_deleted_between_listing_and_opening_is_skipped(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    (repo / name / "gone").mkdir()
    vanish_after_listing(monkeypatch, repo / name / "gone")
    converge(repo, name)
    assert not (repo / name / "gone").exists()
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)


@contextlib.contextmanager
def deleted_while_held(path: Path):
    """`path` marked for deletion while a handle to it stays open: it keeps its name and is listed until the handle
    closes, and opening it answers STATUS_DELETE_PENDING. (`os.unlink` would use POSIX semantics and remove the name.)"""
    import _winapi

    DELETE, SHARE_ALL, BACKUP_SEMANTICS, FILE_DISPOSITION_INFO = 0x10000, 0x7, 0x02000000, 4
    handle = _winapi.CreateFile(str(path), DELETE, SHARE_ALL, 0, 3, BACKUP_SEMANTICS, 0)
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        mark = ctypes.c_ubyte(1)
        if not kernel32.SetFileInformationByHandle(handle, FILE_DISPOSITION_INFO, ctypes.byref(mark), 1):
            raise ctypes.WinError(ctypes.get_last_error())
        assert path.name in os.listdir(
            path.parent
        ), "a name pending deletion must still be listed for this test to mean it"
        yield
    finally:
        _winapi.CloseHandle(handle)


@pytest.mark.parametrize("name", KINDS)
def test_a_file_pending_deletion_between_listing_and_opening_is_skipped(tmp_path, name):
    repo = repo_with(tmp_path)
    (repo / name / "rotated").write_bytes(b"")
    kept = [p for p in (repo / name).iterdir() if p.name != "rotated"]
    with deleted_while_held(repo / name / "rotated"):
        converge(repo, name)
    assert not (repo / name / "rotated").exists()
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)
    for path in kept:
        assert shape_of(path) == inherited_shape(repo, name, path)


@pytest.mark.parametrize("name", KINDS)
def test_a_file_pending_deletion_in_a_subdirectory_is_skipped(tmp_path, name):
    repo = repo_with(tmp_path)
    nested = add_nested(repo, name)
    with deleted_while_held(nested[3]):
        converge(repo, name)
    for path in nested[:3]:
        assert shape_of(path) == inherited_shape(repo, name, path), path


@pytest.mark.parametrize("name", KINDS)
def test_a_subdirectory_pending_deletion_is_skipped(tmp_path, name):
    repo = repo_with(tmp_path)
    (repo / name / "gone").mkdir()
    with deleted_while_held(repo / name / "gone"):
        converge(repo, name)
    assert shape_of(repo / name) == (owned_shape(repo, KINDS[name], INHERITING), True)


@pytest.mark.parametrize("name", KINDS)
def test_an_entry_that_cannot_be_opened_for_another_reason_still_refuses(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    real = perms_windows.winfile.open_relative
    (victim, ) = [p.name for p in (repo / name).iterdir()]

    def opening(parent, entry, **kwargs):
        if entry == victim:
            raise PermissionError(5, "Access is denied")
        return real(parent, entry, **kwargs)

    monkeypatch.setattr(perms_windows.winfile, "open_relative", opening)
    before = snapshot(repo)
    with pytest.raises(PermsError) as raised:
        converge(repo, name)
    assert "cannot be opened" in str(raised.value) and "Access is denied" in str(raised.value)
    assert snapshot(repo) == before


# Order and interruption ===============================================================================================


def old_shape(tmp_path: Path) -> Path:
    """What the oldest install granted: an inheritable service ACE on the root, inherited by everything under it."""
    repo = repo_with(tmp_path)
    icacls(str(repo), "/grant", f"*{SID_LOCAL_SERVICE}:(OI)(CI)(RX)")
    return repo


def openable(repo: Path) -> list[Path]:
    """The objects of `bin` and `host` the service cannot open now."""
    wanted = {
        repo / "bin": LIST, repo / "bin" / "frpc.exe": EXECUTE, repo / "host": LIST, repo / "host" / "frpc.toml": READ
    }
    return [path for path, access in wanted.items() if not can_open(path, access)]


@pytest.mark.parametrize("name", ["bin", "host"])
def test_no_write_of_converging_a_directory_leaves_what_the_service_reads_without_access(tmp_path, monkeypatch, name):
    repo = old_shape(tmp_path)
    assert openable(repo) == []
    seen = after_each_write(monkeypatch, lambda: openable(repo))
    converge(repo, name)
    assert len(seen) > 1 and seen == [[]] * len(seen)


@pytest.mark.parametrize("name", ["bin", "host"])
def test_no_write_of_converging_a_directory_with_subdirectories_leaves_what_the_service_reads_without_access(
    tmp_path, monkeypatch, name
):
    repo = old_shape(tmp_path)
    nested = add_nested(repo, name)

    def unreadable() -> list[Path]:
        return [path for path in nested if not can_open(path, LIST if path.is_dir() else READ)]

    assert unreadable() == []
    seen = after_each_write(monkeypatch, unreadable)
    converge(repo, name)
    assert len(seen) > 1 and seen == [[]] * len(seen)


@pytest.mark.parametrize("name", KINDS)
def test_the_directory_is_written_before_its_files(tmp_path, monkeypatch, name):
    repo = repo_with(tmp_path)
    converged = []
    before = entries_of(repo / name)
    after_each_write(monkeypatch, lambda: converged.append(entries_of(repo / name) != before))
    converge(repo, name)
    assert converged and converged[0] is True


@pytest.mark.parametrize("name", KINDS)
def test_ctrl_c_does_not_land_between_the_writes_of_converging_a_directory(tmp_path, monkeypatch, name):
    whole, interrupted = (repo_with(tmp_path / case) for case in ("whole", "interrupted"))
    for repo in (whole, interrupted):
        (repo / name / "extra").write_bytes(b"")
        add_nested(repo, name)
    real = winacl.set_dacl
    calls = []
    interrupt = False

    def writing(handle, entries, *, protected):
        real(handle, entries, protected=protected)
        calls.append(handle)
        if len(calls) == 1 and interrupt:
            signal.raise_signal(signal.SIGINT)

    monkeypatch.setattr(winacl, "set_dacl", writing)
    converge(whole, name)
    expected = len(calls)
    calls.clear()
    interrupt = True
    with pytest.raises(KeyboardInterrupt):
        converge(interrupted, name)
    assert len(calls) == expected > 1


# The root =============================================================================================================


def service_aces(path: Path) -> list[winacl.Entry]:
    return [e for e in entries_of(path) if e.sid == SID_LOCAL_SERVICE]


@pytest.mark.parametrize("flags", [0, INHERITING], ids=["explicit", "inheritable"])
def test_revoking_removes_the_read_and_execute_ace_an_earlier_install_wrote_on_the_root(tmp_path, flags):
    repo = repo_with(tmp_path)
    icacls(str(repo), "/grant", f"*{SID_LOCAL_SERVICE}:" + ("(OI)(CI)(RX)" if flags else "(RX)"))
    assert [e.flags & INHERITING for e in service_aces(repo)] == [flags]
    revoke_root(repo, LOCAL_SERVICE)
    assert service_aces(repo) == []


def test_revoking_keeps_every_other_ace_of_the_root_and_its_inheritance_state(tmp_path):
    repo = repo_with(tmp_path)
    icacls(str(repo), "/grant", f"*{SID_LOCAL_SERVICE}:(RX)", f"*{winacl.SID_USERS}:(OI)(CI)(R)")
    icacls(str(repo), "/deny", f"*{winacl.SID_EVERYONE}:(WD)")
    before = whole_entries(repo)
    revoke_root(repo, LOCAL_SERVICE)
    entries, protected = whole_entries(repo)
    assert protected == before[1]
    assert entries == [e for e in before[0] if e.sid != SID_LOCAL_SERVICE]


def test_revoking_keeps_an_ace_for_the_service_that_is_not_the_one_install_wrote(tmp_path):
    repo = repo_with(tmp_path)
    icacls(str(repo), "/grant", f"*{SID_LOCAL_SERVICE}:(M)")
    icacls(str(repo), "/deny", f"*{SID_LOCAL_SERVICE}:(WD)")
    before = whole_entries(repo)
    revoke_root(repo, LOCAL_SERVICE)
    assert whole_entries(repo) == before


def test_revoking_writes_nothing_when_the_root_holds_no_such_ace(tmp_path, monkeypatch):
    repo = repo_with(tmp_path)
    writes = count_writes(monkeypatch)
    revoke_root(repo, LOCAL_SERVICE)
    assert writes == []


def test_revoking_writes_the_root_once(tmp_path, monkeypatch):
    repo = old_shape(tmp_path)
    writes = count_writes(monkeypatch)
    revoke_root(repo, LOCAL_SERVICE)
    assert len(writes) == 1


def test_revoking_from_the_oldest_shape_leaves_the_other_children_of_the_root_as_they_were(tmp_path):
    """The oldest install's inheritable ACE is on `ctl` and `goetia.yaml` as an inherited one; they were not opened."""
    repo = old_shape(tmp_path)
    before = snapshot(repo / "ctl", repo / "goetia.yaml")
    revoke_root(repo, LOCAL_SERVICE)
    assert snapshot(repo / "ctl", repo / "goetia.yaml") == before


def test_no_write_of_revoking_leaves_what_the_service_reads_without_access(tmp_path, monkeypatch):
    repo = old_shape(tmp_path)
    converge_all(repo)
    assert openable(repo) == []
    seen = after_each_write(monkeypatch, lambda: openable(repo))
    revoke_root(repo, LOCAL_SERVICE)
    assert seen == [[]]
    assert service_aces(repo) == []


def test_the_service_needs_nothing_on_the_root_once_the_directories_are_converged(tmp_path):
    repo = old_shape(tmp_path)
    converge_all(repo)
    revoke_root(repo, LOCAL_SERVICE)
    assert openable(repo) == [] and service_aces(repo) == []
