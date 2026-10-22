"""Who may read what: the POSIX owner and mode, and on Windows the SIDs and the rights each was given."""

import dataclasses
from pathlib import Path

import pytest
from tests.unit.doctor_support import World, build_bridge, build_host_world

from ctl import winacl
from ctl.doctor import Outcome
from ctl.doctor.permissions import RIGHTS, Permissions
from ctl.doctor.probes import Probes
from ctl.winacl import Ace, Acl

OPERATOR = "S-1-5-21-1111111111-2222222222-3333333333-1001"
OTHER = "S-1-5-21-1111111111-2222222222-3333333333-1002"
INHERIT = winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE
SERVICE = winacl.SID_LOCAL_SERVICE
ADMINS = winacl.SID_ADMINISTRATORS


def acl(*aces: tuple[str, int, int], protected: bool = True) -> Acl:
    return Acl(tuple(Ace(sid, mask, flags) for sid, mask, flags in aces), protected)


def windows(acls: dict[str, Acl], operator: str = OPERATOR, denies: dict[str, tuple[Ace, ...]] | None = None) -> Probes:
    """Probes that read `acls` (and the deny ACEs in `denies`) as the real ones do.

    `acl` leaves the inherit-only ACEs out and `entries` does not.
    """

    def entries(path) -> tuple[list[winacl.Entry], bool]:
        if path.name not in acls:
            raise FileNotFoundError(2, "The system cannot find the file specified", str(path))
        found = acls[path.name]
        denied = [
            winacl.Entry(winacl.ACCESS_DENIED_ACE_TYPE, a.flags, a.mask, a.sid)
            for a in (denies or {}).get(path.name, ())
        ]
        return denied + [
            winacl.Entry(winacl.ACCESS_ALLOWED_ACE_TYPE, a.flags, a.mask, a.sid) for a in found.aces
        ], found.protected

    return Probes(
        windows=True, acl=lambda path: winacl._acl(*entries(path)), entries=entries, operator_sid=lambda root: operator
    )


# What install writes, spelled out independently of `winacl.grants` so a wrong expectation fails here ==================

HOST_ENV = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.READ_WRITE_DELETE, 0))
HOST_SECRETS = acl((ADMINS, winacl.FULL, INHERIT), (SERVICE, winacl.READ_EXECUTE, INHERIT),
                   (OPERATOR, winacl.READ_EXECUTE, INHERIT))
HOST_TOKEN = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ, 0), (OPERATOR, winacl.READ, 0))
BRIDGE_SECRETS = acl((ADMINS, winacl.FULL, INHERIT), (OPERATOR, winacl.MODIFY, INHERIT))
BRIDGE_TOKEN = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.READ_WRITE_DELETE, 0))


@pytest.fixture
def host(tmp_path, monkeypatch) -> World:
    return build_host_world(tmp_path, monkeypatch)[0]


@pytest.fixture
def bridge(tmp_path) -> World:
    return build_bridge(tmp_path)


def host_acls(**changes: Acl) -> dict[str, Acl]:
    return {".env": HOST_ENV, "secrets": HOST_SECRETS, "token": HOST_TOKEN} | changes


def verdicts(world: World, acls: dict[str, Acl], **probe_fields) -> dict[str, tuple[Outcome, str]]:
    permissions = Permissions(world.config, windows(acls, **probe_fields))
    return {name: getattr(permissions, name)() for name in ("env", "secrets_dir", "secrets_token")}


def test_the_acls_install_writes_on_a_host_pass(host):
    assert {name: v[0]
            for name, v in verdicts(host, host_acls()).items()
            } == {"env": Outcome.PASS, "secrets_dir": Outcome.PASS, "secrets_token": Outcome.PASS}


def test_the_acls_install_writes_on_a_bridge_pass(bridge):
    acls = {".env": HOST_ENV, "secrets": BRIDGE_SECRETS, "token": BRIDGE_TOKEN}
    assert {v[0] for v in verdicts(bridge, acls).values()} == {Outcome.PASS}


def test_a_token_ace_widened_from_read_to_full_control_fails(host):
    widened = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.FULL, 0), (OPERATOR, winacl.READ, 0))
    outcome, detail = verdicts(host, host_acls(token=widened))["secrets_token"]
    assert outcome is Outcome.FAIL
    assert SERVICE in detail or "LocalService" in detail
    assert "R" in detail and "F" in detail


def test_the_operator_ace_widened_on_the_token_fails(host):
    widened = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ, 0), (OPERATOR, winacl.FULL, 0))
    assert verdicts(host, host_acls(token=widened))["secrets_token"][0] is Outcome.FAIL


def test_a_token_without_the_operator_ace_fails_naming_the_missing_sid(host):
    narrowed = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ, 0))
    outcome, detail = verdicts(host, host_acls(token=narrowed))["secrets_token"]
    assert outcome is Outcome.FAIL and OPERATOR in detail


def test_an_unexpected_sid_on_the_token_fails(host):
    extra = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ, 0), (OPERATOR, winacl.READ, 0),
                (OTHER, winacl.READ, 0))
    outcome, detail = verdicts(host, host_acls(token=extra))["secrets_token"]
    assert outcome is Outcome.FAIL and OTHER in detail


def test_an_unexpected_principal_on_env_is_a_failure(host):
    extra = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.READ_WRITE_DELETE, 0),
                (winacl.SID_EVERYONE, winacl.READ, 0))
    assert verdicts(host, host_acls(**{".env": extra}))["env"][0] is Outcome.FAIL


def test_the_service_must_not_be_granted_the_env_file(host):
    extra = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.READ_WRITE_DELETE, 0), (SERVICE, winacl.READ, 0))
    outcome, detail = verdicts(host, host_acls(**{".env": extra}))["env"]
    assert outcome is Outcome.FAIL and "unexpected" in detail


def test_broken_inheritance_is_required(host):
    unprotected = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.READ_WRITE_DELETE, 0), protected=False)
    outcome, detail = verdicts(host, host_acls(**{".env": unprotected}))["env"]
    assert outcome is Outcome.FAIL and "inheritance" in detail


def test_a_directory_ace_that_does_not_inherit_fails(host):
    bare = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ_EXECUTE, 0), (OPERATOR, winacl.READ_EXECUTE, 0))
    assert verdicts(host, host_acls(secrets=bare))["secrets_dir"][0] is Outcome.FAIL


def test_an_operator_who_is_also_administrators_is_expected_once(host):
    merged_env = acl((ADMINS, winacl.FULL, 0))
    outcome, detail = verdicts(host, host_acls(**{".env": merged_env}), operator=ADMINS)["env"]
    assert outcome is Outcome.PASS, detail


def test_a_file_that_cannot_be_read_is_a_failure_not_a_crash(host):

    def refuse(path):
        raise PermissionError(5, "Access is denied", str(path))

    permissions = Permissions(host.config, Probes(windows=True, acl=refuse, operator_sid=lambda root: OPERATOR))
    outcome, detail = permissions.secrets_token()
    assert outcome is Outcome.FAIL and "Access is denied" in detail


def test_a_missing_file_is_a_failure_saying_to_install(host):

    def missing(path):
        raise FileNotFoundError(2, "The system cannot find the file specified", str(path))

    permissions = Permissions(host.config, Probes(windows=True, acl=missing, operator_sid=lambda root: OPERATOR))
    outcome, detail = permissions.env()
    assert outcome is Outcome.FAIL and "ctl install" in detail


def test_an_operator_ace_with_delete_on_env_and_on_a_bridge_token_is_shown_as_r_w_d(host, bridge):
    _, detail = verdicts(host, host_acls())["env"]
    assert f"{OPERATOR}:(R,W,D)" in detail
    outcome, detail = verdicts(bridge,
                               {".env": HOST_ENV, "secrets": BRIDGE_SECRETS, "token": BRIDGE_TOKEN})["secrets_token"]
    assert outcome is Outcome.PASS and f"{OPERATOR}:(R,W,D)" in detail


def test_a_legacy_env_whose_operator_ace_lacks_delete_fails_asking_to_reinstall(host):
    legacy = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.READ_WRITE, 0))
    outcome, detail = verdicts(host, host_acls(**{".env": legacy}))["env"]
    path = host.config.root / ".env"
    assert outcome is Outcome.FAIL
    assert detail == (
        f"{path}: unexpected: {OPERATOR}:(R,W); missing: {OPERATOR}:(R,W,D); "
        f"expected exactly {OPERATOR}:(R,W,D), {ADMINS} (Administrators):(F); run `ctl install` to restore it"
    )


# The service's access to what it needs ================================================================================

ID = winacl.INHERITED_ACE
FILES_ONLY = winacl.OBJECT_INHERIT_ACE | winacl.INHERIT_ONLY_ACE
FILE_WRITE_DATA = 0x2
SERVICE_NEEDS = {
    "bin": winacl.READ_EXECUTE,
    "frpc.exe": winacl.READ_EXECUTE,
    "websocat.exe": winacl.READ_EXECUTE,
    "goetia-shim.exe": winacl.READ_EXECUTE,
    "host": winacl.READ_EXECUTE,
    "frpc.toml": winacl.READ,
    "token": winacl.READ,
    "logs": winacl.MODIFY,
}
# The files in `logs` the daemons append to, as `goetia.yaml` names them; one that does not exist yet is no failure.
LOG_FILES = ("frpc.log", "websocat.log")
# What the writer of `logs/<daemon>.log` asks the kernel for. goetia-shim v0.1.0 opens it with
# `OpenOptions::new().create(true).append(true).open(path)` (src/bin/shim/logging.rs:39), and Rust's std on Windows turns
# `append(true)` into `FILE_GENERIC_WRITE & !FILE_WRITE_DATA` (library/std/src/sys/fs/windows.rs, `get_access_mode`).
FILE_GENERIC_WRITE = 0x120116  # windows_sys.rs: FILE_GENERIC_WRITE = 1179926
RUST_APPEND_OPEN = FILE_GENERIC_WRITE & ~FILE_WRITE_DATA
# The old doctor mask: write and append data, read attributes, synchronize. The open above asks for none of the first
# and the last-but-one, and for more besides.
NARROWER_APPEND = 0x2 | 0x4 | 0x80 | 0x100000


def owned(mask: int) -> Acl:
    """A directory `ctl install` owns: protected, the operator and Administrators in full, the service with `mask`."""
    return acl((ADMINS, winacl.FULL, INHERIT), (OPERATOR, winacl.FULL, INHERIT), (SERVICE, mask, INHERIT))


def owned_file(mask: int) -> Acl:
    """A file in one: it holds what it inherits, so it is not protected."""
    return acl((ADMINS, winacl.FULL, ID), (OPERATOR, winacl.FULL, ID), (SERVICE, mask, ID), protected=False)


def service_acls(**changes: Acl) -> dict[str, Acl]:
    """What `ctl install` leaves, keyed by the last component of each path the fake reads (the root is never read)."""
    acls = {
        "bin": owned(winacl.READ_EXECUTE),
        "host": owned(winacl.READ_EXECUTE),
        "logs": owned(winacl.MODIFY),
        "token": HOST_TOKEN,
        ".digests.json": owned_file(winacl.READ_EXECUTE),
        "goetia.exe": owned_file(winacl.READ_EXECUTE),
        "frpc.toml": owned_file(winacl.READ_EXECUTE),
    }
    acls |= {name: owned_file(winacl.READ_EXECUTE) for name in ("frpc.exe", "websocat.exe", "goetia-shim.exe")}
    acls |= {name: owned_file(winacl.MODIFY) for name in LOG_FILES}
    return acls | changes


def service_read(world: World, acls: dict[str, Acl], denies: dict[str, tuple[Ace, ...]] | None = None):
    return Permissions(world.config, windows(acls, denies=denies)).service_read()


def place(world: World, name: str) -> Path:
    root = world.config.root
    where = {
        "frpc.exe": "bin",
        "websocat.exe": "bin",
        "goetia-shim.exe": "bin",
        "frpc.toml": "host",
        "token": "secrets",
        "frpc.log": "logs",
        "websocat.log": "logs",
    }
    return root / where[name] / name if name in where else root / name


def test_the_acls_install_writes_give_the_service_what_it_needs(host):
    outcome, detail = service_read(host, service_acls())
    assert outcome is Outcome.PASS, detail


def test_the_service_read_is_not_applicable_on_posix(host):
    outcome, _ = Permissions(host.config, Probes(windows=False)).service_read()
    assert outcome is Outcome.NOT_APPLICABLE


@pytest.mark.parametrize("name", [*SERVICE_NEEDS, *LOG_FILES])
@pytest.mark.parametrize("flags", [0, ID, FILES_ONLY], ids=["explicit", "inherited", "inherit-only"])
@pytest.mark.parametrize("sid", [SERVICE, winacl.SID_EVERYONE, OTHER], ids=["service", "everyone", "another"])
def test_a_deny_ace_of_any_kind_on_anything_the_service_needs_fails_naming_the_path_and_whom_it_denies(
    host, name, flags, sid
):
    outcome, detail = service_read(host, service_acls(), {name: (Ace(sid, FILE_WRITE_DATA, flags), )})
    assert outcome is Outcome.FAIL
    assert f"{place(host, name)}: has a deny ACE for {sid}" in detail and "ctl install" in detail


@pytest.mark.parametrize("name", [*SERVICE_NEEDS, *LOG_FILES])
def test_an_object_with_no_allow_for_the_service_fails_naming_the_path(host, name):
    bare = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.FULL, 0))
    outcome, detail = service_read(host, service_acls(**{name: bare}))
    assert outcome is Outcome.FAIL
    assert f"{place(host, name)}: LocalService is not allowed" in detail and "it holds no allow" in detail
    assert "ctl install" in detail


def test_a_frpc_toml_moved_into_host_keeps_its_old_acl_and_fails(host):
    """A file moved in from elsewhere keeps the DACL it had, which is the operator's and not the service's."""
    moved = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.FULL, 0), protected=False)
    outcome, detail = service_read(host, service_acls(**{"frpc.toml": moved}))
    toml = host.config.root / "host" / "frpc.toml"
    assert outcome is Outcome.FAIL and f"{toml}: LocalService is not allowed" in detail


@pytest.mark.parametrize(
    "name,narrow", [
        ("bin", winacl.READ),
        ("frpc.exe", winacl.READ),
        ("host", winacl.READ),
        ("logs", winacl.READ_EXECUTE),
    ]
)
def test_an_allow_that_does_not_cover_what_the_service_needs_fails_saying_what_it_holds(host, name, narrow):
    narrowed = acl((ADMINS, winacl.FULL, INHERIT), (SERVICE, narrow, INHERIT))
    outcome, detail = service_read(host, service_acls(**{name: narrowed}))
    assert outcome is Outcome.FAIL
    assert f"{place(host, name)}: LocalService is not allowed" in detail
    assert f"it holds ({RIGHTS[narrow]})" in detail


def test_allows_for_the_service_that_together_cover_what_it_needs_pass(host):
    split = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ, 0), (SERVICE, 0x20, 0))  # read, then execute
    outcome, detail = service_read(host, service_acls(**{"frpc.exe": split}))
    assert outcome is Outcome.PASS, detail


def test_an_allow_the_service_holds_only_by_inheriting_it_counts(host):
    inherited = acl((ADMINS, winacl.FULL, ID), (SERVICE, winacl.READ_EXECUTE, ID), protected=False)
    outcome, detail = service_read(host, service_acls(**{"frpc.toml": inherited}))
    assert outcome is Outcome.PASS, detail


def test_an_allow_that_applies_only_to_new_files_does_not_count_for_the_directory(host):
    files_only = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ_EXECUTE, FILES_ONLY))
    outcome, detail = service_read(host, service_acls(host=files_only))
    assert outcome is Outcome.FAIL and f"{host.config.root / 'host'}: LocalService is not allowed" in detail


@pytest.mark.parametrize("group", [winacl.SID_EVERYONE, winacl.SID_USERS, winacl.SID_AUTHENTICATED_USERS])
def test_an_allow_for_a_group_the_service_is_in_is_not_an_allow_for_the_service(host, group):
    via_group = acl((ADMINS, winacl.FULL, 0), (group, winacl.READ_EXECUTE, 0))
    outcome, detail = service_read(host, service_acls(bin=via_group))
    assert outcome is Outcome.FAIL and f"{host.config.root / 'bin'}: LocalService is not allowed" in detail


def test_files_the_service_never_reads_are_not_judged(host):
    """`goetia.exe` is run by `ctl`, and `.digests.json` is read by doctor, as the operator."""
    bare = acl((ADMINS, winacl.FULL, 0))
    denied = (Ace(SERVICE, FILE_WRITE_DATA, 0), )
    outcome, detail = service_read(
        host, service_acls(**{"goetia.exe": bare, ".digests.json": bare}),
        {"goetia.exe": denied, ".digests.json": denied}
    )
    assert outcome is Outcome.PASS, detail


def test_every_failing_object_is_reported_with_a_count(host):
    bare = acl((ADMINS, winacl.FULL, 0))
    outcome, detail = service_read(host, service_acls(bin=bare, logs=bare))
    assert outcome is Outcome.FAIL
    assert "wrong on 2 path(s)" in detail and f"{host.config.root / 'bin'}:" in detail
    assert f"{host.config.root / 'logs'}:" in detail


def reading(world: World, fail_on: str, error: OSError):
    """The service check with every object readable but the one called `fail_on`, which raises `error`."""
    probes = windows(service_acls())
    read = probes.entries

    def entries(path):
        if path.name == fail_on:
            raise error
        return read(path)

    return Permissions(world.config, dataclasses.replace(probes, entries=entries)).service_read()


@pytest.mark.parametrize("name", SERVICE_NEEDS)
def test_an_object_that_is_missing_fails_saying_to_install(host, name):
    outcome, detail = reading(host, name, FileNotFoundError(2, "The system cannot find the file specified"))
    assert outcome is Outcome.FAIL
    assert f"{place(host, name)}: missing" in detail and "ctl install" in detail


def test_an_object_doctor_cannot_read_fails_instead_of_crashing(host):
    outcome, detail = reading(host, "frpc.toml", PermissionError(5, "Access is denied"))
    assert outcome is Outcome.FAIL and "Access is denied" in detail


# The log files the daemons append to ==================================================================================


@pytest.mark.parametrize("name", LOG_FILES)
def test_a_log_file_that_does_not_exist_yet_is_no_failure(host, name):
    acls = service_acls()
    del acls[name]
    outcome, detail = service_read(host, acls)
    assert outcome is Outcome.PASS, detail


@pytest.mark.parametrize("name", LOG_FILES)
@pytest.mark.parametrize("narrow", [winacl.READ, winacl.READ_EXECUTE])
def test_a_log_file_the_service_cannot_append_to_fails_saying_what_it_holds(host, name, narrow):
    narrowed = acl((ADMINS, winacl.FULL, ID), (SERVICE, narrow, ID), protected=False)
    outcome, detail = service_read(host, service_acls(**{name: narrowed}))
    assert outcome is Outcome.FAIL
    assert f"{place(host, name)}: LocalService is not allowed" in detail and f"it holds ({RIGHTS[narrow]})" in detail


@pytest.mark.parametrize("name", LOG_FILES)
def test_the_access_the_writer_opens_a_log_file_with_is_enough(host, name):
    appending = acl((ADMINS, winacl.FULL, 0), (SERVICE, RUST_APPEND_OPEN, 0))
    outcome, detail = service_read(host, service_acls(**{name: appending}))
    assert outcome is Outcome.PASS, detail


@pytest.mark.parametrize("name", LOG_FILES)
def test_a_log_file_granting_less_than_the_writer_opens_it_with_fails(host, name):
    narrow = acl((ADMINS, winacl.FULL, 0), (SERVICE, NARROWER_APPEND, 0))
    outcome, detail = service_read(host, service_acls(**{name: narrow}))
    assert outcome is Outcome.FAIL and f"{place(host, name)}: LocalService is not allowed" in detail


@pytest.mark.parametrize("name", LOG_FILES)
@pytest.mark.parametrize("bit", [bit for bit in range(32) if RUST_APPEND_OPEN >> bit & 1])
def test_a_log_file_missing_any_one_right_the_writer_asks_for_fails(host, name, bit):
    short = acl((ADMINS, winacl.FULL, 0), (SERVICE, RUST_APPEND_OPEN & ~(1 << bit), 0))
    outcome, detail = service_read(host, service_acls(**{name: short}))
    assert outcome is Outcome.FAIL and f"{place(host, name)}: LocalService is not allowed" in detail


# Creating the log file adds an entry to `logs`: CreateFile with OPEN_ALWAYS needs FILE_ADD_FILE on the directory.
def test_logs_without_the_right_to_add_a_file_fails(host):
    FILE_ADD_FILE = 0x2
    short = acl((ADMINS, winacl.FULL, INHERIT), (SERVICE, winacl.MODIFY & ~FILE_ADD_FILE, INHERIT))
    outcome, detail = service_read(host, service_acls(logs=short))
    assert outcome is Outcome.FAIL and f"{place(host, 'logs')}: LocalService is not allowed" in detail


@pytest.mark.parametrize("name", LOG_FILES)
def test_a_log_file_moved_into_logs_that_keeps_the_acl_it_had_fails(host, name):
    moved = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.FULL, 0), protected=False)
    outcome, detail = service_read(host, service_acls(**{name: moved}))
    assert outcome is Outcome.FAIL and f"{place(host, name)}: LocalService is not allowed" in detail


@pytest.mark.parametrize("name", LOG_FILES)
def test_a_log_file_doctor_cannot_read_fails_instead_of_crashing(host, name):
    outcome, detail = reading(host, name, PermissionError(5, "Access is denied"))
    assert outcome is Outcome.FAIL and f"{place(host, name)}: Access is denied" in detail


def test_the_log_files_checked_are_the_ones_goetia_yaml_has_the_daemons_write():
    import yaml

    from ctl.host import WRITES

    manifest = yaml.safe_load((Path(__file__).resolve().parents[2] / "goetia.yaml").read_text(encoding="utf-8"))
    written = {daemon["logs"] for daemon in manifest["daemons"].values()}
    assert {path for paths in WRITES.values() for path in paths} == written
    assert {Path(path).name for path in written} == set(LOG_FILES)
