"""Who may read what: the POSIX owner and mode, and on Windows the SIDs and the rights each was given."""

from pathlib import Path

import pytest
from tests.unit.doctor_support import World, build_bridge, build_host_world

from ctl import winacl
from ctl.doctor import Outcome
from ctl.doctor.permissions import Permissions
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


# The service's read of the deployment =================================================================================

SERVICE_READ = (SERVICE, winacl.READ_EXECUTE, 0)
FILES_ONLY = winacl.OBJECT_INHERIT_ACE | winacl.INHERIT_ONLY_ACE
SERVICE_FILES = (SERVICE, winacl.READ_EXECUTE, FILES_ONLY)
SERVICE_INHERITED = (SERVICE, winacl.READ_EXECUTE, winacl.INHERITED_ACE)
HOST_DIR = acl((ADMINS, winacl.FULL, 0), SERVICE_READ, SERVICE_FILES)


def service_acls(world: World, **changes: Acl) -> dict[str, Acl]:
    """What `ctl install` leaves. The root, `bin` and its files hold the service's ACE, none inheritable. `host` holds
    it for itself and for the files created in it, which inherit it."""
    root = world.config.root
    acls = {p.name: acl((ADMINS, winacl.FULL, 0), SERVICE_READ) for p in [root, root / "bin"]}
    acls |= {p.name: acl((ADMINS, winacl.FULL, 0), SERVICE_READ) for p in (root / "bin").iterdir() if p.is_file()}
    acls |= {"host": HOST_DIR}
    acls |= {p.name: acl((ADMINS, winacl.FULL, 0), SERVICE_INHERITED) for p in (root / "host").iterdir() if p.is_file()}
    return acls | changes


def service_read(world: World, acls: dict[str, Acl], denies: dict[str, tuple[Ace, ...]] | None = None):
    return Permissions(world.config, windows(acls, denies=denies)).service_read()


def test_the_service_read_install_writes_passes(host):
    outcome, detail = service_read(host, service_acls(host))
    assert outcome is Outcome.PASS, detail


def test_the_files_only_ace_on_host_is_read_from_every_entry_because_acl_leaves_it_out(host):
    probes = windows(service_acls(host))
    host_dir = host.config.root / "host"
    assert not [a for a in probes.acl(host_dir).aces if a.flags & winacl.INHERIT_ONLY_ACE]  # as `winacl.read_acl`
    assert [e for e in probes.entries(host_dir)[0] if e.flags & winacl.INHERIT_ONLY_ACE]
    assert Permissions(host.config, probes).service_read()[0] is Outcome.PASS


def test_an_inheritable_service_ace_on_the_root_from_an_earlier_install_fails_asking_to_reinstall(host):
    old = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ_EXECUTE, INHERIT))
    outcome, detail = service_read(host, service_acls(host, **{host.config.root.name: old}))
    assert outcome is Outcome.FAIL
    assert f"{host.config.root}: {SERVICE} (LocalService):(OI)(CI)(RX) is inheritable" in detail
    assert "ctl install" in detail


def test_an_inheritable_service_ace_on_bin_fails(host):
    old = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.READ_EXECUTE, INHERIT))
    outcome, detail = service_read(host, service_acls(host, bin=old))
    assert outcome is Outcome.FAIL and f"{host.config.root / 'bin'}: " in detail and "is inheritable" in detail


def test_a_files_only_service_ace_on_bin_fails(host):
    old = acl((ADMINS, winacl.FULL, 0), SERVICE_READ, SERVICE_FILES)
    outcome, detail = service_read(host, service_acls(host, bin=old))
    assert outcome is Outcome.FAIL and f"{SERVICE} (LocalService):(OI)(IO)(RX) is inheritable" in detail


@pytest.mark.parametrize(
    "flags", [
        INHERIT, INHERIT | winacl.INHERIT_ONLY_ACE, winacl.OBJECT_INHERIT_ACE,
        FILES_ONLY | winacl.NO_PROPAGATE_INHERIT_ACE
    ]
)
def test_a_service_ace_on_host_that_is_not_files_only_fails(host, flags):
    wrong = acl((ADMINS, winacl.FULL, 0), SERVICE_READ, (SERVICE, winacl.READ_EXECUTE, flags))
    outcome, detail = service_read(host, service_acls(host, host=wrong))
    assert outcome is Outcome.FAIL
    assert f"{host.config.root / 'host'}: " in detail and "(OI)(IO)" in detail and "ctl install" in detail


def test_host_without_the_ace_its_new_files_inherit_fails(host):
    old = acl((ADMINS, winacl.FULL, 0), SERVICE_READ)  # the shape of the previous install
    outcome, detail = service_read(host, service_acls(host, host=old))
    assert outcome is Outcome.FAIL
    assert f"{host.config.root / 'host'}: LocalService has no (OI)(IO) ACE" in detail and "ctl install" in detail


def test_host_without_the_ace_for_the_directory_itself_fails(host):
    only_files = acl((ADMINS, winacl.FULL, 0), SERVICE_FILES)
    outcome, detail = service_read(host, service_acls(host, host=only_files))
    assert outcome is Outcome.FAIL
    assert f"{host.config.root / 'host'}: LocalService has no ACE of its own for the directory" in detail


def test_host_with_no_service_ace_fails(host):
    outcome, detail = service_read(host, service_acls(host, host=acl((ADMINS, winacl.FULL, 0))))
    assert outcome is Outcome.FAIL and f"{host.config.root / 'host'}: LocalService has no ACE of its own" in detail


def test_a_frpc_toml_replaced_without_the_service_ace_fails_naming_it(host):
    bare = acl((ADMINS, winacl.FULL, 0), (OPERATOR, winacl.MODIFY, 0))
    outcome, detail = service_read(host, service_acls(host, **{"frpc.toml": bare}))
    toml = host.config.root / "host" / "frpc.toml"
    assert outcome is Outcome.FAIL and f"{toml}: LocalService has no ACE" in detail and "ctl install" in detail


def test_a_frpc_toml_the_previous_install_gave_its_own_ace_passes(host):
    outcome, detail = service_read(
        host, service_acls(host, **{"frpc.toml": acl((ADMINS, winacl.FULL, 0), SERVICE_READ)})
    )
    assert outcome is Outcome.PASS, detail


def test_an_inheritable_service_ace_on_a_file_in_host_fails(host):
    wrong = acl((ADMINS, winacl.FULL, 0), SERVICE_INHERITED, (SERVICE, winacl.READ_EXECUTE, FILES_ONLY))
    outcome, detail = service_read(host, service_acls(host, **{"frpc.toml": wrong}))
    assert outcome is Outcome.FAIL and "is inheritable" in detail


def test_an_inherited_service_ace_that_is_not_read_and_execute_on_a_file_in_host_fails(host):
    widened = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.MODIFY, winacl.INHERITED_ACE))
    outcome, detail = service_read(host, service_acls(host, **{"frpc.toml": widened}))
    assert outcome is Outcome.FAIL and f"{SERVICE} (LocalService):(M) is not (RX)" in detail


def test_a_service_ace_that_is_not_read_and_execute_fails(host):
    widened = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.MODIFY, 0))
    outcome, detail = service_read(host, service_acls(host, bin=widened))
    assert outcome is Outcome.FAIL and f"{SERVICE} (LocalService):(M) is not (RX)" in detail


def test_a_service_ace_on_host_that_is_not_read_and_execute_fails(host):
    widened = acl((ADMINS, winacl.FULL, 0), (SERVICE, winacl.MODIFY, 0), (SERVICE, winacl.MODIFY, FILES_ONLY))
    outcome, detail = service_read(host, service_acls(host, host=widened))
    assert outcome is Outcome.FAIL and f"{SERVICE} (LocalService):(M) is not (RX)" in detail


def test_a_service_ace_that_only_comes_from_the_parent_does_not_count_on_a_file_in_bin(host):
    inherited = acl((ADMINS, winacl.FULL, 0), SERVICE_INHERITED)
    outcome, detail = service_read(host, service_acls(host, **{".digests.json": inherited}))
    assert outcome is Outcome.FAIL and "has no ACE" in detail


def test_a_directory_left_in_bin_is_not_a_file_the_service_reads(host):
    (host.config.root / "bin" / ".staging").mkdir()
    outcome, detail = service_read(host, service_acls(host))
    assert outcome is Outcome.PASS, detail


def test_the_service_read_is_not_applicable_on_posix(host):
    outcome, _ = Permissions(host.config, Probes(windows=False)).service_read()
    assert outcome is Outcome.NOT_APPLICABLE


# A deny, or an ACE written twice ======================================================================================

FILE_WRITE_DATA = 0x2


def places(world: World) -> dict[str, Path]:
    """Each kind of path the service reads. The fake ACLs are keyed on the last component."""
    root = world.config.root
    (binary, *_) = sorted(p for p in (root / "bin").iterdir() if p.is_file())
    return {
        "root": root, "bin": root / "bin", "file in bin": binary, "host": root / "host",
        "file in host": root / "host" / "frpc.toml"
    }


@pytest.mark.parametrize("kind", ["root", "bin", "file in bin", "host", "file in host"])
@pytest.mark.parametrize("flags", [0, winacl.INHERITED_ACE, FILES_ONLY], ids=["explicit", "inherited", "inherit-only"])
def test_a_deny_for_the_service_on_any_path_it_needs_fails_naming_the_path(host, kind, flags):
    path = places(host)[kind]
    outcome, detail = service_read(host, service_acls(host), {path.name: (Ace(SERVICE, FILE_WRITE_DATA, flags), )})
    assert outcome is Outcome.FAIL
    assert f"{path}: LocalService is denied" in detail and "ctl install" in detail


@pytest.mark.parametrize("kind", ["root", "bin", "file in bin", "file in host"])
def test_two_identical_explicit_service_aces_fail_naming_the_path(host, kind):
    path = places(host)[kind]
    twice = acl((ADMINS, winacl.FULL, 0), SERVICE_READ, SERVICE_READ)
    outcome, detail = service_read(host, service_acls(host, **{path.name: twice}))
    assert outcome is Outcome.FAIL
    assert f"{path}: {SERVICE} (LocalService):(RX) is written twice" in detail


def test_two_identical_explicit_service_aces_on_host_fail(host):
    twice = acl((ADMINS, winacl.FULL, 0), SERVICE_READ, SERVICE_FILES, SERVICE_FILES)
    outcome, detail = service_read(host, service_acls(host, host=twice))
    assert outcome is Outcome.FAIL
    assert f"{host.config.root / 'host'}: {SERVICE} (LocalService):(OI)(IO)(RX) is written twice" in detail


def test_a_file_in_host_that_inherits_the_ace_and_holds_it_explicitly_too_is_not_a_duplicate(host):
    both = acl((ADMINS, winacl.FULL, 0), SERVICE_READ, SERVICE_INHERITED)
    outcome, detail = service_read(host, service_acls(host, **{"frpc.toml": both}))
    assert outcome is Outcome.PASS, detail
