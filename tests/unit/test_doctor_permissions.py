"""Who may read what: the POSIX owner and mode, and on Windows the SIDs and the rights each was given."""

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


def windows(acls: dict[str, Acl], operator: str = OPERATOR) -> Probes:
    return Probes(windows=True, acl=lambda path: acls[path.name], operator_sid=lambda root: operator)


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
