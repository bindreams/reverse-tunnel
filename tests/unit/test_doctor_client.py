"""A client has no daemon and no tunnel of its own, so its doctor checks only what `ctl install` put on disk."""

import json

import pytest
from tests.unit.doctor_support import World, build_client, by_name, failures

from ctl import doctor
from ctl.doctor import Outcome


@pytest.fixture
def world(tmp_path) -> World:
    return build_client(tmp_path)


def checks_of(world: World):
    return by_name(doctor.run(world.config, world.probes()))


def test_a_client_runs_no_docker_no_network_and_no_goetia(world):
    world.docker.on("version", returncode=1)  # would fail the run if asked
    checks_of(world)
    assert world.docker.calls == [] and world.net.requests == [] and world.tcp.calls == []


def test_digest_drift_in_bin_is_a_failure(world):
    (world.root / "bin" / "websocat").write_bytes(b"tampered")
    check = checks_of(world)["bin_digests_match_record"]
    assert check.outcome is Outcome.FAIL and "websocat" in check.detail


def test_a_client_that_was_never_installed_says_so(world):
    (world.root / "bin" / ".digests.json").unlink()
    (world.root / "bin" / "websocat").unlink()
    check = checks_of(world)["bin_digests_match_record"]
    assert check.outcome is Outcome.FAIL and "ctl install" in check.detail


def test_a_record_that_omits_websocat_is_a_failure(world):
    (world.root / "bin" / ".digests.json").write_text(json.dumps({}), encoding="utf-8")
    assert checks_of(world)["bin_digests_match_record"].outcome is Outcome.FAIL


def test_a_record_that_cannot_be_trusted_is_a_failure_not_a_crash(world):
    (world.root / "bin" / ".digests.json").write_text("{not json", encoding="utf-8")
    assert checks_of(world)["bin_digests_match_record"].outcome is Outcome.FAIL


def test_loose_env_permissions_are_a_failure(world):
    world.loosen(world.root / ".env", 0o644)
    assert failures(list(checks_of(world).values())) == ["env_permissions"]
