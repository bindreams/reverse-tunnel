"""The real stack: image built by compose, container started with `up --wait`, admin API reached through its publish."""

import hashlib
import json

import httpx
import pytest
from bridge_support import GOOD_PASSWORD, Project, make_project


def published_admin_url(project: Project) -> str:
    result = project.compose("port", "frps", "7500")
    assert result.returncode == 0, result.stderr
    address = result.stdout.strip()
    assert address.startswith("127.0.0.1:"), address
    return f"http://{address}"


@pytest.fixture
def running(project: Project) -> Project:
    up = project.compose("up", "--detach", "--wait", "--build")
    assert up.returncode == 0, up.stdout + up.stderr
    return project


def test_starts_and_reports_healthy_with_a_valid_token(project: Project):
    up = project.compose("up", "--detach", "--wait", "--build")
    assert up.returncode == 0, up.stdout + up.stderr
    listing = project.compose("ps", "--format", "json")
    assert listing.returncode == 0, listing.stderr
    states = [json.loads(line) for line in listing.stdout.splitlines()]
    assert [(s["Service"], s["State"], s["Health"]) for s in states] == [("frps", "running", "healthy")]


def test_admin_api_answers_on_the_published_port_from_the_host(running: Project):
    response = httpx.get(published_admin_url(running) + "/api/v2/system/info", auth=("", GOOD_PASSWORD))
    assert response.status_code == 200
    assert response.json()["data"]["config"]["subdomainHost"] == "tunnel.example.com"


def test_admin_api_rejects_a_non_empty_username(running: Project):
    response = httpx.get(published_admin_url(running) + "/api/v2/system/info", auth=("admin", GOOD_PASSWORD))
    assert response.status_code == 401


def test_records_the_loaded_config_digest(running: Project):
    recorded = running.compose("exec", "-T", "frps", "cat", "/run/rt/config.sha256")
    assert recorded.returncode == 0, recorded.stderr
    expected = hashlib.sha256((running.root / "bridge" / "frps.toml").read_bytes()).hexdigest()
    assert recorded.stdout.split()[0] == expected


def test_records_the_loaded_token_digest_of_the_host_file(running: Project):
    recorded = running.compose("exec", "-T", "frps", "cat", "/run/rt/token.sha256")
    assert recorded.returncode == 0, recorded.stderr
    assert recorded.stdout.split()[0] == hashlib.sha256(running.token_file.read_bytes()).hexdigest()


def test_a_rotated_token_file_no_longer_matches_the_recorded_digest(running: Project):
    running.token_file.write_text("f" * 64 + "\n")
    recorded = running.compose("exec", "-T", "frps", "cat", "/run/rt/token.sha256")
    assert recorded.stdout.split()[0] != hashlib.sha256(running.token_file.read_bytes()).hexdigest()


def test_compose_does_not_create_a_missing_token_source(tmp_path):
    project = make_project(tmp_path, RT_CONTROL_PORT="0", RT_VHOST_PORT="0", RT_ADMIN_PORT="0")
    project.token_file.unlink()
    (project.root / "secrets").rmdir()
    try:
        created = project.compose("up", "--detach", "--build")
        assert created.returncode != 0
        assert "secrets/token" in created.stderr
        assert not (project.root / "secrets").exists()
    finally:
        down = project.compose("down", "--volumes", "--remove-orphans", "--rmi", "local")
        assert down.returncode == 0, down.stderr
