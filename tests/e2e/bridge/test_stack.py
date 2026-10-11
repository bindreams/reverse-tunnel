"""The real stack: image built by compose, container started, admin API reached through its publish."""

import hashlib
import json

import pytest
from bridge_support import GOOD_PASSWORD, Project, get, make_project


def published_admin_url(project: Project) -> str:
    result = project.compose("port", "frps", "7500")
    assert result.returncode == 0, result.stderr
    address = result.stdout.strip()
    assert address.startswith("127.0.0.1:"), address
    return f"http://{address}"


@pytest.fixture
def running(project: Project) -> Project:
    project.up()
    return project


def test_starts_with_a_valid_token_and_its_healthcheck_command_succeeds(project: Project):
    """The healthcheck is run once, on request, rather than waited for until Docker's schedule reports a state."""
    project.up()
    listing = project.compose("ps", "--format", "json")
    assert listing.returncode == 0, listing.stderr
    states = [json.loads(line) for line in listing.stdout.splitlines()]
    assert [(s["Service"], s["State"]) for s in states] == [("frps", "running")]
    healthcheck = project.config()["services"]["frps"]["healthcheck"]["test"]
    assert healthcheck[0] == "CMD"
    probe = project.compose("exec", "-T", "frps", *healthcheck[1:])
    assert probe.returncode == 0, probe.stdout + probe.stderr


def test_admin_api_answers_on_the_published_port_from_the_host(running: Project):
    response = get(published_admin_url(running) + "/api/v2/system/info", auth=("", GOOD_PASSWORD))
    assert response.status_code == 200
    assert response.json()["data"]["config"]["subdomainHost"] == "tunnel.example.com"


def test_admin_api_rejects_a_non_empty_username(running: Project):
    response = get(published_admin_url(running) + "/api/v2/system/info", auth=("admin", GOOD_PASSWORD))
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


CAPABILITY_NUMBERS = {"DAC_OVERRIDE": 1, "DAC_READ_SEARCH": 2}


def test_the_running_container_holds_exactly_the_added_capabilities(running: Project):
    status = running.compose("exec", "-T", "frps", "grep", "-E", "^Cap(Eff|Bnd|Prm):", "/proc/1/status")
    assert status.returncode == 0, status.stderr
    expected = sum(1 << CAPABILITY_NUMBERS[name] for name in running.config()["services"]["frps"]["cap_add"])
    masks = {line.split(":")[0]: int(line.split()[1], 16) for line in status.stdout.splitlines()}
    assert masks == {"CapPrm": expected, "CapEff": expected, "CapBnd": expected}


def test_the_running_container_cannot_write_its_root_filesystem_and_keeps_state_on_a_tmpfs(running: Project):
    script = "touch /x 2>&1; grep -c ' /run/rt tmpfs ' /proc/mounts"
    result = running.compose("exec", "-T", "frps", "sh", "-c", script)
    assert "Read-only file system" in result.stdout
    assert result.stdout.splitlines()[-1] == "1"


# The environment frps runs with =======================================================================================

# Valid for the entrypoint's rules, and distinctive enough that a stray default or a rewrite cannot match them.
DOMAIN = "distinct-domain.example.org"
PASSWORD = "Distinct_Admin-Password_0123"
SENTINELS = {
    "RT_SENTINEL_SPACES": "a  b   c",
    "RT_SENTINEL_PUNCTUATION": "Qz9-_.:/=+,;@%^&*()[]{}|<>?~!",
    "RT_SENTINEL_QUOTES": "it's \"quoted\" and \\ backslashed",
}
SENTINEL_FILE = "compose.sentinels.yaml"


def environment_of_pid_one(project: Project) -> dict[str, str]:
    result = project.compose("exec", "-T", "frps", "cat", "/proc/1/environ", extra_files=(SENTINEL_FILE, ))
    assert result.returncode == 0, result.stderr
    entries = [entry for entry in result.stdout.split("\0") if entry]
    return dict(entry.split("=", 1) for entry in entries)


def test_frps_carries_every_rt_variable_exactly_as_given(tmp_path):
    project = make_project(
        tmp_path,
        RT_CONTROL_PORT="0",
        RT_VHOST_PORT="0",
        RT_ADMIN_PORT="0",
        RT_DOMAIN=DOMAIN,
        RT_ADMIN_PASSWORD=PASSWORD,
    )
    # A JSON string is a YAML string; `$` is doubled so that compose does not interpolate it.
    entries = [f"      {name}: {json.dumps(value.replace('$', '$$'))}" for name, value in SENTINELS.items()]
    (project.root / SENTINEL_FILE).write_text("\n".join(["services:", "  frps:", "    environment:", *entries]) + "\n")
    try:
        project.up(extra_files=(SENTINEL_FILE, ))
        environment = environment_of_pid_one(project)
        given = {"RT_DOMAIN": DOMAIN, "RT_ADMIN_PASSWORD": PASSWORD, **SENTINELS}
        assert {name: value for name, value in environment.items() if name.startswith("RT_")} == given
        assert set(environment) - set(given) <= {"PATH", "HOSTNAME", "HOME", "PWD", "OLDPWD", "SHLVL"}
    finally:
        project.down(extra_files=(SENTINEL_FILE, ))
