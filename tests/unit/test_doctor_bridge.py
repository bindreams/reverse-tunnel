"""The bridge's checks: Docker and the container, what frps says about itself, what it loaded, and its front."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import httpx
import pytest
from tests.unit.deployment_support import write_env
from tests.unit.doctor_support import (
    IMAGE_ENV,
    IMAGE_ID,
    PORT_BINDINGS,
    PS_ENTRY,
    World,
    build_bridge,
    by_name,
    failures,
)

from ctl import doctor
from ctl.config import Role
from ctl.doctor.hardening import MASKED_PATHS, READONLY_PATHS
from ctl.host import token_digest
from ctl.install import install
from ctl.doctor import Outcome


@pytest.fixture
def world(tmp_path) -> World:
    return build_bridge(tmp_path, RT_PUBLIC_HOST="tunnel.example.com")


def checks_of(world: World, **overrides):
    return by_name(doctor.run(world.config, world.probes(**overrides)))


# Docker ===============================================================================================================


@pytest.mark.parametrize(
    "arrange", [
        pytest.param(
            lambda docker, command: docker.raises(command, error=FileNotFoundError("docker")), id="not-installed"
        ),
        pytest.param(
            lambda docker, command: docker.on(command, returncode=1, stderr="Cannot connect to the Docker daemon"),
            id="daemon-down",
        ),
        pytest.param(
            lambda docker, command: docker.raises(command, error=subprocess.TimeoutExpired("docker", 60)), id="hung"
        ),
    ]
)
def test_docker_unavailable_is_one_named_failure_not_ten(world, arrange):
    # `docker info` is as unusable as `docker version`, so a check that asks the daemon first cannot hide behind it.
    for command in ("version", "info"):
        arrange(world.docker, command)
    checks = checks_of(world)
    assert failures(list(checks.values())) == ["docker_reachable"]
    assert "Docker" in checks["docker_reachable"].detail
    for name in (
        "container_healthy", "restart_policy", "container_hardening", "control_port_published", "config_skew",
        "token_skew"
    ):
        assert checks[name].outcome is Outcome.NOT_APPLICABLE
        assert "docker_reachable" in checks[name].detail


def test_docker_down_and_nothing_answering_on_loopback_is_exactly_one_docker_failure(world):
    """The usual cause of both is the same: the stack is not up. Docker is named once and nothing else fails."""
    world.docker.on("version", returncode=1, stderr="Cannot connect to the Docker daemon")
    world.net.down = True
    checks = checks_of(world)
    assert failures(list(checks.values())) == ["docker_reachable"]
    for name in ("admin_healthz", "vhost_answers_404", "registered_labels", "label_collisions"):
        assert checks[name].outcome is Outcome.NOT_APPLICABLE and "docker_reachable" in checks[name].detail


def test_docker_down_but_frps_answering_keeps_the_real_results(world):
    world.docker.on("version", returncode=1, stderr="Cannot connect to the Docker daemon")
    checks = checks_of(world)
    for name in ("admin_healthz", "registered_labels", "label_collisions"):
        assert checks[name].outcome is Outcome.PASS


def test_docker_down_and_a_wrong_admin_password_is_still_a_failure_of_that_check(world):
    world.docker.on("version", returncode=1, stderr="Cannot connect to the Docker daemon")

    def deny(request):
        return httpx.Response(401) if request.url.path.startswith("/api") else httpx.Response(200)

    checks = checks_of(world, transport=httpx.MockTransport(deny))
    assert checks["registered_labels"].outcome is Outcome.FAIL


def test_docker_unavailable_still_checks_what_does_not_need_it(world):
    world.docker.on("version", returncode=1, stderr="Cannot connect to the Docker daemon")
    checks = checks_of(world)
    assert checks["admin_healthz"].outcome is Outcome.PASS
    assert checks["env_permissions"].outcome is Outcome.PASS


def test_the_daemons_own_words_are_in_the_failure(world):
    world.docker.on(
        "version", returncode=1, stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
    )
    assert "Cannot connect to the Docker daemon" in checks_of(world)["docker_reachable"].detail


# The container ========================================================================================================


def test_a_missing_container_fails_and_says_how_to_start_it(world):
    world.docker.on("ps", stdout="")
    checks = checks_of(world)
    assert checks["container_healthy"].outcome is Outcome.FAIL
    assert "docker compose up" in checks["container_healthy"].detail


@pytest.mark.parametrize(
    "state,health", [("exited", ""), ("restarting", ""), ("running", "unhealthy"), ("running", "starting"),
                     ("created", "")]
)
def test_a_container_that_is_not_up_and_healthy_fails_naming_its_state(world, state, health):
    world.docker.healthy(state=state, health=health)
    detail = checks_of(world)["container_healthy"]
    assert detail.outcome is Outcome.FAIL
    assert state in detail.detail


def test_compose_ps_as_a_json_array_is_read_too(world):
    world.docker.on("ps", stdout=json.dumps([PS_ENTRY]))
    assert checks_of(world)["container_healthy"].outcome is Outcome.PASS


def test_a_down_container_makes_its_http_checks_not_applicable_rather_than_four_failures(world):
    world.docker.healthy(state="exited", health="")
    checks = checks_of(world)
    assert failures(list(checks.values())) == ["container_healthy"]
    for name in ("admin_healthz", "registered_labels", "label_collisions", "config_skew", "token_skew"):
        assert checks[name].outcome is Outcome.NOT_APPLICABLE and "container_healthy" in checks[name].detail


def test_a_compose_project_that_cannot_be_listed_is_one_failure_with_composes_words(world):
    world.docker.on("ps", returncode=1, stderr="required variable RT_DOMAIN is missing a value")
    checks = checks_of(world)
    assert failures(list(checks.values())) == ["container_healthy"]
    assert "RT_DOMAIN is missing" in checks["container_healthy"].detail
    for name in ("restart_policy", "control_port_published", "config_skew", "token_skew"):
        assert checks[name].outcome is Outcome.NOT_APPLICABLE and "container_healthy" in checks[name].detail


def test_a_listing_that_is_not_json_is_a_failure_not_a_crash(world):
    world.docker.on("ps", stdout="this is not json\n")
    assert checks_of(world)["container_healthy"].outcome is Outcome.FAIL


def test_a_project_without_an_frps_service_has_no_container(world):
    world.docker.on("ps", stdout=json.dumps({"Service": "other", "State": "running"}) + "\n")
    check = checks_of(world)["container_healthy"]
    assert check.outcome is Outcome.FAIL and "docker compose up" in check.detail


def test_an_inspect_that_fails_fails_the_checks_that_need_it_with_dockers_words(world):
    world.docker.on("inspect", returncode=1, stderr="permission denied while trying to connect")
    checks = checks_of(world)
    for name in ("restart_policy", "control_port_published", "vhost_answers_404"):
        assert checks[name].outcome is Outcome.FAIL and "permission denied" in checks[name].detail


def test_an_inspect_of_a_container_that_is_gone_skips_the_checks_that_need_it(world):
    world.docker.on("inspect", returncode=1, stderr="Error: No such object: 0123456789ab")
    checks = checks_of(world)
    for name in ("restart_policy", "control_port_published", "vhost_answers_404", "container_hardening"):
        assert checks[name].outcome is Outcome.NOT_APPLICABLE and "container_healthy" in checks[name].detail


@pytest.mark.parametrize("policy", ["no", "", "on-failure"])
def test_a_container_restart_policy_that_does_not_survive_a_reboot_is_a_failure(world, policy):
    world.docker.healthy(restart=policy)
    check = checks_of(world)["restart_policy"]
    assert check.outcome is Outcome.FAIL
    assert "restart" in check.detail and "unless-stopped" in check.detail


@pytest.mark.parametrize("policy", ["unless-stopped", "always"])
def test_only_always_and_unless_stopped_pass(world, policy):
    world.docker.healthy(restart=policy)
    assert checks_of(world)["restart_policy"].outcome is Outcome.PASS


def test_a_null_restart_policy_is_its_own_named_failure(world):
    world.docker.altered(lambda document: document["HostConfig"].update(RestartPolicy=None))
    check = checks_of(world)["restart_policy"]
    assert check.outcome is Outcome.FAIL and "RestartPolicy" in check.detail and "null" in check.detail


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_the_control_port_must_be_published_on_tcp_and_udp(world, protocol):
    bindings = {key: value for key, value in PORT_BINDINGS.items() if key != f"8001/{protocol}"}
    world.docker.healthy(bindings=bindings)
    check = checks_of(world)["control_port_published"]
    assert check.outcome is Outcome.FAIL and protocol in check.detail


def test_the_control_port_published_somewhere_else_fails(world):
    bindings = PORT_BINDINGS | {"8001/udp": [{"HostIp": "", "HostPort": "9999"}]}
    world.docker.healthy(bindings=bindings)
    check = checks_of(world)["control_port_published"]
    assert check.outcome is Outcome.FAIL and "9999" in check.detail


# The container's security settings ====================================================================================


def host_config(**fields):
    return lambda document: document["HostConfig"].update(fields)


def config(**fields):
    return lambda document: document["Config"].update(fields)


def network_ports(**ports):
    return lambda document: document["NetworkSettings"]["Ports"].update(ports)


def mounts(change):
    return lambda document: change(document["Mounts"])


def hardening(world: World):
    return checks_of(world)["container_hardening"]


def test_container_hardening_passes_for_the_shipped_compose_shape(world):
    check = hardening(world)
    assert check.outcome is Outcome.PASS
    assert check.detail == "the container matches compose.yaml's security settings"


DOCKER_SOCKET = {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True}
# Each case: the edit, the field the message names, and the value text it reports on that same line.
HARDENING_VIOLATIONS = [
    pytest.param(host_config(CapDrop=[]), "HostConfig.CapDrop", "[]", id="no-cap-drop"),
    pytest.param(host_config(CapDrop=["NET_RAW"]), "HostConfig.CapDrop", '["NET_RAW"]', id="cap-drop-without-all"),
    pytest.param(
        host_config(CapAdd=["DAC_READ_SEARCH", "SYS_ADMIN"]),
        "HostConfig.CapAdd",
        '["DAC_READ_SEARCH", "SYS_ADMIN"]',
        id="extra-capability",
    ),
    pytest.param(host_config(CapAdd=[]), "HostConfig.CapAdd", "[]", id="capability-missing"),
    pytest.param(host_config(Privileged=True), "HostConfig.Privileged", "true", id="privileged"),
    pytest.param(
        host_config(SecurityOpt=["seccomp=unconfined"]),
        "HostConfig.SecurityOpt",
        '["seccomp=unconfined"]',
        id="seccomp-unconfined-alone",
    ),
    pytest.param(
        host_config(SecurityOpt=["no-new-privileges:true", "seccomp=unconfined"]),
        "HostConfig.SecurityOpt",
        '["no-new-privileges:true", "seccomp=unconfined"]',
        id="seccomp-unconfined-beside-no-new-privileges",
    ),
    pytest.param(host_config(SecurityOpt=[]), "HostConfig.SecurityOpt", "[]", id="no-new-privileges-missing"),
    pytest.param(
        host_config(SecurityOpt=["no-new-privileges:false"]),
        "HostConfig.SecurityOpt",
        '["no-new-privileges:false"]',
        id="npp-false",
    ),
    pytest.param(host_config(NetworkMode="host"), "HostConfig.NetworkMode", '"host"', id="host-network"),
    pytest.param(host_config(NetworkMode="none"), "HostConfig.NetworkMode", '"none"', id="no-network"),
    pytest.param(
        host_config(NetworkMode="container:abc123"),
        "HostConfig.NetworkMode",
        '"container:abc123"',
        id="shared-network"
    ),
    pytest.param(host_config(PidMode="host"), "HostConfig.PidMode", '"host"', id="host-pid"),
    pytest.param(host_config(UsernsMode="host"), "HostConfig.UsernsMode", '"host"', id="host-userns"),
    pytest.param(host_config(IpcMode="host"), "HostConfig.IpcMode", '"host"', id="host-ipc"),
    pytest.param(host_config(IpcMode="container:abc123"), "HostConfig.IpcMode", '"container:abc123"', id="shared-ipc"),
    pytest.param(host_config(IpcMode="shareable"), "HostConfig.IpcMode", '"shareable"', id="shareable-ipc"),
    pytest.param(host_config(IpcMode=""), "HostConfig.IpcMode", '""', id="empty-ipc"),
    pytest.param(lambda document: document["HostConfig"].pop("IpcMode"), "HostConfig.IpcMode", "null", id="absent-ipc"),
    pytest.param(host_config(MaskedPaths=[]), "HostConfig.MaskedPaths", "[]", id="no-masked-paths"),
    pytest.param(
        host_config(MaskedPaths=sorted(MASKED_PATHS - {"/proc/kcore"})),
        "HostConfig.MaskedPaths",
        json.dumps(sorted(MASKED_PATHS - {"/proc/kcore"})),
        id="masked-paths-without-kcore",
    ),
    pytest.param(host_config(ReadonlyPaths=[]), "HostConfig.ReadonlyPaths", "[]", id="no-readonly-paths"),
    pytest.param(
        host_config(ReadonlyPaths=sorted(READONLY_PATHS - {"/proc/sys"})),
        "HostConfig.ReadonlyPaths",
        json.dumps(sorted(READONLY_PATHS - {"/proc/sys"})),
        id="readonly-paths-without-proc-sys",
    ),
    pytest.param(host_config(UTSMode="host"), "HostConfig.UTSMode", '"host"', id="host-uts"),
    pytest.param(host_config(CgroupnsMode="host"), "HostConfig.CgroupnsMode", '"host"', id="host-cgroupns"),
    pytest.param(
        host_config(Devices=[{"PathOnHost": "/dev/mem"}]),
        "HostConfig.Devices",
        '[{"PathOnHost": "/dev/mem"}]',
        id="device",
    ),
    pytest.param(
        host_config(Sysctls={"net.ipv4.ip_forward": "1"}),
        "HostConfig.Sysctls",
        '{"net.ipv4.ip_forward": "1"}',
        id="sysctl",
    ),
    pytest.param(
        host_config(DeviceCgroupRules=["c *:* rwm"]),
        "HostConfig.DeviceCgroupRules",
        '["c *:* rwm"]',
        id="device-cgroup-rule",
    ),
    pytest.param(
        host_config(DeviceRequests=[{"Driver": "nvidia"}]),
        "HostConfig.DeviceRequests",
        '[{"Driver": "nvidia"}]',
        id="device-request",
    ),
    pytest.param(host_config(GroupAdd=["0"]), "HostConfig.GroupAdd", '["0"]', id="group-add-root"),
    pytest.param(host_config(GroupAdd=["disk", "42"]), "HostConfig.GroupAdd", '["disk", "42"]', id="group-add-several"),
    pytest.param(host_config(Runtime="nvidia"), "HostConfig.Runtime", '"nvidia"', id="another-runtime"),
    pytest.param(host_config(Runtime=""), "HostConfig.Runtime", '""', id="no-runtime"),
    pytest.param(config(User="root"), "Config.User", '"root"', id="user"),
    pytest.param(
        mounts(lambda found: found.append(DOCKER_SOCKET)),
        "Mounts",
        "a bind of /var/run/docker.sock at /var/run/docker.sock, which reaches the host",
        id="docker-socket",
    ),
    pytest.param(
        mounts(lambda found: found[0].update(RW=True)),
        "Mounts",
        "/rt/secrets/token not read-only (RW is true)",
        id="writable-token-mount"
    ),
    pytest.param(
        mounts(lambda found: found[1].update(RW=True)),
        "Mounts",
        "/rt/bridge/frps.toml not read-only (RW is true)",
        id="writable-config-mount",
    ),
    pytest.param(mounts(lambda found: found.pop()), "Mounts", "no /rt/bridge/frps.toml", id="config-mount-missing"),
    pytest.param(
        mounts(lambda found: found[0].update(RW=None)),
        "Mounts",
        "/rt/secrets/token not read-only (RW is null)",
        id="null-rw-token-mount",
    ),
    pytest.param(
        mounts(lambda found: found[1].pop("RW")),
        "Mounts",
        "/rt/bridge/frps.toml not read-only (RW is null)",
        id="absent-rw-config-mount",
    ),
    pytest.param(
        mounts(lambda found: found[0].update(Source="/etc/shadow")),
        "Mounts",
        "/rt/secrets/token coming from /etc/shadow",
        id="token-mount-from-elsewhere",
    ),
    pytest.param(
        host_config(PortBindings=PORT_BINDINGS | {"7500/tcp": [{"HostIp": "", "HostPort": "7500"}]}),
        "HostConfig.PortBindings[7500/tcp]",
        '[""]',
        id="admin-port-on-every-interface",
    ),
    pytest.param(
        host_config(PortBindings=PORT_BINDINGS | {"7500/tcp": [{"HostIp": "0.0.0.0", "HostPort": "7500"}]}),
        "HostConfig.PortBindings[7500/tcp]",
        '["0.0.0.0"]',
        id="admin-port-on-the-wildcard",
    ),
    pytest.param(host_config(PublishAllPorts=True), "HostConfig.PublishAllPorts", "true", id="publish-all-ports"),
    pytest.param(
        network_ports(**{"7500/tcp": [{"HostIp": "0.0.0.0", "HostPort": "49153"}]}),
        "NetworkSettings.Ports[7500/tcp]",
        '["0.0.0.0"]',
        id="admin-port-published-on-the-wildcard",
    ),
    pytest.param(
        network_ports(
            **{"7500/tcp": [{"HostIp": "127.0.0.1", "HostPort": "7500"}, {"HostIp": "::", "HostPort": "7500"}]}
        ),
        "NetworkSettings.Ports[7500/tcp]",
        '["127.0.0.1", "::"]',
        id="admin-port-published-on-every-ipv6-interface",
    ),
]


def violation_line(field: str, value: str) -> str:
    """The start of the line `container_hardening` writes for `field` with the found `value`."""
    if field == "Mounts":
        return f"Mounts has {value};"
    if field.endswith("]"):
        return f"{field} publishes on {value};"
    return f"{field} is {value};"


@pytest.mark.parametrize(("change", "field", "value"), HARDENING_VIOLATIONS)
def test_container_hardening_names_each_violation(world, change, field, value):
    world.docker.altered(change)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "\n- " + violation_line(field, value) in check.detail, check.detail


@pytest.mark.parametrize(
    "change", [
        pytest.param(host_config(ReadonlyRootfs=False), id="writable-rootfs"),
        pytest.param(host_config(ReadonlyRootfs=None), id="null-readonly-rootfs"),
        pytest.param(host_config(Tmpfs={"/run/rt": "mode=0777,exec", "/tmp": ""}), id="different-tmpfs"),
        pytest.param(host_config(Tmpfs={}), id="no-tmpfs"),
        pytest.param(host_config(Tmpfs=None), id="null-tmpfs"),
    ]
)
def test_the_containers_interior_is_not_held_to_compose_yamls_defaults(world, change):
    # A writable root and other tmpfs mounts keep the container inside itself: compose.yaml ships them, doctor does not
    # require them.
    world.docker.altered(change)
    assert hardening(world).outcome is Outcome.PASS


def test_the_hardening_failure_says_recreating_from_compose_yaml_fixes_a_container_with_no_override(world):
    world.docker.altered(host_config(Privileged=True))
    detail = hardening(world).detail
    assert "created before an upgrade that tightened these rules" in detail
    assert "recreate" in detail.lower() and "docker compose up -d --force-recreate" in detail


def test_an_env_file_that_adds_variables_is_named_by_variable_and_never_by_value(world):
    world.docker.altered(
        lambda document: document["Config"]["Env"].extend(["RT_TOKEN=sekrit-token-value", "RT_LABEL=alpha"])
    )
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "RT_TOKEN" in check.detail and "RT_LABEL" in check.detail
    assert "sekrit-token-value" not in check.detail and "alpha" not in check.detail


def test_a_variable_the_image_declares_is_not_a_violation(world):
    # Present in the shipped document already; a second copy is no new name.
    world.docker.altered(lambda document: document["Config"]["Env"].append(IMAGE_ENV[0]))
    assert hardening(world).outcome is Outcome.PASS


def test_the_image_is_asked_by_the_containers_image_id_not_by_its_tag(world):
    hardening(world)
    assert ["image", "inspect", IMAGE_ID] in [call[:3] for call in world.docker.calls]


def test_an_image_inspect_that_fails_fails_the_check_closed_with_dockers_words(world):
    world.docker.on("image", "inspect", returncode=1, stderr="No such image")
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "No such image" in check.detail


def test_a_daemon_that_cannot_say_its_defaults_fails_the_check_closed_with_dockers_words(world):
    world.docker.on("info", returncode=1, stderr="permission denied while trying to connect")
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "permission denied" in check.detail


@pytest.mark.parametrize("mode", ["host", ""])
def test_a_cgroupns_mode_other_than_private_fails(world, mode):
    world.docker.altered(host_config(CgroupnsMode=mode))
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "HostConfig.CgroupnsMode" in check.detail


def test_the_runtime_the_daemon_defaults_to_is_the_one_the_container_must_use(world):
    world.docker.on("info", stdout=json.dumps({"DefaultRuntime": "crun"}))
    world.docker.altered(host_config(Runtime="crun"))
    assert hardening(world).outcome is Outcome.PASS


def test_a_container_running_another_entrypoint_and_command_than_the_images_passes(world):
    world.docker.altered(config(Entrypoint=["/bin/sh", "-c"], Cmd=["echo", "hello"]))
    assert hardening(world).outcome is Outcome.PASS


def test_a_mount_source_is_compared_resolved_on_both_sides(world):
    world.docker.altered(
        mounts(lambda found: found[0].update(Source=str(world.root / "elsewhere" / ".." / "secrets" / "token")))
    )
    assert hardening(world).outcome is Outcome.PASS


def test_a_volume_at_a_wanted_target_is_a_violation(world):
    volume = {"Type": "volume", "Name": "data", "Destination": "/rt/secrets/token", "RW": False}
    world.docker.altered(mounts(lambda found: found.__setitem__(0, volume)))
    detail = hardening(world).detail
    assert "\n- Mounts has a volume of data at /rt/secrets/token;" in detail
    assert "\n- Mounts has no /rt/secrets/token;" in detail


# Mounts beyond the two binds ------------------------------------------------------------------------------------------


def volume_mount(name: str = "data", target: str = "/data") -> dict:
    return {
        "Type": "volume", "Name": name, "Driver": "local", "Source": f"/var/lib/docker/volumes/{name}/_data",
        "Destination": target, "RW": True
    }


def mounted(*extra: dict):
    return mounts(lambda found: found.extend(extra))


def privileged_with(world, *extra: dict) -> None:
    """A privileged container that also mounts the volumes `extra` describes."""
    world.docker.altered(lambda document: (host_config(Privileged=True)(document), mounted(*extra)(document)))


@pytest.mark.parametrize("options", [None, {}])
def test_an_anonymous_local_volume_with_no_options_passes(world, options):
    world.docker.altered(mounted(volume_mount("a1b2c3")))
    world.docker.volume("a1b2c3", options=options)
    assert hardening(world).outcome is Outcome.PASS


def test_the_volume_is_asked_for_its_options_by_name(world):
    world.docker.altered(mounted(volume_mount()))
    world.docker.volume("data")
    hardening(world)
    assert ["volume", "inspect", "data"] in world.docker.calls


@pytest.mark.parametrize(
    "options", [
        pytest.param({"type": "none", "o": "bind", "device": "/etc"}, id="bind-to-a-host-path"),
        pytest.param({"type": "nfs", "o": "addr=nas.example.com,rw", "device": ":/export"}, id="nfs"),
    ]
)
def test_a_local_volume_with_driver_options_fails_naming_the_volume_and_the_options(world, options):
    world.docker.altered(mounted(volume_mount()))
    world.docker.volume("data", options=options)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "\n- Mounts has a volume of data at /data, " in check.detail
    assert "driver options" in check.detail and options["type"] in check.detail


def test_a_volume_of_another_driver_fails_naming_the_volume_and_the_driver(world):
    world.docker.altered(mounted(volume_mount()))
    world.docker.volume("data", driver="rexray/ebs")
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "\n- Mounts has a volume of data at /data, " in check.detail and "rexray/ebs" in check.detail


def test_a_volume_that_vanished_before_volume_inspect_is_not_applicable_not_a_docker_problem(world):
    world.docker.altered(mounted(volume_mount()))
    world.docker.on(
        "volume", "inspect", "data", returncode=1, stderr="Error response from daemon: No such volume: data"
    )
    check = hardening(world)
    assert check.outcome is Outcome.NOT_APPLICABLE and "container_healthy" in check.detail


def test_a_volume_inspect_that_fails_fails_the_check_closed_with_dockers_words(world):
    world.docker.altered(mounted(volume_mount()))
    world.docker.on("volume", "inspect", "data", returncode=1, stderr="permission denied while trying to connect")
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "permission denied" in check.detail


@pytest.mark.parametrize(("stderr", "reason"), [
    pytest.param("Error response from daemon: No such volume: data", "is gone", id="vanished"),
    pytest.param("permission denied while trying to connect", "permission denied", id="inspect-fails"),
])
def test_a_volume_that_cannot_be_inspected_does_not_hide_the_other_violations(world, stderr, reason):
    privileged_with(world, volume_mount())
    world.docker.on("volume", "inspect", "data", returncode=1, stderr=stderr)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "\n- HostConfig.Privileged is true" in check.detail
    assert "\n- Mounts has a volume of data at /data, which could not be inspected" in check.detail
    assert reason in check.detail


def test_every_volume_that_cannot_be_inspected_is_named(world):
    privileged_with(world, volume_mount("a"), volume_mount("b", "/b"))
    world.docker.on("volume", "inspect", "a", returncode=1, stderr="No such volume: a")
    world.docker.on("volume", "inspect", "b", returncode=1, stderr="permission denied")
    detail = hardening(world).detail
    assert "volume of a at /data, which could not be inspected" in detail
    assert "volume of b at /b, which could not be inspected" in detail


def test_with_nothing_else_wrong_a_failed_volume_lookup_outranks_a_vanished_volume(world):
    world.docker.altered(mounted(volume_mount("a"), volume_mount("b", "/b")))
    world.docker.on("volume", "inspect", "a", returncode=1, stderr="No such volume: a")
    world.docker.on("volume", "inspect", "b", returncode=1, stderr="permission denied")
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "permission denied" in check.detail


@pytest.mark.parametrize("document", ["[null]", "[[]]", '["x"]', "[]", "{}", "not json"])
def test_a_volume_inspect_that_is_not_an_object_fails_the_check_with_a_message(world, document):
    world.docker.altered(mounted(volume_mount()))
    world.docker.on("volume", "inspect", "data", stdout=document)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "`docker volume inspect` printed something that is not a volume's configuration" in check.detail


def test_a_volume_mount_with_no_name_fails_since_its_options_cannot_be_read(world):
    world.docker.altered(mounted(volume_mount() | {"Name": ""}))
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "\n- Mounts has a volume of nothing at /data, " in check.detail


def test_a_read_only_bind_of_the_docker_socket_fails(world):
    world.docker.altered(mounted(DOCKER_SOCKET | {"RW": False, "Mode": "ro"}))
    detail = hardening(world).detail
    assert "\n- Mounts has a bind of /var/run/docker.sock at /var/run/docker.sock" in detail


@pytest.mark.parametrize("kind", ["image", "npipe", "cluster", "devpts", ""])
def test_a_mount_of_any_other_type_fails_closed(world, kind):
    world.docker.altered(mounted({"Type": kind, "Source": "x", "Destination": "/x", "RW": False}))
    detail = hardening(world).detail
    assert f"\n- Mounts has a {kind or 'mount'} of x at /x" in detail


def test_a_tmpfs_mount_passes(world):
    world.docker.altered(mounted({"Type": "tmpfs", "Destination": "/scratch", "RW": True}))
    assert hardening(world).outcome is Outcome.PASS


def test_a_second_mount_at_a_wanted_target_is_a_violation(world):
    world.docker.altered(mounts(lambda found: found.append(dict(found[0]))))
    source = str(world.root / "secrets" / "token")
    assert f"\n- Mounts has a bind of {source} at /rt/secrets/token;" in hardening(world).detail


def test_a_mount_source_that_cannot_be_resolved_is_a_violation_with_the_error(world, monkeypatch):
    resolve = Path.resolve

    def failing(self, *args, **kwargs):
        if self == Path("/etc/loop"):
            raise OSError("Too many levels of symbolic links")
        return resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", failing)
    world.docker.altered(mounts(lambda found: found[0].update(Source="/etc/loop")))
    detail = hardening(world).detail
    assert "\n- Mounts has /rt/secrets/token coming from /etc/loop, which cannot be resolved" in detail
    assert "Too many levels of symbolic links" in detail


NULLED = [
    pytest.param(host_config(CapDrop=None), "HostConfig.CapDrop is null;", id="CapDrop"),
    pytest.param(host_config(SecurityOpt=None), "HostConfig.SecurityOpt is null;", id="SecurityOpt"),
    pytest.param(lambda document: document.update(Mounts=None), "Mounts has no /rt/secrets/token;", id="Mounts"),
    pytest.param(host_config(CapAdd=None), "HostConfig.CapAdd is [];", id="CapAdd"),
    pytest.param(
        lambda document: document.update(Config=None),
        "`docker inspect` has no Config for the container, so its settings cannot be confirmed",
        id="null-Config",
    ),
    pytest.param(
        lambda document: document.pop("HostConfig"),
        "`docker inspect` has no HostConfig for the container, so its settings cannot be confirmed",
        id="missing-HostConfig",
    ),
    pytest.param(
        lambda document: document.update(HostConfig=None),
        "`docker inspect` has no HostConfig for the container, so its settings cannot be confirmed",
        id="null-HostConfig",
    ),
    pytest.param(
        lambda document: document.pop("Image"),
        "`docker inspect` has no Image (the ID of the container's image), so the variables the image declares are "
        "unknown",
        id="missing-Image",
    ),
    pytest.param(host_config(MaskedPaths=None), "HostConfig.MaskedPaths is null;", id="MaskedPaths"),
    pytest.param(host_config(ReadonlyPaths=None), "HostConfig.ReadonlyPaths is null;", id="ReadonlyPaths"),
    pytest.param(host_config(IpcMode=None), "HostConfig.IpcMode is null;", id="IpcMode"),
]


@pytest.mark.parametrize(("change", "cause"), NULLED)
def test_container_hardening_fails_closed_on_null_fields(world, change, cause):
    world.docker.altered(change)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and cause in check.detail


def test_container_hardening_lists_every_violation_at_once(world):

    def weaken(document):
        document["HostConfig"].update(Privileged=True, NetworkMode="host", SecurityOpt=["seccomp=unconfined"])
        document["Config"]["Env"].append("RT_TOKEN=x")
        document["Mounts"].append(DOCKER_SOCKET)

    world.docker.altered(weaken)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    for cause in ("Privileged", "NetworkMode", "seccomp=unconfined", "RT_TOKEN", "/var/run/docker.sock"):
        assert cause in check.detail


# Go's strconv.ParseBool reads these as true, and Docker parses the value with it.
GO_TRUE = ["1", "t", "T", "TRUE", "true", "True"]
GO_FALSE = ["0", "f", "F", "FALSE", "false", "False"]


@pytest.mark.parametrize(
    "spelling",
    ["no-new-privileges"] + [f"no-new-privileges{separator}{value}" for separator in ":=" for value in GO_TRUE]
)
def test_container_hardening_accepts_every_no_new_privileges_spelling(world, spelling):
    world.docker.altered(host_config(SecurityOpt=[spelling]))
    assert hardening(world).outcome is Outcome.PASS


@pytest.mark.parametrize(
    "spelling",
    [f"no-new-privileges{separator}{value}" for separator in ":=" for value in GO_FALSE + ["", "yes", "TrUe"]]
)
def test_container_hardening_rejects_a_no_new_privileges_that_is_not_true(world, spelling):
    world.docker.altered(host_config(SecurityOpt=[spelling]))
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and spelling in check.detail


@pytest.mark.parametrize("capability", ["dac_read_search", "CAP_DAC_READ_SEARCH", "cap_dac_read_search"])
def test_container_hardening_reads_a_capability_however_it_is_spelled(world, capability):
    world.docker.altered(host_config(CapAdd=[capability]))
    assert hardening(world).outcome is Outcome.PASS


@pytest.mark.parametrize("bindings", [{}, {"7500/tcp": None}, {"7500/tcp": []}], ids=["absent", "null", "empty"])
def test_container_hardening_fails_when_the_admin_port_is_not_published_on_loopback(world, bindings):
    world.docker.altered(host_config(PortBindings=bindings))
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "\n- HostConfig.PortBindings[7500/tcp] is not published;" in check.detail


def test_container_hardening_fails_when_port_bindings_are_null(world):
    world.docker.altered(host_config(PortBindings=None))
    assert "\n- HostConfig.PortBindings[7500/tcp] is not published;" in hardening(world).detail


@pytest.mark.parametrize("groups", [None, []], ids=["null", "empty"])
def test_container_hardening_reads_a_null_and_an_empty_group_add_as_none(world, groups):
    world.docker.altered(host_config(GroupAdd=groups))
    assert hardening(world).outcome is Outcome.PASS


@pytest.mark.parametrize("published", [None, False], ids=["null", "false"])
def test_container_hardening_reads_a_null_publish_all_ports_as_false(world, published):
    world.docker.altered(host_config(PublishAllPorts=published))
    assert hardening(world).outcome is Outcome.PASS


def test_container_hardening_reads_an_absent_publish_all_ports_as_false(world):
    world.docker.altered(lambda document: document["HostConfig"].pop("PublishAllPorts"))
    assert hardening(world).outcome is Outcome.PASS


PORTS_NOT_REPORTED = [None, {}, {"7500/tcp": None}, {"7500/tcp": []}]
PORTS_IDS = ["null", "empty", "admin-port-null", "admin-port-empty"]


@pytest.mark.parametrize("ports", PORTS_NOT_REPORTED, ids=PORTS_IDS)
def test_container_hardening_fails_when_a_running_container_reports_no_admin_port(world, ports):
    world.docker.altered(lambda document: document["NetworkSettings"].update(Ports=ports))
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "\n- NetworkSettings.Ports[7500/tcp] is not published;" in check.detail


def test_container_hardening_fails_without_network_settings_on_a_running_container(world):
    world.docker.altered(lambda document: document.pop("NetworkSettings"))
    assert "\n- NetworkSettings.Ports[7500/tcp] is not published;" in hardening(world).detail


def test_container_hardening_fails_without_a_state_since_the_container_may_be_running(world):

    def change(document):
        document.pop("State")
        document["NetworkSettings"]["Ports"] = {}

    world.docker.altered(change)
    assert "\n- NetworkSettings.Ports[7500/tcp] is not published;" in hardening(world).detail


@pytest.mark.parametrize("ports", PORTS_NOT_REPORTED, ids=PORTS_IDS)
def test_an_exited_container_that_reports_no_ports_is_not_a_violation(world, ports):

    def change(document):
        document["State"]["Running"] = False
        document["NetworkSettings"]["Ports"] = ports

    world.docker.altered(change)
    assert hardening(world).outcome is Outcome.PASS


def test_an_exited_container_is_still_held_to_its_admin_port_binding(world):

    def change(document):
        document["State"]["Running"] = False
        document["NetworkSettings"]["Ports"] = {}
        document["HostConfig"]["PortBindings"] = {}

    world.docker.altered(change)
    assert "\n- HostConfig.PortBindings[7500/tcp] is not published;" in hardening(world).detail


def test_an_exited_container_that_reports_a_wildcard_port_is_still_a_violation(world):

    def change(document):
        document["State"]["Running"] = False
        document["NetworkSettings"]["Ports"] = {"7500/tcp": [{"HostIp": "0.0.0.0", "HostPort": "7500"}]}

    world.docker.altered(change)
    assert "\n- NetworkSettings.Ports[7500/tcp] publishes on" in hardening(world).detail


def test_container_hardening_skips_when_there_is_no_container(world):
    world.docker.on("ps", stdout="")
    assert hardening(world).outcome is Outcome.NOT_APPLICABLE


def test_container_hardening_skips_when_there_is_no_container_and_the_daemon_cannot_say_its_defaults(world):
    world.docker.on("ps", stdout="")
    world.docker.on("info", returncode=1, stderr="permission denied while trying to connect")
    assert hardening(world).outcome is Outcome.NOT_APPLICABLE


def test_container_hardening_fails_with_dockers_words_when_the_container_cannot_be_inspected(world):
    world.docker.on("inspect", returncode=1, stderr="permission denied while trying to connect")
    check = hardening(world)
    assert check.outcome is Outcome.FAIL and "permission denied" in check.detail


@pytest.mark.parametrize(
    "stderr", ["Error: No such object: 0123456789ab", "Error response from daemon: No such container: 0123456789ab"]
)
def test_a_container_removed_between_ps_and_inspect_is_not_applicable_not_a_docker_problem(world, stderr):
    world.docker.on("inspect", returncode=1, stderr=stderr)
    check = hardening(world)
    assert check.outcome is Outcome.NOT_APPLICABLE and "container_healthy" in check.detail


@pytest.mark.parametrize("document", ["[null]", "[[]]", '["x"]', "[]", "{}"])
def test_an_image_inspect_that_is_not_an_object_fails_the_check_with_a_message(world, document):
    world.docker.on("image", "inspect", stdout=document)
    check = hardening(world)
    assert check.outcome is Outcome.FAIL
    assert "`docker image inspect` printed something that is not an image's configuration" in check.detail


# frps answers =========================================================================================================


def test_healthz_is_asked_on_the_published_admin_port_of_loopback(world):
    checks_of(world)
    assert [r.url.path for r in world.net.asked("127.0.0.1", 7500) if r.url.path == "/healthz"] == ["/healthz"]


def test_a_healthz_that_does_not_answer_200_fails(world):
    world.net.healthz = httpx.Response(503)
    check = checks_of(world)["admin_healthz"]
    assert check.outcome is Outcome.FAIL and "503" in check.detail


def test_a_healthz_that_cannot_be_reached_fails(world):

    def refuse(request):
        raise httpx.ConnectError("connection refused", request=request)

    check = checks_of(world, transport=httpx.MockTransport(refuse))["admin_healthz"]
    assert check.outcome is Outcome.FAIL and "connection refused" in check.detail


def test_the_vhost_must_answer_frps_404_for_an_unknown_subdomain(world):
    checks_of(world)
    (probe, ) = world.net.asked("127.0.0.1", 8080)
    assert probe.headers["host"].endswith(".tunnel.example.com")


@pytest.mark.parametrize("response", [httpx.Response(200, text="hello"), httpx.Response(502), httpx.Response(400)])
def test_a_vhost_that_does_not_answer_404_fails_with_the_status(world, response):
    world.net.vhost = response
    check = checks_of(world)["vhost_answers_404"]
    assert check.outcome is Outcome.FAIL and str(response.status_code) in check.detail


@pytest.mark.parametrize("server", ["nginx/1.27", "Caddy", "websocat"])
def test_a_404_that_names_a_server_is_another_server_on_the_vhost_port(world, server):
    world.net.vhost = httpx.Response(404, headers={"Server": server})
    check = checks_of(world)["vhost_answers_404"]
    assert check.outcome is Outcome.FAIL and server in check.detail and "another server" in check.detail


def test_a_vhost_that_is_not_published_is_not_applicable_behind_traefik(world):
    bindings = {key: value for key, value in PORT_BINDINGS.items() if key != "8080/tcp"}
    world.docker.healthy(bindings=bindings)
    check = checks_of(world)["vhost_answers_404"]
    assert check.outcome is Outcome.NOT_APPLICABLE and "published" in check.detail
    assert world.net.asked("127.0.0.1", 8080) == []


def test_a_wildcard_vhost_bind_is_probed_on_loopback(tmp_path):
    world = build_bridge(tmp_path, RT_VHOST_BIND="0.0.0.0", RT_VHOST_PORT="8099")
    world.net.vhost_port = 8099
    world.docker.healthy(bindings=PORT_BINDINGS | {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8099"}]})
    assert checks_of(world)["vhost_answers_404"].outcome is Outcome.PASS


# Who is registered ====================================================================================================


def test_registered_labels_lists_the_online_labels(world):
    check = checks_of(world)["registered_labels"]
    assert check.outcome is Outcome.PASS and "alpha" in check.detail


def test_registered_labels_asks_only_for_online_proxies(world):
    checks_of(world)
    requests = [r for r in world.net.requests if r.url.path == "/api/v2/proxies"]
    assert requests and all(r.url.params["status"] == "online" for r in requests)


def asked_users(world, path: str) -> list[str | None]:
    return [r.url.params.get("user") for r in world.net.requests if r.url.path == path]


def test_each_label_is_confirmed_with_the_server_side_user_filter(world):
    world.net.proxies += [{"name": "beta.ssh", "user": "beta", "clientID": "c-2", "status": {"phase": "online"}}]
    world.net.clients += [{"key": "k-2", "user": "beta", "clientID": "c-2", "online": True}]
    checks_of(world)
    assert sorted(u for u in asked_users(world, "/api/v2/clients") if u) == ["alpha", "beta"]
    assert sorted(u for u in asked_users(world, "/api/v2/proxies") if u) == ["alpha", "beta"]


def test_a_proxy_without_a_user_is_not_one_of_ours_and_is_not_queried_as_a_label(world):
    world.net.proxies += [{"name": "stray", "clientID": "c-x", "status": {"phase": "online"}}]
    check = checks_of(world)["registered_labels"]
    assert check.outcome is Outcome.PASS
    assert "proxy without a user (not a reverse-tunnel host): stray" in check.detail
    assert "1 online: alpha" in check.detail
    assert asked_users(world, "/api/v2/proxies").count("stray") == 0


def test_the_collision_verdict_comes_from_the_label_filtered_query_not_the_fleet_listing(world):
    """An unfiltered listing is paged by offset while the fleet changes, so it can claim an entry twice or not at all."""
    world.net.stale_clients = [
        {"key": "k-1", "user": "alpha", "clientID": "c-1", "online": True},
        {"key": "k-9", "user": "alpha", "clientID": "c-9", "online": True},
    ]
    assert checks_of(world)["label_collisions"].outcome is Outcome.PASS


def test_a_label_whose_filtered_query_is_incomplete_fails_the_collision_check(world):
    world.net.clients = [
        {"key": "k-1", "user": "alpha", "clientID": "c-1", "online": True},
        {"key": "k-2", "user": "alpha", "clientID": "c-2", "online": True},
    ]
    world.net.truncate_filtered_at = 1
    check = checks_of(world)["label_collisions"]
    assert check.outcome is Outcome.FAIL and "alpha" in check.detail and "incomplete" in check.detail


def test_offline_proxy_records_do_not_count_as_registered(world):
    world.net.proxies = [{"name": "alpha.ssh", "user": "alpha", "clientID": "c-1", "status": {"phase": "offline"}}]
    check = checks_of(world)["registered_labels"]
    assert "alpha" not in check.detail
    assert "none" in check.detail


def test_an_admin_api_that_rejects_the_password_fails_both_api_checks(world):

    def deny(request):
        return httpx.Response(401, text="Unauthorized") if request.url.path.startswith("/api") else httpx.Response(200)

    checks = checks_of(world, transport=httpx.MockTransport(deny))
    assert checks["registered_labels"].outcome is Outcome.FAIL and "empty username" in checks["registered_labels"].detail
    assert checks["label_collisions"].outcome is Outcome.FAIL


def test_the_admin_password_is_never_in_a_detail(world):

    def deny(request):
        return httpx.Response(401, text="Unauthorized")

    for check in doctor.run(world.config, world.probes(transport=httpx.MockTransport(deny))):
        assert "correct-horse" not in check.detail


def test_collision_is_detected_from_clients_not_proxies(world):
    world.net.proxies = [{"name": "alpha.ssh", "user": "alpha", "clientID": "c-1", "status": {"phase": "online"}}]
    world.net.clients = [
        {"key": "k-1", "user": "alpha", "clientID": "c-1", "online": True},
        {"key": "k-2", "user": "alpha", "clientID": "c-2", "online": True},
    ]
    checks = checks_of(world)
    assert checks["label_collisions"].outcome is Outcome.FAIL
    assert "alpha" in checks["label_collisions"].detail and "c-2" in checks["label_collisions"].detail
    assert checks["registered_labels"].outcome is Outcome.PASS  # proxies alone show nothing wrong
    assert {r.url.path for r in world.net.requests if "clients" in r.url.path} == {"/api/v2/clients"}


def test_distinct_labels_are_not_a_collision(world):
    world.net.clients = [
        {"key": "k-1", "user": "alpha", "clientID": "c-1", "online": True},
        {"key": "k-2", "user": "beta", "clientID": "c-2", "online": True},
    ]
    assert checks_of(world)["label_collisions"].outcome is Outcome.PASS


def test_a_second_claimant_that_is_not_online_is_not_a_collision(world):
    world.net.clients = [
        {"key": "k-1", "user": "alpha", "clientID": "c-1", "online": True},
        {"key": "k-2", "user": "alpha", "clientID": "c-2", "online": False},
    ]
    assert checks_of(world)["label_collisions"].outcome is Outcome.PASS


def test_an_incomplete_client_page_fails_rather_than_reporting_no_collision(world):
    world.net.clients = [
        {"key": "k-1", "user": "alpha", "clientID": "c-1", "online": True},
        {"key": "k-2", "user": "alpha", "clientID": "c-2", "online": True},
    ]
    world.net.page_size = 1
    world.net.truncate_clients_at = 1  # the second claimant never pages in, though total says 2
    check = checks_of(world)["label_collisions"]
    assert check.outcome is Outcome.FAIL
    assert "incomplete" in check.detail


def test_an_incomplete_proxy_page_fails_the_registration_check(world):
    world.net.proxies = [
        {"name": "a.ssh", "user": "a", "clientID": "c", "status": {"phase": "online"}},
        {"name": "b.ssh", "user": "b", "clientID": "d", "status": {"phase": "online"}},
    ]
    world.net.truncate_proxies_at = 1
    check = checks_of(world)["registered_labels"]
    assert check.outcome is Outcome.FAIL and "incomplete" in check.detail


# What frps loaded =====================================================================================================


def edit(world: World, relative: str, content: bytes) -> None:
    (world.root / relative).write_bytes(content)


def test_config_skew_compares_content_not_mtime_same_content_newer_mtime_passes(world):
    path = world.root / "bridge" / "frps.toml"
    stat = path.stat()
    path.write_bytes(path.read_bytes())
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 3_600_000_000_000))
    assert checks_of(world)["config_skew"].outcome is Outcome.PASS


def test_config_skew_compares_content_not_mtime_a_changed_byte_fails_with_an_older_mtime(world):
    path = world.root / "bridge" / "frps.toml"
    stat = path.stat()
    path.write_bytes(path.read_bytes() + b"# edited\n")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns - 3_600_000_000_000))
    check = checks_of(world)["config_skew"]
    assert check.outcome is Outcome.FAIL
    assert "docker compose up -d --force-recreate" in check.detail


def test_token_skew_is_a_failure_naming_the_recreate(world):
    world.edit_env(RT_TOKEN="f" * 64)
    check = checks_of(world)["token_skew"]
    assert check.outcome is Outcome.FAIL
    assert "docker compose up -d --force-recreate" in check.detail
    assert "f" * 64 not in check.detail


def test_token_skew_gives_the_whole_remedy_because_the_file_may_be_stale_too(world):
    """A recreate alone reloads `secrets/token`, which is still the old token if `ctl install` has not run."""
    detail = checks_of(world)["token_skew"].detail
    assert detail == "frps loaded the RT_TOKEN that is on disk"
    world.edit_env(RT_TOKEN="f" * 64)
    detail = checks_of(world)["token_skew"].detail
    install, recreate = detail.index("uv run -m ctl install"), detail.index("docker compose up -d --force-recreate")
    assert install < recreate, "install writes secrets/token from .env; only then does a recreate load it"
    assert "writes secrets/token" in detail and "drops every connected tunnel" in detail
    assert "unchanged" in detail and "only the recreate" in detail


def test_config_skew_needs_only_the_recreate(world):
    (world.root / "bridge" / "frps.toml").write_bytes(b"# edited\n")
    detail = checks_of(world)["config_skew"].detail
    assert "docker compose up -d --force-recreate" in detail and "ctl install" not in detail


def test_the_token_file_is_never_opened_by_the_bridge_doctor(world):
    (world.root / "secrets" / "token").write_bytes(b"not the token\n")  # only RT_TOKEN counts: the file is not read
    assert checks_of(world)["token_skew"].outcome is Outcome.PASS


def test_the_digest_compared_is_of_exactly_what_bridge_install_writes(tmp_path):
    """Doctor hashes `RT_TOKEN + newline`; install writes that file. If either changes, this fails."""
    root = tmp_path / "fresh"
    root.mkdir()
    config = write_env(root, Role.BRIDGE)
    assert install(config) == 0
    written = (root / "secrets" / "token").read_bytes()
    assert token_digest(config) == hashlib.sha256(written).hexdigest()


def test_token_that_matches_what_frps_loaded_passes(world):
    assert checks_of(world)["token_skew"].outcome is Outcome.PASS


def test_the_recorded_digest_is_read_from_the_container_with_compose_exec(world):
    checks_of(world)
    assert ["compose", "exec", "-T", "frps", "cat", "/run/rt/config.sha256"] in world.docker.calls
    assert ["compose", "exec", "-T", "frps", "cat", "/run/rt/token.sha256"] in world.docker.calls


def test_a_container_that_recorded_nothing_is_a_failure(world):
    world.docker.on("exec", "/run/rt/config.sha256", returncode=1, stderr="cat: can't open")
    check = checks_of(world)["config_skew"]
    assert check.outcome is Outcome.FAIL and "can't open" in check.detail


def test_a_recorded_digest_that_is_not_a_digest_is_a_failure(world):
    world.docker.on("exec", "/run/rt/token.sha256", stdout="not a digest\n")
    assert checks_of(world)["token_skew"].outcome is Outcome.FAIL


# TLS ==================================================================================================================


def test_tls_validates_and_inspects_the_public_host_on_the_public_port(world):
    checks_of(world)
    assert world.tls.validations == [("tunnel.example.com", 443, None)]
    assert world.tls.issuer_lookups == [("tunnel.example.com", 443)]


def test_tls_uses_the_configured_public_port_and_ca_bundle(tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("pem")
    world = build_bridge(
        tmp_path, RT_PUBLIC_HOST="front.example.com", RT_PUBLIC_PORT="8443", RT_TLS_CA_BUNDLE=bundle.as_posix()
    )
    checks_of(world)
    assert world.tls.validations == [("front.example.com", 8443, bundle.as_posix())]


def test_tls_is_not_applicable_when_the_front_does_not_terminate_tls(tmp_path):
    world = build_bridge(tmp_path, RT_PUBLIC_HOST="front.example.com", RT_SCHEME="ws", RT_PUBLIC_PORT="80")
    checks = checks_of(world)
    assert checks["tls_chain_validates"].outcome is Outcome.NOT_APPLICABLE
    assert "ws" in checks["tls_chain_validates"].detail


def test_a_chain_that_does_not_validate_is_a_failure(world):
    world.tls.chain_error = "certificate verify failed: unable to get local issuer certificate"
    check = checks_of(world)["tls_chain_validates"]
    assert check.outcome is Outcome.FAIL and "unable to get local issuer" in check.detail


@pytest.mark.parametrize("issuer", ["(STAGING) Ephemeral Elderberry R10", "Fake LE Intermediate X1"])
def test_staging_certificate_is_a_failure(world, issuer):
    world.tls.issuer_name = issuer
    check = checks_of(world)["tls_issuer_is_not_staging"]
    assert check.outcome is Outcome.FAIL and issuer in check.detail


def test_chain_validation_and_issuer_inspection_are_separate_checks(world):
    """A staging chain fails validation first; the issuer verdict must still be given, and be right."""
    world.tls.chain_error = "certificate verify failed: unable to get local issuer certificate"
    world.tls.issuer_name = "(STAGING) Ephemeral Elderberry R10"
    checks = checks_of(world)
    assert checks["tls_chain_validates"].outcome is Outcome.FAIL
    assert checks["tls_issuer_is_not_staging"].outcome is Outcome.FAIL
    assert "STAGING" in checks["tls_issuer_is_not_staging"].detail


def test_an_untrusted_chain_from_a_genuine_issuer_fails_only_the_validation(world):
    world.tls.chain_error = "certificate verify failed: self-signed certificate"
    checks = checks_of(world)
    assert failures(list(checks.values())) == ["tls_chain_validates"]


def test_the_issuer_is_inspected_without_validating(world):
    world.tls.chain_error = "certificate verify failed"
    checks_of(world)
    assert world.tls.issuer_lookups, "issuer inspection must not be gated on validation"


def test_a_front_that_cannot_be_reached_fails_the_issuer_check_with_the_reason(world):
    world.tls.unreachable = "connection refused"
    check = checks_of(world)["tls_issuer_is_not_staging"]
    assert check.outcome is Outcome.FAIL and "connection refused" in check.detail


# Files ================================================================================================================


def test_loose_env_permissions_are_a_failure(world):
    world.loosen(world.root / ".env", 0o644)
    check = checks_of(world)["env_permissions"]
    assert check.outcome is Outcome.FAIL and "0644" in check.detail


def test_loose_secrets_dir_permissions_are_a_failure(world):
    world.loosen(world.root / "secrets", 0o755)
    check = checks_of(world)["secrets_dir_permissions"]
    assert check.outcome is Outcome.FAIL and "0755" in check.detail


def test_a_readable_token_is_a_failure(world):
    world.loosen(world.root / "secrets" / "token", 0o644)
    assert checks_of(world)["secrets_token_permissions"].outcome is Outcome.FAIL


def test_the_bridge_expects_the_operator_to_own_secrets(world):
    path = world.root / "secrets"
    world.granted[path] = frozenset({"owner=somebody-else", "mode=0711"})
    check = checks_of(world)["secrets_dir_permissions"]
    assert check.outcome is Outcome.FAIL and "somebody-else" in check.detail


def test_a_missing_secrets_directory_is_a_failure_saying_to_install(world):
    (world.root / "secrets" / "token").unlink()
    (world.root / "secrets").rmdir()
    checks = checks_of(world)
    assert checks["secrets_dir_permissions"].outcome is Outcome.FAIL
    assert "ctl install" in checks["secrets_dir_permissions"].detail
    assert checks["token_skew"].outcome is Outcome.PASS  # judged from RT_TOKEN, as the file is never opened
