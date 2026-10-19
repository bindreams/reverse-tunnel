"""`ctl doctor` against a real bridge container whose compose override changes it: the check sees what Docker made, and
fails on what reaches past the container, not on its interior."""

import uuid

from bridge_support import FRPS_READY, GOOD_TOKEN, Project, make_project

from ctl import cli
from ctl.config import Config
from ctl.doctor import Outcome
from ctl.doctor.bridge import Bridge
from ctl.doctor.model import execute
from ctl.doctor.probes import Probes

WEAKENING = """\
services:
  frps:
    env_file: .env
    privileged: true
"""
# The interior is the operator's: a writable root and Docker-managed storage stay inside the container.
INTERIOR = """\
services:
  frps:
    read_only: false
    volumes:
      - /scratch
"""
# A `local` volume with `o: bind` is a bind mount of `device` by another name.
HOST_BACKED_VOLUME = """\
services:
  frps:
    volumes:
      - type: volume
        source: hostdata
        target: /hostdata
volumes:
  hostdata:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: {device}
"""


def start(project: Project) -> None:
    """Create or recreate the stack the way an operator does, from `COMPOSE_FILE` in `.env`, then wait for frps's log line."""
    started = project.bare_compose("up", "--detach", "--build")
    assert started.returncode == 0, started.stdout + started.stderr
    log = project.tail("frps")
    project.tails.append(log)
    log.wait_for(FRPS_READY, after=0)


def hardening(project: Project):
    """Just `container_hardening`, through the wrapper doctor runs every check in, without the network probes."""
    bridge = Bridge(Config.load(project.root), Probes())
    return execute([("container_hardening", bridge.container_hardening)])[0]


def deploy(tmp_path, override: str) -> Project:
    """A scratch deployment whose `.env` loads `compose.override.yaml`, installed but not started."""
    # `ctl` runs `docker compose` without a project name, so compose names the project after the directory.
    project = make_project(
        tmp_path,
        root_name=f"rt-e2e-hardening-{uuid.uuid4().hex[:8]}",
        RT_CONTROL_PORT="17821",
        RT_VHOST_PORT="17822",
        RT_ADMIN_PORT="17823",
    )
    (project.root / "compose.override.yaml").write_text(override, newline="\n")
    project.values |= {"ROLE": "bridge", "RT_TOKEN": GOOD_TOKEN, "COMPOSE_FILE": "compose.yaml:compose.override.yaml"}
    project.token_file.unlink()
    project.token_file.parent.rmdir()
    project.write_env()
    assert cli.main(["install"], root=project.root) == 0
    return project


def test_doctor_names_an_override_that_weakens_the_container(tmp_path):
    project = deploy(tmp_path, WEAKENING)
    try:
        start(project)
        weakened = hardening(project)
        assert weakened.outcome is Outcome.FAIL
        assert "HostConfig.Privileged" in weakened.detail and "RT_TOKEN" in weakened.detail
        assert GOOD_TOKEN not in weakened.detail

        project.values["COMPOSE_FILE"] = "compose.yaml"
        start(project)
        assert hardening(project).outcome is Outcome.PASS
    finally:
        project.down()


def test_doctor_passes_a_container_with_a_writable_root_and_an_anonymous_volume(tmp_path):
    project = deploy(tmp_path, INTERIOR)
    try:
        start(project)
        assert hardening(project).outcome is Outcome.PASS
    finally:
        project.down()


def test_doctor_fails_a_named_volume_backed_by_a_host_directory(tmp_path):
    host_directory = tmp_path / "host-directory"
    host_directory.mkdir()
    project = deploy(tmp_path, HOST_BACKED_VOLUME.format(device=host_directory))
    try:
        start(project)
        reaching = hardening(project)
        assert reaching.outcome is Outcome.FAIL
        assert "Mounts has a volume of" in reaching.detail and "hostdata" in reaching.detail
        assert "driver options" in reaching.detail and str(host_directory) in reaching.detail
    finally:
        project.down()
