"""`ctl doctor` against a real bridge container whose compose override weakens it: the allow-list sees what Docker made."""

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


def test_doctor_names_an_override_that_weakens_the_container(tmp_path):
    # `ctl` runs `docker compose` without a project name, so compose names the project after the directory.
    project = make_project(
        tmp_path,
        root_name=f"rt-e2e-hardening-{uuid.uuid4().hex[:8]}",
        RT_CONTROL_PORT="17821",
        RT_VHOST_PORT="17822",
        RT_ADMIN_PORT="17823",
    )
    (project.root / "compose.override.yaml").write_text(WEAKENING, newline="\n")
    project.values |= {"ROLE": "bridge", "RT_TOKEN": GOOD_TOKEN, "COMPOSE_FILE": "compose.yaml:compose.override.yaml"}
    project.token_file.unlink()
    project.token_file.parent.rmdir()
    project.write_env()
    try:
        assert cli.main(["install"], root=project.root) == 0
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
