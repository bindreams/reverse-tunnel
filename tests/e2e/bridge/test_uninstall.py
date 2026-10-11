"""`ctl install` and `ctl uninstall` for the bridge, against a real Docker: the container goes down before `secrets/` does."""

import uuid

from bridge_support import GOOD_TOKEN, Project, make_project

from ctl import cli


def running_containers(project: Project) -> list[str]:
    listing = project.compose("ps", "--all", "--quiet")
    assert listing.returncode == 0, listing.stderr
    return listing.stdout.split()


def test_uninstall_takes_the_container_down_then_removes_secrets_and_a_later_up_does_not_recreate_them(
    tmp_path, capsys
):
    # `ctl` runs `docker compose down` without a project name, so compose names the project after the directory.
    project = make_project(
        tmp_path,
        root_name=f"rt-e2e-uninstall-{uuid.uuid4().hex[:8]}",
        # ctl refuses port 0, so these are fixed; a busy port fails `up` rather than the test passing wrongly.
        RT_CONTROL_PORT="17811",
        RT_VHOST_PORT="17812",
        RT_ADMIN_PORT="17813",
    )
    project.values |= {"ROLE": "bridge", "RT_TOKEN": GOOD_TOKEN}
    project.token_file.unlink()
    project.token_file.parent.rmdir()
    project.write_env()
    try:
        assert cli.main(["install"], root=project.root) == 0
        assert project.token_file.read_text() == GOOD_TOKEN + "\n"
        project.up()
        assert len(running_containers(project)) == 1

        assert cli.main(["uninstall"], root=project.root) == 0
        assert running_containers(project) == []
        assert not (project.root / "secrets").exists()

        assert cli.main(["uninstall"], root=project.root) == 0  # a second run has nothing to do

        refused = project.compose("up", "--detach")
        assert refused.returncode != 0 and "secrets/token" in refused.stderr
        assert not (project.root / "secrets").exists()  # compose did not make a root-owned directory in its place
    finally:
        project.down()
    output = capsys.readouterr()
    assert "removed secrets/" in output.out and "already absent" in output.out
