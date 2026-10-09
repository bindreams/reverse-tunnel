"""Running the detached child's bootstrap with the base interpreter, and what its `sys.path` must look like."""

import json
import os
import subprocess
import sys
import sysconfig
from pathlib import Path

from ctl import detach
from tests.unit.deployment_support import REPO_ROOT


def base_interpreter() -> str:
    return getattr(sys, "_base_executable", sys.executable)


def venv_site_packages() -> str:
    return sysconfig.get_path("purelib")


def normalise(paths) -> set[str]:
    return {os.path.normcase(os.path.realpath(path)) for path in paths}


def isolated_report() -> dict:
    """`sys.path` and the user-site switch as the bootstrap leaves them, from the base interpreter."""
    code = detach.ISOLATED_SETUP + "import json\nprint(json.dumps({'path': sys.path, 'user_site': site.ENABLE_USER_SITE}))\n"
    command = [base_interpreter(), "-I", "-S", "-c", code, venv_site_packages(), str(REPO_ROOT)]
    result = subprocess.run(command, capture_output=True, text=True, check=True, cwd=Path(sys.prefix))
    return json.loads(result.stdout)


def venv_dash_m_path() -> list[str]:
    """`sys.path` of the venv's own interpreter run from the repository: what `python -m ctl` sees."""
    command = [sys.executable, "-c", "import json, sys; print(json.dumps(sys.path))"]
    result = subprocess.run(command, capture_output=True, text=True, check=True, cwd=REPO_ROOT)
    return [str(REPO_ROOT) if entry == "" else entry for entry in json.loads(result.stdout)]


def base_site_packages() -> str:
    return sysconfig.get_path("purelib", vars={"base": sys.base_prefix, "platbase": sys.base_prefix})


def check_same_shape_as_the_venv() -> None:
    report = isolated_report()
    path = report["path"]
    assert os.path.normcase(os.path.realpath(path[0])) == os.path.normcase(os.path.realpath(REPO_ROOT))
    assert normalise(path) == normalise(venv_dash_m_path())
    if os.path.normcase(os.path.realpath(base_site_packages())
                        ) != os.path.normcase(os.path.realpath(venv_site_packages())):
        assert os.path.normcase(os.path.realpath(base_site_packages())) not in normalise(path)
    import site

    assert os.path.normcase(os.path.realpath(site.getusersitepackages())) not in normalise(path)
    assert not report["user_site"]


def check_help_runs(tmp_path: Path) -> None:
    command = detach.isolated_command(base_interpreter(), venv_site_packages(), str(REPO_ROOT), ["--help"])
    result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "usage: ctl" in result.stdout
