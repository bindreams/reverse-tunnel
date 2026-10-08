import subprocess
import sys

from scanner_support import REPO_ROOT


def collected() -> list[str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return [line.partition("::")[0].replace("\\", "/") for line in result.stdout.splitlines() if "::" in line]


def test_a_bare_run_collects_the_unit_tests_and_only_this_platforms_tests():
    files = set(collected())
    mine, other = ("windows", "posix") if sys.platform == "win32" else ("posix", "windows")
    assert any(f.startswith("tests/unit/") for f in files)
    assert any(f.startswith(f"tests/platform/{mine}/") for f in files)
    assert not any(f.startswith(f"tests/platform/{other}/") for f in files)
