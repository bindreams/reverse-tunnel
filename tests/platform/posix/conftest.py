import os
from pathlib import Path

import mount_gate
import pytest

from tests.unit.scanner_support import init_repo, write_hashes_file

NEEDS_ROOT = (
    "this test needs uid 0 (it chowns to other accounts) and never runs against a real machine. Run it in a "
    "throwaway container or on CI; `-m 'not root'` opts out explicitly."
)

NEEDS_PRIVATE_NAMESPACE = (
    "this test mounts filesystems, so it runs only inside a private mount namespace that is not PID 1's, which "
    "`unshare --mount --propagation private` provides: in a throwaway container or on CI, never on a development "
    "machine. `-m 'not mount'` opts out explicitly. Refused because: "
)


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Fail, never skip, a root-marked test run without root and a mount-marked test run outside a private namespace."""
    if pyfuncitem.get_closest_marker("root") and os.geteuid() != 0:
        pytest.fail(NEEDS_ROOT, pytrace=False)
    if pyfuncitem.get_closest_marker("mount") and (problems := mount_gate.current_problems()):
        pytest.fail(NEEDS_PRIVATE_NAMESPACE + "; ".join(problems), pytrace=False)


@pytest.fixture
def hashes_file(tmp_path: Path) -> Path:
    return write_hashes_file(tmp_path)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path)
