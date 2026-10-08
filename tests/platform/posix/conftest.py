import os

import pytest

NEEDS_ROOT = (
    "this test needs uid 0 (it chowns to other accounts) and never runs against a real machine. Run it in a "
    "throwaway container or on CI; `-m 'not root'` opts out explicitly."
)

NEEDS_PRIVATE_NAMESPACE = (
    "this test mounts filesystems, so it runs only inside a private mount namespace (RT_PRIVATE_MOUNT_NS=1), which "
    "`unshare --mount --propagation private` provides: in a throwaway container or on CI, never on a development "
    "machine. `-m 'not mount'` opts out explicitly."
)


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Fail, never skip, a root-marked test run without root and a mount-marked test run outside a private namespace."""
    if pyfuncitem.get_closest_marker("root") and os.geteuid() != 0:
        pytest.fail(NEEDS_ROOT, pytrace=False)
    if pyfuncitem.get_closest_marker("mount") and os.environ.get("RT_PRIVATE_MOUNT_NS") != "1":
        pytest.fail(NEEDS_PRIVATE_NAMESPACE, pytrace=False)
