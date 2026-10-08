import os

import pytest

NEEDS_ROOT = (
    "this test needs uid 0 (it chowns to other accounts) and never runs against a real machine. Run it in a "
    "throwaway container or on CI; `-m 'not root'` opts out explicitly."
)


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Fail, never skip, a root-marked test run without root."""
    if pyfuncitem.get_closest_marker("root") and os.geteuid() != 0:
        pytest.fail(NEEDS_ROOT, pytrace=False)
