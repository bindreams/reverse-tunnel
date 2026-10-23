"""Failures of the Windows security calls in `ctl.winacl` surface as `OSError`, the type the callers catch."""

import pytest

from ctl import winacl


@pytest.mark.parametrize("read", [winacl.owner_sid, winacl.owner_and_group])
def test_a_failed_read_of_the_owner_is_an_os_error_not_pywin32s_own_error(read):
    with pytest.raises(OSError):
        read(0)  # not a handle to anything: ERROR_INVALID_HANDLE
