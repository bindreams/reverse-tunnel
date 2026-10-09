"""The traversal seam: until the owner decides how a separate service account reaches the deployment, it fails closed."""

import pytest

from ctl import access
from ctl.errors import InstallError
from ctl.perms import Account


def test_a_separate_account_is_refused_with_a_message_that_names_the_account(tmp_path):
    with pytest.raises(InstallError) as raised:
        access.verify_traversable(tmp_path, Account("svc-account", None, None))
    message = str(raised.value)
    assert "separate-account" in message and "not yet available" in message and "svc-account" in message
    assert "RT_SERVICE_USER" in message
