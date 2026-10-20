"""The traversal seam on Windows."""

from ctl import access
from ctl.perms import Account


def test_the_seam_does_not_refuse_local_service(tmp_path):
    """The service needs nothing on the repository root: its working directory is `logs`, and LocalService holds
    SeChangeNotifyPrivilege, so the ancestors of `bin`, `host` and `logs` need no ACE either."""
    access.verify_traversable(tmp_path, Account("LocalService", None, None))
