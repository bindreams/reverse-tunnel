"""The traversal seam on Windows."""

from ctl import access
from ctl.perms import Account


def test_the_seam_does_not_refuse_local_service(tmp_path):
    """Traversal is guaranteed by construction: `grant_service_read` gives LocalService an inheritable read-and-execute
    ACE on the repository root, and LocalService holds SeChangeNotifyPrivilege, so the ancestors need no ACE."""
    access.verify_traversable(tmp_path, Account("LocalService", None, None))
