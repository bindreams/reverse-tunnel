"""What LocalService can actually open: the product's access check of its token against a path's descriptor.

The check is `ctl.authz`, with the groups `ctl.perms_windows` gives the service's token, so a test and the install judge
a DACL by the same rule: Windows' `AuthzAccessCheck`, which orders ACEs, honours denies and the inherit-only flag, and
asks for every group of the token. A test that read ACEs would be blind to a deny for `Users`.
"""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from ctl import authz, perms_windows, winacl


@contextmanager
def service_token() -> Generator[authz.Token]:
    with authz.token(winacl.SID_LOCAL_SERVICE, perms_windows.service_token_groups(winacl.SID_LOCAL_SERVICE)) as token:
        yield token


def descriptor_of(path: Path) -> bytes:
    """The owner, group and DACL of `path`, read by name."""
    import win32security

    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, authz.OWNER_GROUP_DACL)
    return bytes(descriptor)  # ty: ignore[invalid-argument-type]


def can_open(path: Path, access: int = winacl.READ_EXECUTE) -> bool:
    """Whether the service is granted every right in `access` on `path`, as the kernel would decide."""
    with service_token() as token:
        return token.grants(descriptor_of(path), access)
