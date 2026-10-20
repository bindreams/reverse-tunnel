"""What LocalService can open, asked of Windows' own access check (`AuthzAccessCheck`).

This is the tests' oracle, kept apart from `ctl` on purpose: the install does not judge access at all. It is sound
here because the trees under test hold no deny ACE. Authz derives the groups of an account from its SID alone, which
leaves out those the service manager adds to the token of a real service, and only a deny for one of those could make
the answer differ.
"""

import contextlib
import ctypes
from collections.abc import Generator
from ctypes import wintypes
from pathlib import Path

from ctl import winacl

AUTHZ_RM_FLAG_NO_AUDIT = 0x1
OWNER_GROUP_DACL = 0x7  # OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
_POINTER = ctypes.c_void_p


class _Luid(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.LONG)]


class _Request(ctypes.Structure):
    _fields_ = [
        ("desired", wintypes.DWORD),
        ("principal_self_sid", _POINTER),
        ("object_types", _POINTER),
        ("object_type_count", wintypes.DWORD),
        ("optional_arguments", _POINTER),
    ]


class _Reply(ctypes.Structure):
    _fields_ = [
        ("result_count", wintypes.DWORD),
        ("granted", ctypes.POINTER(wintypes.DWORD)),
        ("sacl_results", _POINTER),
        ("error", ctypes.POINTER(wintypes.DWORD)),
    ]


def _library():
    authz = ctypes.WinDLL("authz", use_last_error=True)
    authz.AuthzInitializeResourceManager.argtypes = [
        wintypes.DWORD, _POINTER, _POINTER, _POINTER, wintypes.LPCWSTR,
        ctypes.POINTER(_POINTER)
    ]
    authz.AuthzInitializeContextFromSid.argtypes = [
        wintypes.DWORD, _POINTER, _POINTER, _POINTER, _Luid, _POINTER,
        ctypes.POINTER(_POINTER)
    ]
    authz.AuthzAccessCheck.argtypes = [
        wintypes.DWORD, _POINTER,
        ctypes.POINTER(_Request), _POINTER, _POINTER, _POINTER, wintypes.DWORD,
        ctypes.POINTER(_Reply), _POINTER
    ]
    authz.AuthzFreeContext.argtypes = [_POINTER]
    authz.AuthzFreeResourceManager.argtypes = [_POINTER]
    return authz


def _sid_bytes(sid: str) -> bytes:
    import win32security

    # pywin32's SID objects export their bytes; its stubs do not say so.
    return bytes(win32security.ConvertStringSidToSid(sid))  # ty: ignore[invalid-argument-type]


class Token:
    """The client context of one account: what a process running as it would be granted."""

    def __init__(self, authz, context) -> None:
        self._authz = authz
        self._context = context

    def grants(self, descriptor: bytes, access: int) -> bool:
        """Whether the security descriptor `descriptor` (owner, group and DACL) grants every right in `access`."""
        raw = ctypes.create_string_buffer(descriptor, len(descriptor))
        granted, error = wintypes.DWORD(), wintypes.DWORD()
        reply = _Reply(1, ctypes.pointer(granted), None, ctypes.pointer(error))
        request = _Request(access, None, None, 0, None)
        if not self._authz.AuthzAccessCheck(
            0, self._context, ctypes.byref(request), None, raw, None, 0, ctypes.byref(reply), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return error.value == 0 and granted.value & access == access


@contextlib.contextmanager
def service_token() -> Generator[Token]:
    authz = _library()
    manager, context = _POINTER(), _POINTER()
    if not authz.AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, None, None, None, None, ctypes.byref(manager)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        account = ctypes.c_char_p(_sid_bytes(winacl.SID_LOCAL_SERVICE))
        if not authz.AuthzInitializeContextFromSid(
            0, ctypes.cast(account, _POINTER), manager, None, _Luid(0, 0), None, ctypes.byref(context)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield Token(authz, context)
        finally:
            authz.AuthzFreeContext(context)
    finally:
        authz.AuthzFreeResourceManager(manager)


def descriptor_of(path: Path) -> bytes:
    """The owner, group and DACL of `path`, read by name."""
    import win32security

    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, OWNER_GROUP_DACL)
    return bytes(descriptor)  # ty: ignore[invalid-argument-type]


def can_open(path: Path, access: int = winacl.READ_EXECUTE) -> bool:
    """Whether the service is granted every right in `access` on `path`, as the kernel would decide."""
    with service_token() as token:
        return token.grants(descriptor_of(path), access)
