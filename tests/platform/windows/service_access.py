"""What LocalService can actually open: an access check of its token's rights against a path's security descriptor.

`AuthzAccessCheck` evaluates the DACL as the kernel does (order, denies, inheritance flags, group memberships), so a test
that asks it needs no reading of ACEs. Authz needs no privilege and no logon.
"""

import ctypes
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


def _authz():
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


def can_open(path: Path, sid: str = winacl.SID_LOCAL_SERVICE, access: int = winacl.READ_EXECUTE) -> bool:
    """Whether the account `sid` is granted every right in `access` on `path`, as the kernel would decide."""
    import win32security

    authz = _authz()
    descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, OWNER_GROUP_DACL)
    # pywin32's descriptor and SID objects export their bytes; its stubs do not say so.
    data = bytes(descriptor)  # ty: ignore[invalid-argument-type]
    raw = ctypes.create_string_buffer(data, len(data))
    sid_bytes = ctypes.c_char_p(bytes(win32security.ConvertStringSidToSid(sid)))  # ty: ignore[invalid-argument-type]
    manager, context = _POINTER(), _POINTER()
    if not authz.AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, None, None, None, None, ctypes.byref(manager)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not authz.AuthzInitializeContextFromSid(
            0, ctypes.cast(sid_bytes, _POINTER), manager, None, _Luid(0, 0), None, ctypes.byref(context)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            granted, error = wintypes.DWORD(), wintypes.DWORD()
            reply = _Reply(1, ctypes.pointer(granted), None, ctypes.pointer(error))
            request = _Request(access, None, None, 0, None)
            if not authz.AuthzAccessCheck(
                0, context, ctypes.byref(request), None, raw, None, 0, ctypes.byref(reply), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return error.value == 0 and granted.value & access == access
        finally:
            authz.AuthzFreeContext(context)
    finally:
        authz.AuthzFreeResourceManager(manager)
