# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Windows' own access check, asked what a service account would be granted by a security descriptor.

`AuthzAccessCheck` evaluates a DACL as the kernel does: in order, with denies, with the inherit-only flag, and for every
group the account's token holds. Reading ACEs for the account's own SID would miss a deny for `Users` or `Everyone`.
Authz needs no privilege and no logon. Failures surface as `OSError`.
"""

import contextlib
import ctypes
from collections.abc import Generator, Iterable
from ctypes import wintypes

from ctl import winacl

AUTHZ_RM_FLAG_NO_AUDIT = 0x1
OWNER_GROUP_DACL = 0x7  # OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
AUTHZ_CONTEXT_INFO_GROUPS_SIDS = 2
ERROR_INSUFFICIENT_BUFFER = 122
TOKEN_GROUPS_OFFSET = 8  # of `Groups` in TOKEN_GROUPS: a DWORD count, padded to pointer alignment
SE_GROUP_ENABLED = 0x7  # SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
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


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", _POINTER), ("attributes", wintypes.DWORD)]


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
    authz.AuthzAddSidsToContext.argtypes = [
        _POINTER,
        ctypes.POINTER(_SidAndAttributes), wintypes.DWORD, _POINTER, wintypes.DWORD,
        ctypes.POINTER(_POINTER)
    ]
    authz.AuthzAccessCheck.argtypes = [
        wintypes.DWORD, _POINTER,
        ctypes.POINTER(_Request), _POINTER, _POINTER, _POINTER, wintypes.DWORD,
        ctypes.POINTER(_Reply), _POINTER
    ]
    authz.AuthzGetInformationFromContext.argtypes = [
        _POINTER, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), _POINTER
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

    def groups(self) -> frozenset[str]:
        """The SIDs of the groups in the context, as the access check sees them (the account's own SID is not one)."""
        needed = wintypes.DWORD()
        if self._authz.AuthzGetInformationFromContext(
            self._context, AUTHZ_CONTEXT_INFO_GROUPS_SIDS, 0, ctypes.byref(needed), None
        ):
            raise OSError("AuthzGetInformationFromContext succeeded with no buffer")
        if (error := ctypes.get_last_error()) != ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        buffer = ctypes.create_string_buffer(needed.value)
        if not self._authz.AuthzGetInformationFromContext(
            self._context, AUTHZ_CONTEXT_INFO_GROUPS_SIDS, needed.value, ctypes.byref(needed), buffer
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        count = wintypes.DWORD.from_buffer(buffer).value
        entries = (_SidAndAttributes * count).from_buffer(buffer, TOKEN_GROUPS_OFFSET)
        return frozenset(_sid_string(entry.sid) for entry in entries)


def _sid_string(sid) -> str:
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertSidToStringSidW.argtypes = [_POINTER, ctypes.POINTER(ctypes.c_void_p)]
    kernel32.LocalFree.argtypes = [_POINTER]
    kernel32.LocalFree.restype = _POINTER
    text = ctypes.c_void_p()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.wstring_at(text)
    finally:
        kernel32.LocalFree(text)


@contextlib.contextmanager
def token(sid: str, groups: Iterable[str] = ()) -> Generator[Token]:
    """The context of the account `sid` with the groups Authz derives for it, plus `groups` (SID strings).

    Authz derives a service account's groups from its SID alone, which leaves out what the service manager puts in the
    token of a process it starts; `groups` adds those.
    """
    authz = _library()
    manager, context = _POINTER(), _POINTER()
    if not authz.AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, None, None, None, None, ctypes.byref(manager)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        account = ctypes.c_char_p(_sid_bytes(sid))
        if not authz.AuthzInitializeContextFromSid(
            0, ctypes.cast(account, _POINTER), manager, None, _Luid(0, 0), None, ctypes.byref(context)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            extra = sorted(set(groups))
            if extra:
                buffers = [ctypes.c_char_p(_sid_bytes(group)) for group in extra]
                added = (_SidAndAttributes * len(extra))(
                    *[_SidAndAttributes(ctypes.cast(buffer, _POINTER), SE_GROUP_ENABLED) for buffer in buffers]
                )
                widened = _POINTER()
                if not authz.AuthzAddSidsToContext(context, added, len(extra), None, 0, ctypes.byref(widened)):
                    raise ctypes.WinError(ctypes.get_last_error())
                authz.AuthzFreeContext(context)
                context = widened
            yield Token(authz, context)
        finally:
            authz.AuthzFreeContext(context)
    finally:
        authz.AuthzFreeResourceManager(manager)


def descriptor_of(handle: int) -> bytes:
    """The owner, group and DACL of the object behind `handle` (READ_CONTROL), as they are on disk."""
    import win32security

    descriptor = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT, OWNER_GROUP_DACL)
    return bytes(descriptor)  # ty: ignore[invalid-argument-type]


def descriptor_for(entries: Iterable[winacl.Entry], *, protected: bool, owner: str, group: str) -> bytes:
    """The descriptor `winacl.set_dacl` would leave on an object owned by `owner` with primary group `group`.

    Built from the very SDDL that function writes, so the order of the ACEs is the order the DACL would have on disk.
    """
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, wintypes.DWORD,
        ctypes.POINTER(_POINTER),
        ctypes.POINTER(wintypes.DWORD)
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [_POINTER]
    kernel32.LocalFree.restype = _POINTER
    sddl = f"O:{owner}G:{group}" + winacl.to_sddl(entries, protected=protected)
    descriptor, size = _POINTER(), wintypes.DWORD()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, winacl.SDDL_REVISION_1, ctypes.byref(descriptor), ctypes.byref(size)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(descriptor, size.value)
    finally:
        kernel32.LocalFree(descriptor)
