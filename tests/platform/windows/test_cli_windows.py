"""Elevation on Windows: `cli.is_elevated` against an independent query of the process token."""

import ctypes
from ctypes import wintypes

import pytest

from ctl import cli
from ctl.config import Role
from ctl.errors import InstallError
from tests.unit.deployment_support import write_env

TOKEN_QUERY = 0x0008
TOKEN_ELEVATION = 20


def token_says_elevated() -> bool:
    """`TokenElevation` of the current process token, which is what UAC means by an elevated process."""
    advapi32, kernel32 = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    # Without prototypes ctypes passes a 64-bit handle (GetCurrentProcess is -1, so 0xFFFF_FFFF_FFFF_FFFF) as a C int.
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)
    ]
    token = wintypes.HANDLE()
    assert advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token))
    try:
        elevation = wintypes.DWORD()
        returned = wintypes.DWORD()
        assert advapi32.GetTokenInformation(
            token, TOKEN_ELEVATION, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(returned)
        )
        return bool(elevation.value)
    finally:
        kernel32.CloseHandle(token)


def test_is_elevated_agrees_with_the_process_token():
    assert cli.is_elevated() is token_says_elevated()


@pytest.mark.parametrize("role", [Role.BRIDGE, Role.CLIENT])
def test_refuse_root_follows_the_process_token_for_bridge_and_client(tmp_path, role):
    config = write_env(tmp_path, role)
    if token_says_elevated():
        with pytest.raises(InstallError, match="Administrator"):
            cli.refuse_root("install", config)
    else:
        cli.refuse_root("install", config)


def test_refuse_root_never_refuses_a_host(tmp_path):
    cli.refuse_root("install", write_env(tmp_path, Role.HOST))
