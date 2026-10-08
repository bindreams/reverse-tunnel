# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Open a Windows file or directory so that a reparse point is refused before its target is ever touched.

Windows has no `O_NOFOLLOW`. `FILE_FLAG_OPEN_REPARSE_POINT` is the equivalent: it opens the link itself, which is then
inspected through the handle, so there is no gap between the check and the use. Callers keep the handle and act through
it.
"""

import ctypes
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_SHARE_ALL = 0x7
# FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS; the latter lets the open succeed on a directory.
FLAGS = 0x00200000 | 0x02000000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_TYPE_DISK = 1


class _FileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", wintypes.FILETIME),
        ("ftLastAccessTime", wintypes.FILETIME),
        ("ftLastWriteTime", wintypes.FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
        wintypes.HANDLE
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInformation)]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFileType.argtypes = [wintypes.HANDLE]
    kernel32.GetFileType.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def close_handle(handle: int) -> None:
    _kernel32().CloseHandle(handle)


def open_handle(
    path, *, access: int, disposition: int, directory: bool, error: type[Exception], single_link: bool = False
) -> int:
    """A handle to `path` opened with `access`, or `error` if it is a reparse point or not the expected kind.

    `directory` says whether a directory or a regular file is expected; `single_link` also refuses a file with more than
    one hard link, whose ACL would change for every name. OS failures are raised as `OSError`.
    """
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(str(path), access, FILE_SHARE_ALL, None, disposition, FLAGS, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        information = _FileInformation()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = information.dwFileAttributes
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise error(f"{path}: is a symlink or other reparse point; refusing to follow it")
        is_directory = bool(attributes & FILE_ATTRIBUTE_DIRECTORY)
        if directory and not is_directory:
            raise error(f"{path}: not a directory")
        if not directory and (is_directory or kernel32.GetFileType(handle) != FILE_TYPE_DISK):
            raise error(f"{path}: not a regular file")
        if single_link and not directory and information.nNumberOfLinks > 1:
            raise error(
                f"{path}: has {information.nNumberOfLinks} hard links; "
                "refusing to change a file that is also reachable under another name"
            )
        return handle
    except BaseException:
        kernel32.CloseHandle(handle)
        raise
