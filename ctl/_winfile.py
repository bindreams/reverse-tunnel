# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Open a Windows file or directory so that a reparse point is refused before its target is ever touched.

Windows has no `O_NOFOLLOW`. `FILE_FLAG_OPEN_REPARSE_POINT` is the equivalent: it opens the link itself, which is then
inspected through the handle, so there is no gap between the check and the use. Callers keep the handle and act through
it.

`open_handle` opens by path. For a directory a caller wants to hold while it works on the entries, `list_names` reads
the names through the held handle and `open_relative` opens each entry relative to it (`NtCreateFile` with the directory
as `RootDirectory`), so no path is ever resolved a second time.
"""

import ctypes
import errno
from ctypes import wintypes

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_LIST_DIRECTORY = 0x00000001
FILE_READ_ATTRIBUTES = 0x00000080
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
SYNCHRONIZE = 0x00100000
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_SHARE_READ_WRITE = 0x3
FILE_SHARE_ALL = 0x7
# FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS; the latter lets the open succeed on a directory.
FLAGS = 0x00200000 | 0x02000000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_TYPE_DISK = 1

# NtCreateFile and NtQueryDirectoryFile
FILE_OPEN = 1
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
OBJ_CASE_INSENSITIVE = 0x40
FILE_NAMES_INFORMATION = 12
STATUS_NO_MORE_FILES = 0x80000006
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_DELETE_PENDING = 0xC0000056
QUERY_BUFFER_SIZE = 65536


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


class _UnicodeString(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_uint16), ("MaximumLength", ctypes.c_uint16), ("Buffer", ctypes.c_void_p)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", ctypes.c_uint32),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_void_p)]


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


def _ntdll():
    ntdll = ctypes.WinDLL("ntdll")
    void_p, uint32 = ctypes.c_void_p, ctypes.c_uint32
    ntdll.NtCreateFile.argtypes = [
        ctypes.POINTER(void_p), uint32,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock), void_p, uint32, uint32, uint32, uint32, void_p, uint32
    ]
    ntdll.NtCreateFile.restype = ctypes.c_int32
    ntdll.NtQueryDirectoryFile.argtypes = [
        void_p, void_p, void_p, void_p,
        ctypes.POINTER(_IoStatusBlock), void_p, uint32, uint32, ctypes.c_ubyte, void_p, ctypes.c_ubyte
    ]
    ntdll.NtQueryDirectoryFile.restype = ctypes.c_int32
    ntdll.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
    ntdll.RtlNtStatusToDosError.restype = uint32
    return ntdll


def _status_error(ntdll, status: int) -> OSError:
    """The `OSError` (a `FileNotFoundError` for a missing name, and so on) that an NTSTATUS means."""
    if status & 0xFFFFFFFF == STATUS_DELETE_PENDING:
        return OSError(errno.EBUSY, "is being deleted")
    return ctypes.WinError(ntdll.RtlNtStatusToDosError(status))


def _raise_status(ntdll, status: int):
    raise _status_error(ntdll, status)


def close_handle(handle: int) -> None:
    _kernel32().CloseHandle(handle)


def _inspect(kernel32, handle: int, path, *, directory: bool, single_link: bool, error: type[Exception]) -> None:
    """Refuse a reparse point, the wrong kind, or (for a file) a second hard link, through the handle."""
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


def open_handle(
    path,
    *,
    access: int,
    disposition: int,
    directory: bool,
    error: type[Exception],
    single_link: bool = False,
    share: int = FILE_SHARE_ALL,
) -> int:
    """A handle to `path` opened with `access`, or `error` if it is a reparse point or not the expected kind.

    `directory` says whether a directory or a regular file is expected; `single_link` also refuses a file with more than
    one hard link, whose ACL would change for every name. A directory a caller holds while working on it should be
    opened without `FILE_SHARE_DELETE` in `share`, so that nobody can rename or delete it meanwhile. OS failures are
    raised as `OSError`.
    """
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(str(path), access | FILE_READ_ATTRIBUTES, share, None, disposition, FLAGS, None)
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        _inspect(kernel32, handle, path, directory=directory, single_link=single_link, error=error)
        return handle
    except BaseException:
        kernel32.CloseHandle(handle)
        raise


def open_relative(
    parent: int,
    name: str,
    *,
    label,
    access: int,
    directory: bool,
    error: type[Exception],
    single_link: bool = False,
    share: int = FILE_SHARE_READ_WRITE,
) -> int:
    """A handle to the entry `name` of the directory held by `parent`, opened relative to it and vetted like `open_handle`.

    `label` is the path to name in messages. A `name` containing a separator is refused: it must be one entry.
    `NtCreateFile` adds no rights of its own, unlike `CreateFileW`, so SYNCHRONIZE and FILE_READ_ATTRIBUTES (which the
    vetting needs) are requested here.
    """
    if not name or "\\" in name or "/" in name or ":" in name:
        raise error(f"{label}: not a single directory entry name")
    kernel32, ntdll = _kernel32(), _ntdll()
    # UNICODE_STRING counts bytes of UTF-16, so a name outside the BMP (two units a character) is twice as long as its
    # code points; a lone surrogate is a legal NTFS name and passes through.
    encoded = name.encode("utf-16-le", "surrogatepass")
    buffer = ctypes.create_string_buffer(encoded + b"\0\0")
    text = _UnicodeString(len(encoded), len(encoded) + 2, ctypes.addressof(buffer))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), parent, ctypes.pointer(text), OBJ_CASE_INSENSITIVE, None, None
    )
    handle, status_block = ctypes.c_void_p(), _IoStatusBlock()
    status = ntdll.NtCreateFile(
        ctypes.byref(handle), access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, ctypes.byref(attributes),
        ctypes.byref(status_block), None, 0, share, FILE_OPEN, FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        None, 0
    )
    if status < 0:
        _raise_status(ntdll, status)
    assert handle.value is not None
    try:
        _inspect(kernel32, handle.value, label, directory=directory, single_link=single_link, error=error)
        return handle.value
    except BaseException:
        kernel32.CloseHandle(handle.value)
        raise


def list_names(directory: int) -> list[str]:
    """The names of the entries of the directory held by `directory` (FILE_LIST_DIRECTORY), without `.` and `..`."""
    ntdll = _ntdll()
    buffer = ctypes.create_string_buffer(QUERY_BUFFER_SIZE)
    base = ctypes.addressof(buffer)
    names: list[str] = []
    restart = 1
    while True:
        status_block = _IoStatusBlock()
        status = ntdll.NtQueryDirectoryFile(
            directory, None, None, None, ctypes.byref(status_block), base, QUERY_BUFFER_SIZE, FILE_NAMES_INFORMATION, 0,
            None, restart
        )
        restart = 0
        if status & 0xFFFFFFFF in (STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE):
            return names
        if status < 0:
            _raise_status(ntdll, status)
        offset = 0
        while True:
            # FILE_NAMES_INFORMATION: ULONG NextEntryOffset, ULONG FileIndex, ULONG FileNameLength, WCHAR FileName[].
            following = ctypes.c_uint32.from_address(base + offset).value
            length = ctypes.c_uint32.from_address(base + offset + 8).value
            name = ctypes.wstring_at(base + offset + 12, length // 2)
            if name not in (".", ".."):
                names.append(name)
            if following == 0:
                break
            offset += following
