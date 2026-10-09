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
DELETE = 0x00010000
FILE_LIST_DIRECTORY = 0x00000001
FILE_ADD_FILE = 0x00000002
FILE_READ_ATTRIBUTES = 0x00000080
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
SYNCHRONIZE = 0x00100000
CREATE_NEW = 1
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
FILE_SHARE_READ_WRITE = 0x3
FILE_SHARE_ALL = 0x7
# FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS; the latter lets the open succeed on a directory.
FLAGS = 0x00200000 | 0x02000000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_TYPE_DISK = 1

# NtCreateFile and NtQueryDirectoryFile
FILE_OPEN = 1
FILE_CREATE = 2
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NAMES_INFORMATION = 12
STATUS_NO_MORE_FILES = 0x80000006
STATUS_NO_SUCH_FILE = 0xC000000F
STATUS_DELETE_PENDING = 0xC0000056
QUERY_BUFFER_SIZE = 65536

# NtSetInformationFile
FILE_RENAME_INFORMATION = 10
FILE_DISPOSITION_INFORMATION = 13
FILE_DISPOSITION_INFORMATION_EX = 64
FILE_RENAME_INFORMATION_EX = 65
FILE_NAME_INFORMATION = 9
# A volume or an older Windows that does not know the `Ex` classes answers one of these, and the plain class serves.
STATUS_INVALID_INFO_CLASS = 0xC0000003
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NOT_SUPPORTED = 0xC00000BB
UNSUPPORTED_CLASS = (STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED)
NAME_BUFFER_SIZE = 4 + 2 * 260  # a first guess; `final_name` grows it to whatever the name needs
STATUS_BUFFER_OVERFLOW = 0x80000005
FILE_RENAME_REPLACE_IF_EXISTS = 0x1
FILE_DISPOSITION_DELETE = 0x1
FILE_DISPOSITION_POSIX_SEMANTICS = 0x2


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


class _RenameInfo(ctypes.Structure):
    """FILE_RENAME_INFORMATION_EX: the name follows the header and `FileNameLength` counts its bytes."""

    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", ctypes.c_wchar * 1),
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
    ntdll.NtSetInformationFile.argtypes = [void_p, ctypes.POINTER(_IoStatusBlock), void_p, uint32, uint32]
    ntdll.NtSetInformationFile.restype = ctypes.c_int32
    ntdll.NtQueryInformationFile.argtypes = [void_p, ctypes.POINTER(_IoStatusBlock), void_p, uint32, uint32]
    ntdll.NtQueryInformationFile.restype = ctypes.c_int32
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


def file_identity(handle: int) -> tuple[int, int]:
    """The volume serial number and file index of the object behind `handle`: equal for two handles to one file."""
    information = _FileInformation()
    if not _kernel32().GetFileInformationByHandle(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    return information.dwVolumeSerialNumber, (information.nFileIndexHigh << 32) | information.nFileIndexLow


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

    `label` is the path to name in messages. A `name` containing a separator is refused: it must be one entry. The name
    is matched exactly (no `OBJ_CASE_INSENSITIVE`), so it must be a name as `list_names` returned it; in a
    case-sensitive directory a different spelling is a different entry.
    `NtCreateFile` adds no rights of its own, unlike `CreateFileW`, so SYNCHRONIZE and FILE_READ_ATTRIBUTES (which the
    vetting needs) are requested here.
    """
    return _relative(
        parent,
        name,
        label=label,
        access=access,
        disposition=FILE_OPEN,
        options=FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        directory=directory,
        error=error,
        single_link=single_link,
        share=share
    )


def create_relative(
    parent: int,
    name: str,
    *,
    label,
    access: int,
    error: type[Exception],
    into: ctypes.c_void_p,
    share: int = FILE_SHARE_READ_WRITE
) -> int:
    """A handle to a new regular file `name` in the directory held by `parent`; `FileExistsError` if it exists.

    The file is created through `parent`, so no path is resolved and nothing already at `name` is ever opened. The kernel
    writes the handle straight into the caller's `into`, so a caller that closes `into.value` on any failure cannot leak it,
    even if it is interrupted the instant the call returns.
    """
    return _relative(
        parent,
        name,
        label=label,
        access=access,
        disposition=FILE_CREATE,
        options=FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        directory=False,
        error=error,
        single_link=True,
        share=share,
        into=into
    )


def _entry_name(name: str, label, error: type[Exception]) -> bytes:
    if not name or "\\" in name or "/" in name or ":" in name:
        raise error(f"{label}: not a single directory entry name")
    # UNICODE_STRING counts bytes of UTF-16, so a name outside the BMP (two units a character) is twice as long as its
    # code points; a lone surrogate is a legal NTFS name and passes through.
    return name.encode("utf-16-le", "surrogatepass")


def _relative(
    parent: int,
    name: str,
    *,
    label,
    access: int,
    disposition: int,
    options: int,
    directory: bool,
    error: type[Exception],
    single_link: bool,
    share: int,
    into: ctypes.c_void_p | None = None
) -> int:
    encoded = _entry_name(name, label, error)
    kernel32, ntdll = _kernel32(), _ntdll()
    buffer = ctypes.create_string_buffer(encoded + b"\0\0")
    text = _UnicodeString(len(encoded), len(encoded) + 2, ctypes.addressof(buffer))
    attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), parent, ctypes.pointer(text), 0, None, None)
    handle, status_block = into if into is not None else ctypes.c_void_p(), _IoStatusBlock()
    try:
        status = ntdll.NtCreateFile(
            ctypes.byref(handle), access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, ctypes.byref(attributes),
            ctypes.byref(status_block), None, 0, share, disposition, options, None, 0
        )
        if status < 0:
            _raise_status(ntdll, status)
        assert handle.value is not None
        _inspect(kernel32, handle.value, label, directory=directory, single_link=single_link, error=error)
    except BaseException:
        # A handle in the caller's `into` is the caller's to dispose of: for a file just created that means deleting it
        # before closing, which only the caller knows how to do.
        if into is None and handle.value is not None:
            kernel32.CloseHandle(handle.value)
        raise
    return handle.value


def rename_over(handle: int, directory: int, name: str, *, label, error: type[Exception]) -> None:
    """Rename the open file `handle` (which needs DELETE access) to `name` in the directory held by `directory`.

    An existing entry of that name is replaced. The destination is given relative to the directory handle through
    `NtSetInformationFile` (the Win32 wrapper may rewrite a relative name as a DOS path); `directory` needs FILE_ADD_FILE.
    Where `FileRenameInformationEx` is not understood, the same buffer is sent as `FileRenameInformation`, whose first
    byte is `ReplaceIfExists`.
    """
    encoded = _entry_name(name, label, error)
    size = ctypes.sizeof(_RenameInfo) + len(encoded)
    buffer = ctypes.create_string_buffer(size)
    info = _RenameInfo.from_buffer(buffer)
    info.Flags = FILE_RENAME_REPLACE_IF_EXISTS
    info.RootDirectory = directory
    info.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + _RenameInfo.FileName.offset, encoded, len(encoded))
    status = _set_information(handle, FILE_RENAME_INFORMATION_EX, buffer, size)
    if status & 0xFFFFFFFF in UNSUPPORTED_CLASS:
        status = _set_information(handle, FILE_RENAME_INFORMATION, buffer, size)
    if status < 0:
        _raise_status(_ntdll(), status)


def delete_now(handle: int) -> None:
    """Delete the file open as `handle` (which needs DELETE access), by name, without a path.

    POSIX semantics remove the name at once even while handles stay open; where the volume cannot do that, the plain
    disposition deletes when the last handle closes.
    """
    flags = ctypes.c_uint32(FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS)
    status = _set_information(handle, FILE_DISPOSITION_INFORMATION_EX, flags, ctypes.sizeof(flags))
    if status < 0:
        status = _set_information(handle, FILE_DISPOSITION_INFORMATION, ctypes.c_ubyte(1), 1)
    if status < 0:
        _raise_status(_ntdll(), status)


def final_name(handle: int) -> str:
    """The last component of the name the open file `handle` has now, which a rename through the handle changes."""
    ntdll = _ntdll()
    size = NAME_BUFFER_SIZE
    while True:
        buffer = ctypes.create_string_buffer(size)
        status = ntdll.NtQueryInformationFile(
            handle, ctypes.byref(_IoStatusBlock()), ctypes.addressof(buffer), size, FILE_NAME_INFORMATION
        )
        length = ctypes.c_uint32.from_buffer(buffer).value
        if status & 0xFFFFFFFF == STATUS_BUFFER_OVERFLOW:  # the length field still says how much the name needs
            size = 4 + length
            continue
        if status < 0:
            _raise_status(ntdll, status)
        path = ctypes.wstring_at(ctypes.addressof(buffer) + 4, length // 2)
        return path.rsplit("\\", 1)[-1]


def _set_information(handle: int, information_class: int, buffer, size: int) -> int:
    """The NTSTATUS of `NtSetInformationFile`; the callers decide which failures to retry."""
    return _ntdll().NtSetInformationFile(
        handle, ctypes.byref(_IoStatusBlock()), ctypes.addressof(buffer), size, information_class
    )


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
