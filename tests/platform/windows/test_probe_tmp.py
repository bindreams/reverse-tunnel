"""TEMPORARY probe: the groups of a real LocalService service token and of the Authz context built from its SID."""

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path


def run(*args):
    done = subprocess.run(list(args), capture_output=True, text=True)
    return f"$ {' '.join(args)}\nrc={done.returncode}\n{done.stdout}{done.stderr}"


CHILD = r"""
import ctypes, sys, traceback
from ctypes import wintypes
out = open(sys.argv[1], "w")
try:
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetCurrentProcess.restype = ctypes.c_void_p
    adv.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    adv.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    token = ctypes.c_void_p()
    assert adv.OpenProcessToken(k32.GetCurrentProcess(), 8, ctypes.byref(token)), ctypes.WinError()
    def info(cls):
        size = wintypes.DWORD()
        adv.GetTokenInformation(token, cls, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        assert adv.GetTokenInformation(token, cls, buf, size, ctypes.byref(size)), ctypes.WinError()
        return buf
    def sidstr(address):
        text = ctypes.c_wchar_p()
        assert adv.ConvertSidToStringSidW(address, ctypes.byref(text))
        return text.value
    ptr = ctypes.sizeof(ctypes.c_void_p)
    user = info(1)
    out.write("user " + sidstr(ctypes.c_void_p.from_buffer(user).value) + 
")
    groups = info(2)
    count = ctypes.c_uint32.from_buffer(groups).value
    for i in range(count):
        base = ctypes.addressof(groups) + ptr + i * 2 * ptr
        address = ctypes.c_void_p.from_address(base).value
        attributes = ctypes.c_uint32.from_address(base + ptr).value
        out.write(f"group {sidstr(address)} attributes={attributes:#x}
")
    for label, cls in (("restricted", 11),):
        buf = info(cls)
        n = ctypes.c_uint32.from_buffer(buf).value
        out.write(f"{label} count {n}
")
    out.write("integrity " + sidstr(ctypes.c_void_p.from_buffer(info(25)).value) + 
")
except BaseException:
    out.write(traceback.format_exc())
out.close()
"""


def service_groups(directory: Path, name: str, sidtype: str | None) -> str:
    log = [run("sc", "delete", name)]
    out = directory / f"{name}.txt"
    script = directory / "child.py"
    script.write_text(CHILD)
    command = f"{sys._base_executable} {script} {out}"
    log.append(run("sc", "create", name, "binPath=", command, "obj=", r"NT AUTHORITY\LocalService"))
    if sidtype:
        log.append(run("sc", "sidtype", name, sidtype))
    log.append(run("sc", "start", name))
    log.append(f"--- {out}" + chr(10) + (out.read_text(errors="replace") if out.exists() else "<missing>"))
    log.append(run("sc", "delete", name))
    return chr(10).join(log)


def authz_groups() -> str:
    authz = ctypes.WinDLL("authz", use_last_error=True)
    ptr = ctypes.c_void_p
    authz.AuthzInitializeResourceManager.argtypes = [
        wintypes.DWORD, ptr, ptr, ptr, wintypes.LPCWSTR, ctypes.POINTER(ptr)
    ]
    authz.AuthzInitializeContextFromSid.argtypes = [
        wintypes.DWORD, ptr, ptr, ptr, ctypes.c_int64, ptr, ctypes.POINTER(ptr)
    ]
    authz.AuthzGetInformationFromContext.argtypes = [
        ptr, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ptr
    ]
    import win32security

    sid = ctypes.c_char_p(bytes(win32security.ConvertStringSidToSid("S-1-5-19")))
    manager, context = ptr(), ptr()
    assert authz.AuthzInitializeResourceManager(1, None, None, None, None, ctypes.byref(manager))
    ok = authz.AuthzInitializeContextFromSid(0, ctypes.cast(sid, ptr), manager, None, 0, None, ctypes.byref(context))
    if not ok:
        return f"AuthzInitializeContextFromSid failed: {ctypes.WinError(ctypes.get_last_error())}"
    lines = []
    for label, info in (("groups", 2), ("restricted", 3)):
        size = wintypes.DWORD()
        authz.AuthzGetInformationFromContext(context, info, 0, ctypes.byref(size), None)
        buffer = ctypes.create_string_buffer(size.value)
        assert authz.AuthzGetInformationFromContext(context, info, size.value, ctypes.byref(size), buffer)
        count = ctypes.c_uint32.from_buffer(buffer).value
        offset = ctypes.sizeof(ctypes.c_void_p)
        for index in range(count):
            address, attributes = ctypes.cast(
                ctypes.addressof(buffer) + offset + index * 2 * ctypes.sizeof(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p * 2)
            ).contents
            raw = ctypes.string_at(address, 8 + 4 * ctypes.c_ubyte.from_address(address + 1).value)
            lines.append(f"{label}: {win32security.ConvertSidToStringSid(win32security.SID(raw))} attributes={attributes & 0xFFFFFFFF:#x}")
    return "\n".join(lines)


def test_probe():
    base = Path(os.environ.get("RUNNER_TEMP", os.environ["TEMP"])) / "rtprobe"
    base.mkdir(exist_ok=True)
    subprocess.run(["icacls", str(base), "/grant", "*S-1-5-19:(OI)(CI)M"], check=True, capture_output=True)
    report = [
        "=== service, default sid type ===", service_groups(base, "rtprobe1", None),
        "=== service, unrestricted sid type ===", service_groups(base, "rtprobe2", "unrestricted"),
        "=== authz groups of S-1-5-19 ===", authz_groups(),
    ]
    assert False, "\n".join(report)
