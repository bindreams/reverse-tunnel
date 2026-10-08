import hashlib
import io
import os
import stat
import tarfile

import httpx

from ctl.archive import ArchiveFormat
from ctl.binaries import Pin
from ctl.download import fetch


def serve(body: bytes) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, content=body))


def test_a_fetched_bare_binary_is_executable(tmp_path):
    body = b"#!/bin/sh\n"
    digest = hashlib.sha256(body).hexdigest()
    pin = Pin(
        "websocat", "1.14.1", "https://example.test/websocat", digest, digest, ArchiveFormat.BARE, None, "websocat"
    )
    dest = tmp_path / "bin"
    dest.mkdir()
    path = fetch(pin, dest, transport=serve(body))
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert os.access(path, os.X_OK)


def test_a_fetched_archive_member_is_executable_whatever_its_archived_mode(tmp_path):
    member = b"binary"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("top/frpc")
        info.size, info.mode = len(member), 0o600
        archive.addfile(info, io.BytesIO(member))
    body = buffer.getvalue()
    pin = Pin(
        "frp", "0.71.0", "https://example.test/frp.tar.gz",
        hashlib.sha256(body).hexdigest(),
        hashlib.sha256(member).hexdigest(), ArchiveFormat.TAR_GZ, "top/frpc", "frpc"
    )
    dest = tmp_path / "bin"
    dest.mkdir()
    path = fetch(pin, dest, transport=serve(body))
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert os.access(path, os.X_OK)
