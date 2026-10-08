"""Root writes into `bin/`, so a link in or at the destination must never be followed."""

import hashlib
import os
import stat

import httpx
import pytest

from ctl.archive import ArchiveFormat
from ctl.binaries import Pin
from ctl.download import fetch
from ctl.errors import BinariesError

BODY = b"binary"
DIGEST = hashlib.sha256(BODY).hexdigest()
PIN = Pin("websocat", "1.14.1", "https://example.test/websocat", DIGEST, DIGEST, ArchiveFormat.BARE, None, "websocat")
TRANSPORT = httpx.MockTransport(lambda request: httpx.Response(200, content=BODY))


def test_a_destination_directory_that_is_a_symlink_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "bin"
    link.symlink_to(real)
    with pytest.raises(BinariesError, match="link"):
        fetch(PIN, link, transport=TRANSPORT)
    assert list(real.iterdir()) == []


def test_a_destination_file_that_is_a_symlink_is_refused_and_its_target_untouched(tmp_path):
    dest = tmp_path / "bin"
    dest.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"precious")
    victim.chmod(0o600)
    (dest / "websocat").symlink_to(victim)
    with pytest.raises(BinariesError, match="link"):
        fetch(PIN, dest, transport=TRANSPORT)
    assert victim.read_bytes() == b"precious"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600
    assert [p.name for p in dest.iterdir()] == ["websocat"]


def test_a_destination_that_is_a_directory_is_refused(tmp_path):
    dest = tmp_path / "bin"
    (dest / "websocat").mkdir(parents=True)
    with pytest.raises(BinariesError, match="regular file"):
        fetch(PIN, dest, transport=TRANSPORT)


def test_the_mode_is_set_on_the_descriptor_whatever_the_umask(tmp_path):
    dest = tmp_path / "bin"
    dest.mkdir()
    old = os.umask(0o077)
    try:
        path = fetch(PIN, dest, transport=TRANSPORT).path
    finally:
        os.umask(old)
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
