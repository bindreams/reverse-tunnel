import os

import pytest

from ctl.env import EnvError, read


def test_read_returns_a_regular_file_without_translating_line_endings(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\nB=2\n")
    assert read(path) == {"A": "1", "B": "2"}


def test_a_crlf_file_is_still_refused(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\r\n")
    with pytest.raises(EnvError):
        read(path)


def test_read_names_a_missing_file(tmp_path):
    path = tmp_path / ".env"
    with pytest.raises(EnvError) as raised:
        read(path)
    assert str(path) in str(raised.value)


def test_read_refuses_a_directory(tmp_path):
    with pytest.raises(EnvError) as raised:
        read(tmp_path)
    assert str(tmp_path) in str(raised.value)


def test_read_refuses_a_file_symlink(tmp_path):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    os.symlink(target, link)
    with pytest.raises(EnvError) as raised:
        read(link)
    assert str(link) in str(raised.value)
    assert "reparse point" in str(raised.value)


def test_read_refuses_a_dangling_symlink(tmp_path):
    link = tmp_path / ".env"
    os.symlink(tmp_path / "absent", link)
    with pytest.raises(EnvError) as raised:
        read(link)
    assert "reparse point" in str(raised.value)


def test_read_refuses_a_directory_junction(tmp_path):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    (target / ".env").write_bytes(b"A=1\n")
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    with pytest.raises(EnvError) as raised:
        read(junction)
    assert "reparse point" in str(raised.value)
