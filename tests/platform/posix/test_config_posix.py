from pathlib import Path

import pytest

from ctl.config import Config, ConfigError

REPO_ROOT = Path(__file__).resolve().parents[3]
CLIENT_ENV = (REPO_ROOT / "example.env").read_text().replace("ROLE=host", "ROLE=client")


def test_read_refuses_a_symlinked_env(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text(CLIENT_ENV)
    (tmp_path / ".env").symlink_to(target)
    with pytest.raises(ConfigError) as raised:
        Config.load(tmp_path)
    assert "symlink" in str(raised.value)


def test_load_never_modifies_the_filesystem(tmp_path):
    path = tmp_path / ".env"
    path.write_text(CLIENT_ENV)
    path.chmod(0o644)
    before_file = path.stat()
    before_dir = tmp_path.stat()
    tmp_path.chmod(0o555)
    try:
        assert Config.load(tmp_path).values["ROLE"] == "client"
        assert sorted(p.name for p in tmp_path.iterdir()) == [".env"]
    finally:
        tmp_path.chmod(0o755)
    after_file = path.stat()
    assert after_file.st_mode == before_file.st_mode
    assert after_file.st_mtime_ns == before_file.st_mtime_ns
    assert after_file.st_ino == before_file.st_ino
    assert tmp_path.stat().st_mtime_ns == before_dir.st_mtime_ns
