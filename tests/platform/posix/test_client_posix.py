import pytest

from ctl.client import render_ssh_config
from ctl.config import ConfigError, Role
from tests.unit.deployment_support import write_env


# Windows cannot name a directory with a line break, so only POSIX can reach the refusal.
@pytest.mark.parametrize("newline", ["\n", "\r"])
def test_an_installed_path_with_a_line_break_is_refused(tmp_path, newline):
    root = tmp_path / f"a{newline}b"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "websocat").write_text("x")
    with pytest.raises(ConfigError, match="line break"):
        render_ssh_config(write_env(root, Role.CLIENT), "alpha")
