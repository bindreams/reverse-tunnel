import pytest

from ctl.cli import main


def test_help_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exit_:
        main(["--help"])
    assert exit_.value.code == 0
    assert "usage: ctl" in capsys.readouterr().out
