"""The isolated bootstrap, run with the base interpreter, as the detached child starts."""

from tests.unit import bootstrap_support as support


def test_the_isolated_path_is_the_one_python_dash_m_ctl_has_in_the_venv():
    support.check_same_shape_as_the_venv()


def test_ctl_runs_from_the_bootstrap_whatever_the_working_directory(tmp_path):
    support.check_help_runs(tmp_path)
