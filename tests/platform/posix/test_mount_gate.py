import pytest
from mount_gate import private_namespace_problems

PRIVATE = """\
22 1 0:21 / / rw,relatime - overlay overlay rw
23 22 0:22 / /proc rw,nosuid - proc proc rw
24 22 0:23 / /sys rw,nosuid - sysfs sysfs rw
"""
SHARED_ROOT = PRIVATE.replace("/ rw,relatime -", "/ rw,relatime shared:1 -")
SLAVE_ROOT = PRIVATE.replace("/ rw,relatime -", "/ rw,relatime master:1 -")
OPT_IN = {"RT_PRIVATE_MOUNT_NS": "1"}


def problems(*, environ=OPT_IN, mountinfo=PRIVATE, own="mnt:[4026532000]", init="mnt:[4026531841]"):
    return private_namespace_problems(environ, mountinfo, own, init)


def test_a_private_namespace_that_is_not_inits_passes():
    assert problems() == []


def test_the_opt_in_is_required_as_well():
    (problem, ) = problems(environ={})
    assert "RT_PRIVATE_MOUNT_NS=1" in problem


def test_a_mount_that_propagates_to_its_peers_fails():
    (problem, ) = problems(mountinfo=SHARED_ROOT)
    assert "shared" in problem and "/" in problem


def test_a_slave_mount_does_not_propagate_out_and_passes():
    assert problems(mountinfo=SLAVE_ROOT) == []


def test_the_namespace_of_pid_1_fails():
    (problem, ) = problems(own="mnt:[4026531841]", init="mnt:[4026531841]")
    assert "PID 1" in problem


def test_an_unreadable_init_namespace_fails_closed():
    (problem, ) = problems(init=None)
    assert "PID 1" in problem and "cannot" in problem


def test_every_problem_is_reported():
    assert len(problems(environ={}, mountinfo=SHARED_ROOT, own="same", init="same")) == 3


@pytest.mark.parametrize("line", ["garbage", "1 2 3"])
def test_a_line_that_cannot_be_read_fails_closed(line):
    (problem, ) = problems(mountinfo=line)
    assert "mountinfo" in problem
