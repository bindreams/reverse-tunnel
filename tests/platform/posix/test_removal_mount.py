"""`remove_directory` on a mount point, which is where an `rm -rf` does the most damage.

Every test mounts, so it runs only in a private mount namespace (see `conftest.py`). Nothing here deletes a tree: the
fixture removes empty directories only, and a failed unmount fails the test and leaves the namespace to discard it.
"""

import os
import subprocess
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from ctl.errors import InstallError
from ctl.removal import remove_directory


def mounted_under(path: Path) -> list[str]:
    """Mount points at or below `path`, as the kernel lists them."""
    points = [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines()]
    return [point for point in points if point == str(path) or point.startswith(f"{path}/")]


@pytest.fixture
def workdir() -> Generator[Path]:
    path = Path(tempfile.mkdtemp(prefix="rt-mount-", dir="/tmp"))
    yield path
    if mounted_under(path):  # a test failed before unmounting: delete nothing, the namespace discards the mounts
        return
    for directory, _, files in os.walk(path, topdown=False, followlinks=False):
        for name in files:
            os.unlink(Path(directory) / name)
        os.rmdir(directory)


def mount(*args: str) -> None:
    subprocess.run(["mount", *args], check=True)


def unmount(target: Path) -> None:
    result = subprocess.run(["umount", str(target)], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.fail(f"umount {target} failed; stopping without deleting anything: {result.stderr}", pytrace=False)


@pytest.mark.root
@pytest.mark.mount
def test_a_tmpfs_mount_point_is_refused_and_its_contents_survive(workdir):
    target = workdir / "bin"
    target.mkdir()
    mount("-t", "tmpfs", "tmpfs", str(target))
    (target / "keep").write_text("x")
    with pytest.raises(InstallError, match="mount point"):
        remove_directory(workdir, "bin")
    assert (target / "keep").read_text() == "x"
    unmount(target)


@pytest.mark.root
@pytest.mark.mount
def test_a_bind_mount_on_the_same_filesystem_is_refused_and_its_source_survives(workdir):
    """`st_dev` is equal here, so only the mount id tells the bind mount from the directory it hides."""
    source, target = workdir / "source", workdir / "bin"
    source.mkdir()
    target.mkdir()
    (source / "keep").write_text("x")
    mount("--bind", str(source), str(target))
    assert os.stat(source).st_dev == os.stat(target).st_dev
    with pytest.raises(InstallError, match="mount point"):
        remove_directory(workdir, "bin")
    assert (source / "keep").read_text() == "x"
    unmount(target)


@pytest.mark.root
@pytest.mark.mount
def test_a_mount_inside_the_directory_is_never_entered(workdir):
    (workdir / "bin" / "mnt").mkdir(parents=True)
    mount("-t", "tmpfs", "tmpfs", str(workdir / "bin" / "mnt"))
    (workdir / "bin" / "mnt" / "keep").write_text("x")
    with pytest.raises(InstallError, match="busy"):
        remove_directory(workdir, "bin")
    assert (workdir / "bin" / "mnt" / "keep").read_text() == "x"
    unmount(workdir / "bin" / "mnt")


@pytest.mark.root
@pytest.mark.mount
def test_an_unmounted_directory_is_removed_again(workdir):
    target = workdir / "bin"
    target.mkdir()
    mount("-t", "tmpfs", "tmpfs", str(target))
    unmount(target)
    assert remove_directory(workdir, "bin") is True
