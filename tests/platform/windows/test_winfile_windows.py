import os

import pytest

from ctl import _winfile as winfile


class Refused(Exception):
    pass


def open_checked(path, *, directory=False, disposition=winfile.OPEN_EXISTING):
    return winfile.open_handle(
        path, access=winfile.READ_CONTROL, disposition=disposition, directory=directory, error=Refused
    )


def test_a_regular_file_opens_and_a_directory_opens_as_a_directory(tmp_path):
    (tmp_path / "file").write_bytes(b"")
    winfile.close_handle(open_checked(tmp_path / "file"))
    winfile.close_handle(open_checked(tmp_path, directory=True))


def test_a_file_symlink_is_refused_before_its_target_is_opened(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"")
    link = tmp_path / "link"
    os.symlink(target, link)
    with pytest.raises(Refused) as raised:
        open_checked(link)
    assert "reparse point" in str(raised.value)


def test_a_directory_symlink_is_refused_even_when_a_directory_is_expected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    os.symlink(target, link, target_is_directory=True)
    with pytest.raises(Refused) as raised:
        open_checked(link, directory=True)
    assert "reparse point" in str(raised.value)


def test_a_junction_is_refused(tmp_path):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(target), str(junction))
    with pytest.raises(Refused):
        open_checked(junction, directory=True)


def test_the_wrong_kind_is_refused_in_both_directions(tmp_path):
    (tmp_path / "file").write_bytes(b"")
    with pytest.raises(Refused) as as_directory:
        open_checked(tmp_path / "file", directory=True)
    assert "not a directory" in str(as_directory.value)
    with pytest.raises(Refused) as as_file:
        open_checked(tmp_path)
    assert "not a regular file" in str(as_file.value)


def test_a_missing_path_is_a_file_not_found_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_checked(tmp_path / "absent")


def test_create_new_refuses_an_existing_name(tmp_path):
    (tmp_path / "file").write_bytes(b"")
    with pytest.raises(FileExistsError):
        open_checked(tmp_path / "file", disposition=winfile.CREATE_NEW)


# An entry whose kind is not known yet =================================================================================


def open_entry(parent: int, name: str, label):
    return winfile.open_relative(
        parent, name, label=label, access=winfile.READ_CONTROL, directory=None, single_link=True, error=Refused
    )


def test_an_entry_of_either_kind_opens_when_the_kind_is_not_given_and_says_which_it_is(tmp_path):
    (tmp_path / "file").write_bytes(b"")
    (tmp_path / "folder").mkdir()
    parent = open_checked(tmp_path, directory=True)
    try:
        kinds = {}
        for name in ("file", "folder"):
            handle = open_entry(parent, name, tmp_path / name)
            kinds[name] = winfile.is_directory(handle)
            winfile.close_handle(handle)
    finally:
        winfile.close_handle(parent)
    assert kinds == {"file": False, "folder": True}


@pytest.mark.parametrize("kind", ["file symlink", "directory symlink", "junction"])
def test_a_reparse_point_is_refused_when_the_kind_is_not_given(tmp_path, kind):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "file-target").write_bytes(b"")
    link = tmp_path / "link"
    if kind == "junction":
        _winapi.CreateJunction(str(target), str(link))
    elif kind == "directory symlink":
        os.symlink(target, link, target_is_directory=True)
    else:
        os.symlink(tmp_path / "file-target", link)
    parent = open_checked(tmp_path, directory=True)
    try:
        with pytest.raises(Refused) as raised:
            open_entry(parent, "link", link)
    finally:
        winfile.close_handle(parent)
    assert "reparse point" in str(raised.value)


def test_a_hard_linked_file_is_refused_when_the_kind_is_not_given(tmp_path):
    (tmp_path / "file").write_bytes(b"")
    os.link(tmp_path / "file", tmp_path / "other")
    parent = open_checked(tmp_path, directory=True)
    try:
        with pytest.raises(Refused) as raised:
            open_entry(parent, "file", tmp_path / "file")
    finally:
        winfile.close_handle(parent)
    assert "hard links" in str(raised.value)


def test_closing_an_invalid_handle_fails_loudly_instead_of_being_ignored():
    """A handle that cannot be closed is a double close or a handle that was never ours: a bug in the caller."""
    with pytest.raises(AssertionError):
        winfile.close_handle(0)
