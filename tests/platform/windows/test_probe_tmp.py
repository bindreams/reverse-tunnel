"""TEMPORARY: does NTFS leave bin and host protected after the earlier install's icacls?"""

from tests.platform.windows.test_stage_windows import acls, build


def test_probe(tmp_path, monkeypatch):
    tree = build("earlier", tmp_path / "earlier", monkeypatch)
    found = acls(tree.root)
    assert False, "\n".join(f"{path}: protected={protected} entries={len(entries)}" for path, (entries, protected) in found.items())
