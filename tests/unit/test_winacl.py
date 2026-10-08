import pytest

from ctl import winacl


class FakeDacl:

    def __init__(self, *aces):
        self.aces = aces

    def GetAceCount(self):
        return len(self.aces)

    def GetAce(self, index):
        return self.aces[index]


def test_an_allowed_and_a_denied_ace_unpack():
    dacl = FakeDacl(((0, 3), 0x1200A9, "sid-a"), ((1, 0), 0x2, "sid-b"))
    assert winacl._entries(dacl, "x") == [(0, 3, 0x1200A9, "sid-a"), (1, 0, 0x2, "sid-b")]


@pytest.mark.parametrize("ace_type", [5, 6, 9, 11])
def test_an_object_or_callback_ace_is_refused_by_type_not_as_a_value_error(ace_type):
    dacl = FakeDacl(((ace_type, 0), 0x1, "object-guid", "inherited-guid", "sid"))
    with pytest.raises(OSError) as raised:
        winacl._entries(dacl, "C:/repo/.env")
    assert f"unsupported ACE type {ace_type}" in str(raised.value)
    assert "C:/repo/.env" in str(raised.value)
