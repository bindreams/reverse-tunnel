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


# Inheritance ==========================================================================================================

OI, CI, NP, IO, ID = 0x1, 0x2, 0x4, 0x8, 0x10
ALLOW, DENY = 0, 1


def entry(flags, *, ace_type=ALLOW, mask=0x1200A9, sid="S-1-5-19"):
    return winacl.Entry(ace_type, flags, mask, sid)


@pytest.mark.parametrize(
    ("parent_flags", "directory", "expected"),
    [
        (OI | CI, False, ID),
        (OI | CI, True, ID | OI | CI),
        (CI, True, ID | CI),
        (CI, False, None),
        (OI, False, ID),
        (OI, True, ID | OI | IO),
        (OI | CI | NP, False, ID),
        (OI | CI | NP, True, ID),
        (CI | NP, True, ID),
        (OI | NP, True, None),
        (OI | CI | IO, False, ID),
        (OI | CI | IO, True, ID | OI | CI),
        (0, True, None),
        (0, False, None),
    ],
)
def test_inherited_flags_follow_the_ntfs_rules(parent_flags, directory, expected):
    result = winacl.inherited_for([entry(parent_flags)], directory=directory)
    assert [e.flags for e in result] == ([] if expected is None else [expected])


def test_an_inherited_entry_keeps_its_type_mask_and_sid_and_a_deny_stays_a_deny():
    parent = [entry(OI | CI, ace_type=DENY, mask=0x2, sid="S-1-5-32-545")]
    (result, ) = winacl.inherited_for(parent, directory=False)
    assert (result.ace_type, result.mask, result.sid) == (DENY, 0x2, "S-1-5-32-545")


def test_entries_the_parent_itself_inherited_pass_down_too():
    parent = [entry(ID | OI | CI, sid="S-1-5-18")]
    (result, ) = winacl.inherited_for(parent, directory=True)
    assert result.sid == "S-1-5-18"
    assert result.flags == ID | OI | CI


def test_explicit_drops_the_inherited_entries():
    kept = winacl.explicit([entry(OI), entry(ID | OI), entry(0)])
    assert [e.flags for e in kept] == [OI, 0]


def test_sddl_orders_explicit_before_inherited_and_denies_before_allows():
    entries = [
        entry(ID | OI | CI, sid="S-1-5-18"),
        entry(OI | CI, sid="S-1-5-19"),
        entry(0, ace_type=DENY, mask=0x2, sid="S-1-5-32-545"),
    ]
    assert winacl.to_sddl(
        entries, protected=False
    ) == ("D:AI(D;;0x2;;;S-1-5-32-545)(A;OICI;0x1200a9;;;S-1-5-19)(A;OICIID;0x1200a9;;;S-1-5-18)")


def test_sddl_marks_a_protected_dacl_and_an_empty_dacl_has_no_aces():
    assert winacl.to_sddl([], protected=True) == "D:PAI"
    assert winacl.to_sddl([], protected=False) == "D:AI"


# Creator SIDs and generic rights ======================================================================================

CREATOR_OWNER, CREATOR_GROUP = "S-1-3-0", "S-1-3-1"
GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL = 0x80000000, 0x40000000, 0x20000000, 0x10000000
FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS = 0x120089, 0x120116, 0x1200A0, 0x1F01FF
OWNER, GROUP = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-513"


def inherit(parent, *, directory):
    return winacl.inherited_for(parent, directory=directory, owner=OWNER, group=GROUP)


def as_set(entries):
    return {(e.sid, e.mask, e.flags) for e in entries}


def test_a_file_replaces_creator_owner_with_its_owner():
    parent = [entry(OI | CI | IO, mask=FILE_ALL_ACCESS, sid=CREATOR_OWNER)]
    assert as_set(inherit(parent, directory=False)) == {(OWNER, FILE_ALL_ACCESS, ID)}


def test_a_directory_gets_an_effective_owner_ace_and_an_inherit_only_creator_copy():
    parent = [entry(OI | CI | IO, mask=FILE_ALL_ACCESS, sid=CREATOR_OWNER)]
    assert as_set(inherit(parent, directory=True)) == {
        (OWNER, FILE_ALL_ACCESS, ID),
        (CREATOR_OWNER, FILE_ALL_ACCESS, ID | OI | CI | IO),
    }


def test_creator_group_uses_the_primary_group():
    parent = [entry(OI | CI, mask=FILE_ALL_ACCESS, sid=CREATOR_GROUP)]
    assert as_set(inherit(parent, directory=False)) == {(GROUP, FILE_ALL_ACCESS, ID)}


def test_a_no_propagate_creator_ace_leaves_a_directory_only_the_effective_copy():
    parent = [entry(OI | CI | NP, mask=FILE_ALL_ACCESS, sid=CREATOR_OWNER)]
    assert as_set(inherit(parent, directory=True)) == {(OWNER, FILE_ALL_ACCESS, ID)}


def test_an_object_only_creator_ace_stays_unmapped_and_inherit_only_on_a_directory():
    parent = [entry(OI, mask=FILE_ALL_ACCESS, sid=CREATOR_OWNER)]
    assert as_set(inherit(parent, directory=True)) == {(CREATOR_OWNER, FILE_ALL_ACCESS, ID | OI | IO)}


@pytest.mark.parametrize(
    ("generic", "mapped"),
    [
        (GENERIC_READ, FILE_GENERIC_READ),
        (GENERIC_WRITE, FILE_GENERIC_WRITE),
        (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
        (GENERIC_ALL, FILE_ALL_ACCESS),
        (GENERIC_READ | GENERIC_EXECUTE, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
    ],
)
def test_a_file_maps_generic_rights(generic, mapped):
    parent = [entry(OI | CI, mask=generic, sid="S-1-5-32-545")]
    assert as_set(inherit(parent, directory=False)) == {("S-1-5-32-545", mapped, ID)}


def test_generic_rights_keep_the_specific_bits_they_were_mixed_with():
    parent = [entry(OI, mask=GENERIC_READ | 0x10000, sid="S-1-5-32-545")]
    assert as_set(inherit(parent, directory=False)) == {("S-1-5-32-545", FILE_GENERIC_READ | 0x10000, ID)}


def test_a_directory_splits_a_propagating_generic_ace_into_mapped_and_unmapped_copies():
    parent = [entry(OI | CI, mask=GENERIC_READ | GENERIC_EXECUTE, sid="S-1-5-32-545")]
    assert as_set(inherit(parent, directory=True)) == {
        ("S-1-5-32-545", FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, ID),
        ("S-1-5-32-545", GENERIC_READ | GENERIC_EXECUTE, ID | OI | CI | IO),
    }


def test_a_no_propagate_generic_ace_is_mapped_without_a_second_copy_on_a_directory():
    parent = [entry(CI | NP, mask=GENERIC_READ, sid="S-1-5-32-545")]
    assert as_set(inherit(parent, directory=True)) == {("S-1-5-32-545", FILE_GENERIC_READ, ID)}


def test_an_object_only_generic_ace_stays_unmapped_on_a_directory():
    parent = [entry(OI, mask=GENERIC_READ, sid="S-1-5-32-545")]
    assert as_set(inherit(parent, directory=True)) == {("S-1-5-32-545", GENERIC_READ, ID | OI | IO)}


def test_an_ace_with_neither_creator_sid_nor_generic_bits_stays_one_ace():
    parent = [entry(OI | CI, mask=FILE_GENERIC_READ, sid="S-1-5-32-545")]
    assert as_set(inherit(parent, directory=True)) == {("S-1-5-32-545", FILE_GENERIC_READ, ID | OI | CI)}


def test_a_creator_ace_without_the_owner_it_needs_is_an_error():
    parent = [entry(OI | CI, mask=FILE_ALL_ACCESS, sid=CREATOR_OWNER)]
    with pytest.raises(ValueError):
        winacl.inherited_for(parent, directory=False)
