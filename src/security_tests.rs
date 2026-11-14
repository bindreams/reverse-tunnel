use super::*;

#[test]
fn a_sid_parsed_from_text_has_that_text_and_equals_only_itself() {
    let system = Sid::parse("S-1-5-18").unwrap();

    // SAFETY: a SID that `parse` made.
    assert_eq!(unsafe { string_of_sid(system.as_psid()) }.unwrap(), "S-1-5-18");
    assert!(system == Sid::parse("S-1-5-18").unwrap());
    assert!(system != Sid::parse("S-1-5-19").unwrap());
}

#[test]
fn text_that_is_not_a_sid_is_refused() {
    assert!(Sid::parse("not a sid").is_err());
}

#[test]
fn no_sid_is_a_null_sid() {
    let system = Sid::parse("S-1-5-18").unwrap();

    // SAFETY: null is allowed.
    assert!(!unsafe { system.is(null_mut()) });
}

/// The ACEs that `sddl`'s DACL gives a new directory, as (allows, inherit-only, mask, SID).
fn aces_after(sddl: &str) -> Vec<(bool, bool, u32, String)> {
    let dir = tempfile::tempdir().unwrap();
    Descriptor::parse(sddl).unwrap().apply(dir.path()).unwrap();
    aces_of(dir.path())
        .unwrap()
        .into_iter()
        .map(|ace| (ace.allows, ace.inherit_only, ace.mask, ace.sid.text().unwrap()))
        .collect()
}

#[test]
fn the_aces_of_a_dacl_are_read_with_their_kind_inheritance_mask_and_sid() {
    let found = aces_after("D:P(D;;0x1;;;WD)(A;;0x120089;;;BU)(A;OICIIO;0x1f01ff;;;SY)");

    assert_eq!(
        found,
        [
            (false, false, 0x1, "S-1-1-0".to_string()),
            (true, false, 0x120089, "S-1-5-32-545".to_string()),
            (true, true, 0x1f01ff, "S-1-5-18".to_string()),
        ]
    );
}

#[test]
fn a_dacl_that_is_not_there_gives_everyone_full_access() {
    assert_eq!(
        aces_after("D:NO_ACCESS_CONTROL"),
        [(true, false, 0x1f01ff, "S-1-1-0".to_string())]
    );
}

#[test]
fn deny_aces_of_every_kind_are_read_with_their_own_sid_and_the_other_allows_are_left_out() {
    // A plain deny, a callback deny and an object deny with both GUIDs, then a callback allow, which is left out.
    let found = aces_after(
        "D:P(D;;0x1;;;WD)(XD;;0x2;;;BU;(Member_of{SID(BA)}))\
         (OD;;0x4;bf967aba-0de6-11d0-a285-00aa00c04fc1;bf967aba-0de6-11d0-a285-00aa00c04fc1;AU)\
         (XA;;0x8;;;SY;(Member_of{SID(BA)}))(A;;0x10;;;BA)",
    );

    assert_eq!(
        found,
        [
            (false, false, 0x1, "S-1-1-0".to_string()),
            (false, false, 0x2, "S-1-5-32-545".to_string()),
            (false, false, 0x4, "S-1-5-11".to_string()),
            (true, false, 0x10, "S-1-5-32-544".to_string()),
        ]
    );
}
