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

#[test]
fn a_sid_of_the_nt_authority_is_built_from_its_sub_authorities() {
    assert!(Sid::nt(&[32, 544]) == Sid::parse("S-1-5-32-544").unwrap());
    assert!(Sid::nt(&[18]) != Sid::parse("S-1-5-32-544").unwrap());
}
