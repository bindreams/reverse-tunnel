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

/// What `aces_of` reads of the DACL that `sddl` gives a new directory.
fn aces_after(sddl: &str) -> Dacl {
    let dir = tempfile::tempdir().unwrap();
    Descriptor::parse(sddl).unwrap().apply(dir.path()).unwrap();
    aces_of(dir.path()).unwrap()
}

fn summary(dacl: Dacl) -> Vec<(bool, bool, u32, String)> {
    dacl.aces
        .into_iter()
        .map(|ace| (ace.allows, ace.inherit_only, ace.mask, ace.sid.text().unwrap()))
        .collect()
}

#[test]
fn the_aces_of_a_dacl_are_read_with_their_kind_inheritance_mask_and_sid() {
    let found = summary(aces_after("D:P(D;;0x1;;;WD)(A;;0x120089;;;BU)(A;OICIIO;0x1f01ff;;;SY)"));

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
        summary(aces_after("D:NO_ACCESS_CONTROL")),
        [(true, false, 0x1f01ff, "S-1-1-0".to_string())]
    );
}

#[test]
fn deny_aces_of_every_kind_are_read_with_their_own_sid_and_the_other_allows_are_left_out() {
    // A plain deny, a callback deny and an object deny with both GUIDs, then a callback allow, which is left out.
    let dacl = aces_after(
        "D:P(D;;0x1;;;WD)(XD;;0x2;;;BU;(Member_of{SID(BA)}))\
         (OD;;0x4;bf967aba-0de6-11d0-a285-00aa00c04fc1;bf967aba-0de6-11d0-a285-00aa00c04fc1;AU)\
         (XA;;0x8;;;SY;(Member_of{SID(BA)}))(A;;0x10;;;BA)",
    );
    assert_eq!(dacl.left_out, 1);
    let found = summary(dacl);

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

#[test]
fn an_ace_that_files_inherit_is_read_as_such() {
    let found: Vec<bool> = aces_after("D:P(A;OI;0x1;;;WD)(A;CI;0x2;;;BU)(A;;0x4;;;SY)")
        .aces
        .iter()
        .map(|ace| ace.object_inherit)
        .collect();

    assert_eq!(found, [true, false, false]);
}

/// The bytes of an ACE of `size` bytes: the header (type, flags, size), the mask, then `body`.
fn ace_bytes(size: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0];
    bytes.extend(size.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(body);
    bytes
}

/// The SID S-1-5-18 (one sub-authority).
const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

#[test]
fn an_ace_is_read_up_to_its_size_and_never_past_it() {
    let whole = ace_bytes(16, &SYSTEM_SID);
    let object = |flags: u32, guids: usize| {
        let mut body = flags.to_le_bytes().to_vec();
        body.extend(vec![0; 16 * guids]);
        body.extend(SYSTEM_SID);
        ace_bytes(0, &body)
    };

    assert_eq!(layout_of(&whole, false), Ok((1, 8)));
    assert_eq!(layout_of(&object(0, 0), true), Ok((1, 12)));
    assert_eq!(
        layout_of(
            &object(ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT, 2),
            true
        ),
        Ok((1, 44))
    );
    // Each cut leaves a read of the mask, the flags, the SID's fixed part or its sub-authorities past the end.
    for (bytes, object_ace) in [
        (&whole[..6], false),
        (&whole[..8], false),
        (&whole[..13], false),
        (&whole[..whole.len() - 1], false),
        (&object(0, 0)[..10], true),
        (&object(ACE_OBJECT_TYPE_PRESENT, 1)[..20], true),
    ] {
        assert!(layout_of(bytes, object_ace).is_err(), "{bytes:?}");
    }
}

#[test]
fn only_a_sid_this_machine_answers_for_is_asked_for_a_name() {
    let sid = |text: &str| Sid::parse(text).unwrap();
    let machine = sid("S-1-5-21-1-2-3");
    let ask = |text: &str, machine: Option<&Sid>| is_local(&sid(text), || machine);

    // Well-known, built-in, service and application-package SIDs, whether or not the machine's domain is known.
    for text in [
        "S-1-1-0",
        "S-1-2-0",
        "S-1-3-0",
        "S-1-5-1",
        "S-1-5-18",
        "S-1-5-20",
        "S-1-5-32-544",
        "S-1-5-33",
        "S-1-5-64-10",
        "S-1-5-80-1-2-3-4-5",
        "S-1-5-83-0",
        "S-1-5-90-0",
        "S-1-5-113",
        "S-1-5-114",
        "S-1-15-2-1",
        "S-1-15-2-2",
    ] {
        assert!(ask(text, Some(&machine)) && ask(text, None), "{text}");
    }
    // The machine's own domain: an account in it, and the domain itself.
    assert!(ask("S-1-5-21-1-2-3-1001", Some(&machine)));
    assert!(ask("S-1-5-21-1-2-3", Some(&machine)));
    // Another domain's, or any domain's when the machine's is unknown.
    assert!(!ask("S-1-5-21-1-2-4-1001", Some(&machine)));
    assert!(!ask("S-1-5-21-9-2-3-1001", Some(&machine)));
    assert!(!ask("S-1-5-21-1-2-3-1001", None));
    // Not on the list (a logon session is one a domain controller may answer for):
    for text in [
        "S-1-5-5-0-12345",
        "S-1-12-1-1-2-3-4",
        "S-1-15-3-1024-1-2-3-4-5-6-7",
        "S-1-15-2-3",
        "S-1-1-1",
        "S-1-5-83-1-2-3-4-5",
        "S-1-5-115",
    ] {
        assert!(!ask(text, Some(&machine)) && !ask(text, None), "{text}");
    }
}

#[test]
fn the_machine_domain_is_read_only_for_a_domain_sid() {
    let reads = std::cell::Cell::new(0);
    let counting = || {
        reads.set(reads.get() + 1);
        None
    };

    for text in ["S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-5-5-0-1", "S-1-12-1-1-2-3-4"] {
        is_local(&Sid::parse(text).unwrap(), counting);
    }
    assert_eq!(reads.get(), 0);
    is_local(&Sid::parse("S-1-5-21-1-2-3-1000").unwrap(), counting);
    assert_eq!(reads.get(), 1);
}

#[test]
fn an_account_of_this_machine_is_labelled_by_its_name() {
    // The machine's own Administrator account (RID 500), which every Windows has: the machine-account path of `label`.
    let domain = machine_domain()
        .expect("this machine has an account domain")
        .text()
        .unwrap();
    let administrator = Sid::parse(&format!("{domain}-500")).unwrap();

    assert_ne!(administrator.label(), administrator.text().unwrap());
}

#[test]
fn a_sid_is_labelled_by_its_name_if_it_is_well_known_else_by_its_text() {
    let everyone = Sid::parse("S-1-1-0").unwrap();
    // The name is the system's, which a localized Windows gives in its language: only that it is a name.
    assert!(!everyone.label().is_empty() && everyone.label() != everyone.text().unwrap());
    // Each is shown as text for its own reason: no such service here, a domain that is not this machine's, a logon
    // session and an Entra ID account, which are not asked about.
    for unknown in [
        "S-1-5-80-1-2-3-4-5",
        "S-1-5-21-1-2-3-1000",
        "S-1-5-5-0-12345",
        "S-1-12-1-1-2-3-4",
    ] {
        let unknown = Sid::parse(unknown).unwrap();
        assert_eq!(unknown.label(), unknown.text().unwrap());
    }
}

#[test]
fn a_file_given_inherit_dacl_has_what_its_directory_gives_and_no_edit_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    Descriptor::parse("D:P(A;OICI;FA;;;AU)(A;OICI;FR;;;WD)")
        .unwrap()
        .apply(dir.path())
        .unwrap();
    let file = dir.path().join("exe");
    std::fs::write(&file, "").unwrap();
    Descriptor::parse("D:P(A;;FA;;;SY)").unwrap().apply(&file).unwrap();
    assert_eq!(
        summary(aces_of(&file).unwrap()),
        [(true, false, 0x1f01ff, "S-1-5-18".to_string())]
    );

    inherit_dacl(&file).unwrap();

    let found = summary(aces_of(&file).unwrap());
    assert_eq!(
        found,
        [
            (true, false, 0x1f01ff, "S-1-5-11".to_string()),
            (true, false, 0x120089, "S-1-1-0".to_string()),
        ]
    );
}
