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

/// `path`'s DACL as SDDL.
fn dacl_of(path: &Path) -> String {
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;

    let (mut dacl, mut descriptor) = (null_mut(), null_mut());
    // SAFETY: the path is NUL-terminated, and the out pointers are live.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(code, 0, "reading the DACL of {}", path.display());
    let _descriptor = Local(descriptor);
    let mut text = null_mut();
    // SAFETY: `descriptor` is live, and `text` is where Windows puts the string it allocates.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            null_mut(),
        )
    };
    assert_ne!(converted, 0, "{}", io::Error::last_os_error());
    let _text = Local(text.cast());
    // SAFETY: Windows wrote a NUL-terminated string.
    unsafe { PCWSTR(text).to_string() }.unwrap()
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
    assert_eq!(dacl_of(&file), "D:PAI(A;;FA;;;SY)");

    inherit_dacl(&file).unwrap();

    assert_eq!(dacl_of(&file), "D:AI(A;ID;FA;;;AU)(A;ID;FR;;;WD)");
}
