use super::*;

const DIR: &str = r"C:\Program Files\reverse-tunnel";

#[test]
fn a_directory_is_appended_after_the_entries_there() {
    assert_eq!(
        with_entry(r"C:\Windows;C:\Tools", DIR).unwrap(),
        format!(r"C:\Windows;C:\Tools;{DIR}")
    );
}

#[test]
fn a_directory_is_the_whole_path_when_there_was_none() {
    assert_eq!(with_entry("", DIR).unwrap(), DIR);
}

#[test]
fn a_directory_follows_a_trailing_separator_without_a_second_one() {
    assert_eq!(with_entry(r"C:\Windows;", DIR).unwrap(), format!(r"C:\Windows;{DIR}"));
}

#[test]
fn a_directory_that_is_named_already_is_not_added_whatever_its_case_or_a_trailing_backslash() {
    for named in [
        DIR.to_string(),
        DIR.to_uppercase(),
        format!(r"{DIR}\"),
        format!("\"{DIR}\""),
    ] {
        assert_eq!(
            with_entry(&format!(r"C:\Windows;{named};C:\Tools"), DIR),
            None,
            "{named}"
        );
    }
}

#[test]
fn an_entry_that_only_starts_with_the_directory_does_not_name_it() {
    let longer = format!("{DIR}-old");
    assert_eq!(
        with_entry(&longer, DIR).unwrap(),
        format!("{longer};{DIR}"),
        "a longer name is another directory"
    );
    assert_eq!(without_entry(&longer, DIR), None);
    assert_eq!(without_entry(&format!(r"{DIR}\bin"), DIR), None);
}

#[test]
fn every_entry_that_names_the_directory_is_removed_and_nothing_else_changes() {
    let path = format!(r"C:\Windows;;{DIR};C:\Tools\;{}\;%SystemRoot%\x;", DIR.to_lowercase());

    // The empty entries stay as they were.
    assert_eq!(
        without_entry(&path, DIR).unwrap(),
        r"C:\Windows;;C:\Tools\;%SystemRoot%\x;"
    );
}

#[test]
fn the_first_and_last_entries_take_their_separator_with_them() {
    assert_eq!(
        without_entry(&format!(r"{DIR};C:\Windows"), DIR).unwrap(),
        r"C:\Windows"
    );
    assert_eq!(
        without_entry(&format!(r"C:\Windows;{DIR}"), DIR).unwrap(),
        r"C:\Windows"
    );
    assert_eq!(without_entry(DIR, DIR).unwrap(), "");
}

#[test]
fn a_path_that_does_not_name_the_directory_is_left_alone() {
    assert_eq!(without_entry(r"C:\Windows;;C:\Tools\;", DIR), None);
    assert_eq!(without_entry("", DIR), None);
}

#[test]
fn a_path_value_survives_being_stored_and_read_back() {
    let text = r"C:\Windows;%SystemRoot%\Ünï";
    let bytes = encode(text);

    assert_eq!(bytes.len(), (text.encode_utf16().count() + 1) * 2, "one NUL ends it");
    assert_eq!(decode(&bytes).unwrap(), text);
    assert!(decode(&bytes[1..]).is_err(), "half a code unit is not text");
}

#[test]
fn an_entry_that_names_the_directory_through_an_environment_variable_names_it() {
    let program_files = std::env::var("ProgramFiles").unwrap();
    let dir = format!(r"{program_files}\reverse-tunnel");

    assert_eq!(with_entry(r"%ProgramFiles%\reverse-tunnel;C:\Tools", &dir), None);
    assert_eq!(with_entry(r"%PROGRAMFILES%\Reverse-Tunnel\", &dir), None);
    assert_eq!(
        without_entry(r"C:\Tools;%ProgramFiles%\reverse-tunnel", &dir).unwrap(),
        r"C:\Tools"
    );
    // A variable that is not set stays as it is, and names nothing.
    assert_eq!(
        with_entry(r"%NoSuchVariableForReverseTunnel%\reverse-tunnel", &dir).unwrap(),
        format!(r"%NoSuchVariableForReverseTunnel%\reverse-tunnel;{dir}")
    );
}

#[test]
fn whitespace_and_quotes_around_an_entry_do_not_change_what_it_names() {
    for named in [
        format!("  {DIR}"),
        format!("{DIR}\t "),
        format!(r#" "{DIR}\" "#),
        format!(r#""  {DIR}  ""#),
    ] {
        assert_eq!(with_entry(&named, DIR), None, "{named:?}");
        assert_eq!(without_entry(&named, DIR).unwrap(), "", "{named:?}");
    }
}
