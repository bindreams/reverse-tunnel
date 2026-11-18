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
fn a_directory_after_a_trailing_separator_keeps_the_separator_after_it() {
    assert_eq!(with_entry(r"C:\Windows;", DIR).unwrap(), format!(r"C:\Windows;{DIR};"));
}

#[test]
fn removing_the_directory_that_was_added_gives_the_path_back_exactly() {
    for path in ["", "A", "A;B", "A;B;", "A;;B", ";"] {
        let added = with_entry(path, DIR).unwrap();

        assert_eq!(without_entry(&added, DIR).unwrap(), path, "{path:?} became {added:?}");
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
fn every_entry_equal_to_the_directory_is_removed_and_nothing_else_changes() {
    let path = format!(r"C:\Windows;;{DIR};C:\Tools\;{DIR};%SystemRoot%\x;");

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
    assert_eq!(decode_path(&bytes).unwrap(), text);
    assert!(decode_path(&bytes[1..]).is_err(), "half a code unit is not text");
}

#[test]
fn an_entry_differing_only_in_case_is_not_ours() {
    let other = DIR.to_uppercase();

    assert_eq!(without_entry(&other, DIR), None);
    assert_eq!(
        with_entry(&other, DIR).unwrap(),
        format!("{other};{DIR}"),
        "ours is added beside it"
    );
}

#[test]
fn a_directory_already_there_is_not_added() {
    assert_eq!(with_entry(&format!(r"C:\Windows;{DIR};C:\Tools"), DIR), None);
}
