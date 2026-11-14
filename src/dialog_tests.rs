use std::fs;
use std::io::Cursor;

use tempfile::TempDir;

use super::*;

const CODE: &str = include_str!("../server/testdata/join-code.txt");
const PROMPT: &str = "Join code (run `uv run ctl join-code` on the bridge; an empty line gives up): ";

fn dialog(input: &str, interactive: bool) -> Dialog<Cursor<String>, Vec<u8>> {
    Dialog {
        input: Cursor::new(input.to_string()),
        out: Vec::new(),
        interactive,
    }
}

fn said(dialog: &Dialog<Cursor<String>, Vec<u8>>) -> String {
    String::from_utf8(dialog.out.clone()).unwrap()
}

/// `code` as a chat client wraps it: lines of 40 characters, indented, with Windows line ends.
fn wrapped(code: &str) -> String {
    let lines: Vec<&str> = code
        .as_bytes()
        .chunks(40)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!("  {}\r\n", lines.join("\r\n  "))
}

/// A host's directories in a temp dir; `configured` writes a `config.yaml` for `myhost`, and `joined` the bridge files.
fn machine(configured: bool, joined: bool) -> (TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir_all(&paths.secrets_dir).unwrap();
    if configured {
        let config = "host: myhost\nbridge: tunnel.example.test\nservices:\n  ssh:\n    port: 22\n    type: tcp\n";
        fs::write(paths.config_file(), config).unwrap();
    }
    if joined {
        fs::write(paths.bridge_pem(), "").unwrap();
        fs::write(paths.bridge_token(), "").unwrap();
    }
    (dir, paths)
}

#[test]
fn intro_names_what_is_set_up_and_where_the_config_is_saved() {
    let (_dir, paths) = machine(false, false);
    let mut dialog = dialog("", true);
    dialog.intro(&paths).unwrap();
    assert_eq!(
        said(&dialog),
        format!(
            "Setting up a system-wide reverse tunnel service.\n  Config is saved to: {}\n",
            paths.config_file().display()
        )
    );
}

#[test]
fn hostname_defaults_on_enter_and_takes_a_typed_name() {
    let mut accepted = dialog("\n", true);
    assert_eq!(accepted.ask_host(Some("minicooper")).unwrap(), "minicooper");
    assert_eq!(said(&accepted), "Hostname [minicooper]: ");

    let mut typed = dialog("  other \n", true);
    assert_eq!(typed.ask_host(Some("minicooper")).unwrap(), "other");
}

#[test]
fn hostname_asks_again_until_it_is_a_valid_name() {
    let mut asked = dialog("Not_Valid\n\nmyhost\n", true);
    assert_eq!(asked.ask_host(None).unwrap(), "myhost");
    assert_eq!(said(&asked).matches("Hostname: ").count(), 3);
    assert!(said(&asked).contains("one DNS label"), "{}", said(&asked));
}

#[test]
fn hostname_at_the_end_of_input_is_an_error_even_with_a_default() {
    let err = dialog("", true).ask_host(Some("minicooper")).unwrap_err();
    assert!(format!("{err:#}").contains("--host"), "{err:#}");
}

#[test]
fn a_new_config_asks_for_the_hostname_before_the_join_code() {
    let (_dir, paths) = machine(false, false);
    let mut dialog = dialog(&format!("myhost\n{}", wrapped(CODE.trim())), true);
    let host = dialog.host(&paths, None).unwrap();
    assert_eq!(host.as_deref(), Some("myhost"));
    let join = dialog.join(&paths, None).unwrap().unwrap();
    assert_eq!(join.domain, "tunnel.example.test");
    let said = said(&dialog);
    assert!(said.contains("Hostname"), "{said}");
    assert!(said.ends_with(PROMPT), "{said}");
}

#[test]
fn flags_are_not_asked_for_and_stdin_is_not_read() {
    let (_dir, paths) = machine(false, false);
    let mut dialog = dialog("", false);
    assert_eq!(dialog.host(&paths, Some("myhost")).unwrap().as_deref(), Some("myhost"));
    assert_eq!(
        dialog.join(&paths, Some(CODE)).unwrap().unwrap().domain,
        "tunnel.example.test"
    );
    assert_eq!(said(&dialog), "Hostname: myhost\n");
}

#[test]
fn without_a_terminal_a_missing_value_names_its_flag() {
    let (_dir, paths) = machine(false, false);
    let err = dialog("myhost\n", false).host(&paths, None).unwrap_err();
    assert!(format!("{err:#}").contains("--host"), "{err:#}");
    let err = dialog(CODE, false).join(&paths, None).unwrap_err();
    assert!(format!("{err:#}").contains("--join"), "{err:#}");
}

#[test]
fn an_existing_config_shows_its_host_and_asks_for_neither() {
    let (_dir, paths) = machine(true, true);
    let mut dialog = dialog("", false);
    assert_eq!(dialog.host(&paths, None).unwrap(), None);
    assert!(dialog.join(&paths, None).unwrap().is_none());
    assert_eq!(said(&dialog), "Hostname: myhost\n");
}

#[test]
fn an_existing_config_that_cannot_be_read_is_left_to_the_checks_after_the_dialog() {
    let (_dir, paths) = machine(true, true);
    fs::write(paths.config_file(), "host: [").unwrap();
    let mut dialog = dialog("", false);
    assert_eq!(dialog.host(&paths, None).unwrap(), None);
    assert_eq!(said(&dialog), "");
    assert!(dialog.host(&paths, Some("myhost")).is_err());
}

#[test]
fn an_existing_config_without_its_bridge_files_asks_for_the_join_code() {
    let (_dir, paths) = machine(true, false);
    let mut dialog = dialog(&wrapped(CODE.trim()), true);
    assert!(dialog.join(&paths, None).unwrap().is_some());
}

#[test]
fn host_that_differs_from_the_config_is_refused() {
    let (_dir, paths) = machine(true, true);
    let err = format!("{:#}", dialog("", true).host(&paths, Some("otherhost")).unwrap_err());
    let config = paths.config_file().display().to_string();
    assert_eq!(
        err,
        format!(
            "--host \"otherhost\" differs from this host's name \"myhost\" in {config}: `install` does not rename \
             a host. To rename it, uninstall it and install it again with --host otherhost"
        )
    );
    let err = format!("{:#}", dialog("", true).host(&paths, Some("Not_Valid")).unwrap_err());
    assert!(err.contains("not a valid name"), "{err}");
    assert_eq!(dialog("", true).host(&paths, Some("myhost")).unwrap(), None);
}

#[test]
fn join_prompt_gives_up_at_a_blank_line_or_the_end_of_input() {
    let half = &CODE[..CODE.len() / 2];
    for input in [format!("{half}\n\nmore\n"), format!("{half}\n")] {
        let err = dialog(&input, true).ask_join().unwrap_err();
        assert!(format!("{err:#}").contains("join code"), "{err:#}");
    }
}

#[test]
fn the_machine_name_is_lowercased_and_must_be_a_host_name() {
    assert_eq!(machine_host("DESKTOP-7Q2X").as_deref(), Some("desktop-7q2x"));
    for machine in ["Annas-MacBook.local", "my_box", ""] {
        assert_eq!(machine_host(machine), None, "{machine:?}");
    }
}
