use std::io::Cursor;

use super::*;
use crate::install::{self, InstallOpts};
use crate::test_support::{CODE, host_dirs, wrapped};

const PROMPT: &str = "Join code (run `uv run ctl join-code` on the bridge; an empty line gives up): ";

type Scripted = Dialog<Cursor<String>, Vec<u8>, Vec<u8>>;

fn dialog(input: &str, interactive: bool) -> Scripted {
    Dialog::new(Cursor::new(input.to_string()), Vec::new(), Vec::new(), interactive)
}

fn said(dialog: &Scripted) -> String {
    String::from_utf8(dialog.out.clone()).unwrap()
}

fn asked(dialog: &Scripted) -> String {
    String::from_utf8(dialog.prompts.clone()).unwrap()
}

#[test]
fn intro_names_what_is_set_up_and_where_the_config_is_saved() {
    let (_dir, paths) = host_dirs();
    let mut dialog = dialog("", true);
    dialog.intro(&paths).unwrap();
    assert_eq!(
        said(&dialog),
        format!(
            "Setting up a system-wide reverse tunnel service.\n  Config is saved to: {}\n",
            paths.config_file().display()
        )
    );
    assert_eq!(asked(&dialog), "");
}

#[test]
fn hostname_defaults_on_enter_and_takes_a_typed_name_lowercased() {
    let mut accepted = dialog("\n", true);
    assert_eq!(accepted.ask_host(Some("minicooper")).unwrap(), "minicooper");
    assert_eq!(asked(&accepted), "Hostname [minicooper]: ");
    assert_eq!(said(&accepted), "", "prompts are not results");

    let mut blank = dialog("  \n", true);
    assert_eq!(blank.ask_host(Some("minicooper")).unwrap(), "minicooper");

    let mut typed = dialog("  Other \n", true);
    assert_eq!(typed.ask_host(Some("minicooper")).unwrap(), "other");
}

#[test]
fn an_invalid_answer_is_not_replaced_by_the_default() {
    let mut dialog = dialog("not_valid\nother\n", true);
    assert_eq!(dialog.ask_host(Some("minicooper")).unwrap(), "other");
    let asked = asked(&dialog);
    assert_eq!(asked.matches("Hostname [minicooper]: ").count(), 2, "{asked}");
    assert!(asked.contains("at most 63 characters"), "{asked}");
}

#[test]
fn the_questions_go_to_stderr_and_the_results_to_stdout() {
    let mut dialog = dialog(&format!("myhost\n{}", wrapped(CODE.trim())), true);
    dialog.ask_host(None).unwrap();
    dialog.ask_join().unwrap();
    assert_eq!(said(&dialog), "");
    let asked = asked(&dialog);
    assert!(asked.starts_with("Hostname: "), "{asked}");
    assert!(asked.ends_with(PROMPT), "{asked}");

    dialog.show_host("myhost").unwrap();
    dialog.ready("the line\n").unwrap();
    assert_eq!(said(&dialog), "Hostname: myhost\nthe line\n");
}

#[test]
fn hostname_asks_again_until_it_is_a_valid_name_and_says_the_rule() {
    let mut dialog = dialog("not_valid\n\n-myhost\nmyhost\n", true);
    assert_eq!(dialog.ask_host(None).unwrap(), "myhost");
    let asked = asked(&dialog);
    assert_eq!(asked.matches("Hostname: ").count(), 4);
    for part in [
        "lowercase letters, digits and hyphens",
        "not starting or ending with a hyphen",
        "at most 63 characters",
    ] {
        assert!(asked.contains(part), "{part}: {asked}");
    }
}

#[test]
fn hostname_at_the_end_of_input_is_an_error_even_with_a_default() {
    let err = dialog("", true).ask_host(Some("minicooper")).unwrap_err();
    assert!(format!("{err:#}").contains("--host"), "{err:#}");
}

#[test]
fn join_prompt_gives_up_at_a_blank_line_or_the_end_of_input() {
    let half = &CODE[..CODE.len() / 2];
    for input in [format!("{half}\n\nmore\n"), format!("{half}\n"), half.to_string()] {
        let err = dialog(&input, true).ask_join().unwrap_err();
        assert!(
            format!("{err:#}").contains("no complete join code was entered"),
            "{input:?}: {err:#}"
        );
    }
}

#[test]
fn the_default_is_the_machines_first_label_lowercased_if_it_is_a_host_name() {
    assert_eq!(machine_host("DESKTOP-7Q2X").as_deref(), Some("desktop-7q2x"));
    assert_eq!(machine_host("Name-MacBook.local").as_deref(), Some("name-macbook"));
    for machine in ["my_box", "", ".local", "-a"] {
        assert_eq!(machine_host(machine), None, "{machine:?}");
    }
}

/// `install` with `host` and `join` as flags, on a fresh machine and a person typing a valid name and a code: it fails
/// with `error` in its message before it has asked or said anything.
fn assert_flags_fail_before_any_prompt(host: Option<&str>, join: Option<&str>, error: &str) {
    let (_dir, paths) = host_dirs();
    let opts = InstallOpts {
        host: host.map(str::to_string),
        join: join.map(str::to_string),
        paths,
    };
    let mut dialog = dialog(&format!("myhost\n{CODE}"), true);
    let err = format!("{:#}", install::install(opts, &mut dialog).unwrap_err());
    assert!(err.contains(error), "{host:?} {join:?}: {err}");
    assert_eq!((asked(&dialog), said(&dialog)), (String::new(), String::new()));
    assert_eq!(dialog.input.position(), 0, "the input was read");
}

#[test]
fn an_explicit_host_that_is_not_a_valid_name_fails_before_any_prompt() {
    let long = "a".repeat(64);
    for host in ["Desktop", "", long.as_str(), "my_box", "-a"] {
        assert_flags_fail_before_any_prompt(Some(host), None, "--host");
    }
}

#[test]
fn an_explicit_join_code_that_does_not_decode_fails_before_the_hostname_is_asked() {
    assert_flags_fail_before_any_prompt(None, Some("not a code"), "join code");
}
