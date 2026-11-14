use std::fs;
use std::io::Cursor;

use tempfile::TempDir;

use super::*;
use crate::install::{self, InstallOpts};
use crate::test_support::{CODE, host_dirs, wrapped};

const PROMPT: &str = "Join code (run `uv run ctl join-code` on the bridge; an empty line gives up): ";

type Scripted = Dialog<Cursor<String>, Vec<u8>, Vec<u8>>;

fn dialog(input: &str, interactive: bool) -> Scripted {
    Dialog::new(Cursor::new(input.to_string()), Vec::new(), Vec::new(), interactive)
}

/// What went to stdout.
fn said(dialog: &Scripted) -> String {
    String::from_utf8(dialog.out.clone()).unwrap()
}

/// What went to stderr.
fn asked(dialog: &Scripted) -> String {
    String::from_utf8(dialog.prompts.clone()).unwrap()
}

/// A host's directories in a temp dir; `configured` writes a `config.yaml` for `myhost`, and `joined` the bridge files.
fn machine(configured: bool, joined: bool) -> (TempDir, Paths) {
    let (dir, paths) = host_dirs();
    fs::create_dir(&paths.secrets_dir).unwrap();
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
    assert_eq!(asked(&dialog), "");
}

#[test]
fn hostname_defaults_on_enter_and_takes_a_typed_name_lowercased() {
    let mut accepted = dialog("\n", true);
    assert_eq!(accepted.ask_host(Some("minicooper")).unwrap(), "minicooper");
    assert_eq!(asked(&accepted), "Hostname [minicooper]: ");
    assert_eq!(said(&accepted), "", "prompts are not results");

    let mut typed = dialog("  Other \n", true);
    assert_eq!(typed.ask_host(Some("minicooper")).unwrap(), "other");
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
fn a_new_config_asks_for_the_hostname_before_the_join_code() {
    let (_dir, paths) = machine(false, false);
    let mut dialog = dialog(&format!("myhost\n{}", wrapped(CODE.trim())), true);
    let host = dialog.host(&paths, None).unwrap();
    assert_eq!(host.as_deref(), Some("myhost"));
    let join = dialog.join(&paths, None).unwrap().unwrap();
    assert_eq!(join.domain, "tunnel.example.test");
    let asked = asked(&dialog);
    assert!(asked.contains("Hostname"), "{asked}");
    assert!(asked.ends_with(PROMPT), "{asked}");
    assert_eq!(said(&dialog), "");
}

#[test]
fn flags_are_not_asked_for_and_stdin_is_not_read() {
    let (_dir, paths) = machine(false, false);
    let mut dialog = dialog("", false);
    let (host, join) = flags(Some("myhost"), Some(CODE)).unwrap();
    assert_eq!(dialog.host(&paths, host).unwrap().as_deref(), Some("myhost"));
    assert_eq!(
        dialog.join(&paths, join).unwrap().unwrap().domain,
        "tunnel.example.test"
    );
    assert_eq!(said(&dialog), "Hostname: myhost\n");
    assert_eq!(asked(&dialog), "");
}

#[test]
fn without_a_terminal_a_missing_value_names_the_command_that_gives_it() {
    let (_dir, paths) = machine(false, false);
    let err = dialog("myhost\n", false).host(&paths, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("`reverse-tunnel install --host NAME`"),
        "{err:#}"
    );
    let err = dialog(CODE, false).join(&paths, None).unwrap_err();
    assert!(
        format!("{err:#}").contains("`reverse-tunnel install --join CODE`"),
        "{err:#}"
    );
}

#[test]
fn an_existing_config_shows_its_host_and_asks_for_neither() {
    let (_dir, paths) = machine(true, true);
    let mut dialog = dialog("", false);
    assert_eq!(dialog.host(&paths, None).unwrap(), None);
    assert!(dialog.join(&paths, None).unwrap().is_none());
    assert_eq!(said(&dialog), "Hostname: myhost\n");
    assert_eq!(asked(&dialog), "");
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
    let (_dir, paths) = machine(false, false);
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
