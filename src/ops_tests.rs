use std::fs;

use goetia::manager::State;
use goetia::manager::fake::Fake;
use tempfile::TempDir;

use super::*;
use crate::service;

const CERT: &str = include_str!("../server/testdata/bridge.pem");
/// SHA-256 of `CERT`'s DER.
const FINGERPRINT: &str =
    "6C:F6:B8:24:0E:D8:DC:B3:29:84:C0:87:32:EF:1C:59:66:C0:06:8F:BB:63:B5:E4:9E:E8:AB:3B:BE:91:C4:DE";

fn host() -> (TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let paths = Paths::testing(root);
    for dir in [&paths.secrets_dir, &paths.log_dir] {
        fs::create_dir_all(dir).unwrap();
    }
    let config = "host: testhost\nbridge: tunnel.example.test\nservices:\n  ssh: {port: 22, type: tcp}\n";
    fs::write(paths.config_file(), config).unwrap();
    fs::write(paths.bridge_pem(), CERT).unwrap();
    (dir, paths)
}

fn status_text(manager: &Fake, paths: &Paths) -> String {
    let mut out = Vec::new();
    status(manager, paths, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn status_shows_domain_and_fingerprint_not_token() {
    let (_dir, paths) = host();
    fs::write(paths.bridge_token(), "frps-secret\n").unwrap();
    fs::write(paths.host_token(), "host-secret\n").unwrap();
    let manager = Fake::default();
    manager
        .install(&service::spec(&service::exe(&paths)).unwrap(), false)
        .unwrap();

    let text = status_text(&manager, &paths);

    assert!(text.contains("tunnel.example.test"), "{text}");
    assert!(text.contains(FINGERPRINT), "{text}");
    assert!(text.contains("stopped"), "{text}");
    assert!(!text.contains("secret"), "{text}");
    assert!(text.ends_with("frpc log: no log yet\n"), "{text}");
}

const TOKEN_HASH: &str = "sha256:60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55";

/// The two arguments of `ctl add` are the `host` and `hash` lines, in that order, so that they read as one.
#[test]
fn status_shows_the_recorded_hash_right_after_the_host() {
    let (_dir, paths) = host();
    fs::write(paths.host_token_hash(), format!("{TOKEN_HASH}\n")).unwrap();
    let manager = Fake::default();
    manager
        .install(&service::spec(&service::exe(&paths)).unwrap(), false)
        .unwrap();

    let text = status_text(&manager, &paths);

    assert!(
        text.contains(&format!(
            "\nhost: testhost\nhash: {TOKEN_HASH}\nbridge: tunnel.example.test\n"
        )),
        "{text}"
    );
}

/// An install from before the hash was recorded: `status` has no admin rights to compute it, and says what records it.
#[test]
fn status_says_when_the_hash_is_not_recorded_yet() {
    let (_dir, paths) = host();
    fs::write(paths.host_token(), "host-secret\n").unwrap();
    let manager = Fake::default();
    manager
        .install(&service::spec(&service::exe(&paths)).unwrap(), false)
        .unwrap();

    let text = status_text(&manager, &paths);

    assert!(
        text.contains(
            "\nhost: testhost\nhash: not recorded yet; run `reverse-tunnel install` (elevated) to record it\n"
        ),
        "{text}"
    );
    assert!(
        !text.contains("sha256:"),
        "status must not compute the hash from the token: {text}"
    );
}

/// A hash file that is there but cannot be read (here, a directory) is said so on the `hash:` line, as the log's is, and
/// the rest of `status` is still shown.
#[test]
fn status_says_when_the_hash_file_cannot_be_read() {
    let (_dir, paths) = host();
    fs::create_dir(paths.host_token_hash()).unwrap();
    let manager = Fake::default();
    manager
        .install(&service::spec(&service::exe(&paths)).unwrap(), false)
        .unwrap();

    let text = status_text(&manager, &paths);

    let (_, rest) = text.split_once("\nhost: testhost\nhash: ").unwrap();
    let (said, rest) = rest.split_once('\n').unwrap();
    assert!(said.contains("host-token.hash"), "{text}");
    assert!(rest.starts_with("bridge: tunnel.example.test\n"), "{text}");
    assert!(text.contains(FINGERPRINT), "{text}");
}

/// The host's `status` with the service in `state`, after `make_log` has made what is at frpc's log's path.
fn status_with(state: State, make_log: impl FnOnce(&Path)) -> String {
    let (_dir, paths) = host();
    make_log(&paths.frpc_log());
    let manager = Fake::default();
    let spec = service::spec(&service::exe(&paths)).unwrap();
    manager.install(&spec, false).unwrap();
    manager.seed_state(spec.id.as_str(), state);
    status_text(&manager, &paths)
}

/// The host's `status` with the service in `state` and `lines` lines in frpc's log.
fn status_with_log(state: State, lines: usize) -> String {
    let log: String = (1..=lines)
        .map(|n| {
            format!(
                "line {n}
"
            )
        })
        .collect();
    status_with(state, |path| fs::write(path, log).unwrap())
}

/// The end of frpc's log, as it is, after the certificate lines: the last ten lines of twelve.
#[test]
fn status_ends_with_the_last_ten_lines_of_frpc_log() {
    let text = status_with_log(State::Running, 12);

    let (_, log) = text.split_once(FINGERPRINT).unwrap();
    let (header, shown) = log.split_once(":\n").unwrap();
    let expected: String = (3..=12).map(|n| format!("line {n}\n")).collect();
    assert_eq!(shown, expected, "{text}");
    assert!(header.contains("frpc log (last 10 lines;"), "{text}");
}

/// The tail of a service that is not running is its last run's: `status` says so, and does not when it runs.
#[test]
fn status_says_when_the_log_tail_is_from_the_last_run() {
    for state in [State::Stopped, State::Failed] {
        let text = status_with_log(state, 3);
        assert!(
            text.contains("frpc log (last 10 lines, from the service's last run;"),
            "{text}"
        );
    }
    let text = status_with_log(State::Running, 3);
    assert!(!text.contains("last run"), "{text}");
}

/// A last line that frpc did not end with a newline still starts its own line after the tail.
#[test]
fn status_ends_a_last_line_that_has_no_newline() {
    let text = status_with(State::Running, |path| {
        fs::write(
            path, "one
two",
        )
        .unwrap()
    });

    assert!(
        text.ends_with(
            ":
one
two
"
        ),
        "{text}"
    );
}

#[test]
fn status_shows_the_header_alone_for_an_empty_log() {
    let text = status_with(State::Running, |path| fs::write(path, "").unwrap());

    assert!(
        text.ends_with(
            "shows it all):
"
        ),
        "{text}"
    );
}

/// A log that is there but cannot be read (here, a directory) is said so, and the rest of `status` is still shown.
#[test]
fn status_says_when_the_log_cannot_be_read() {
    let text = status_with(State::Running, |path| fs::create_dir(path).unwrap());

    let (_, tail) = text.split_once(FINGERPRINT).unwrap();
    let (_, said) = tail.split_once("frpc log: ").unwrap();
    assert!(said.contains("frpc.log"), "{text}");
    assert!(!text.contains("frpc log (last"), "{text}");
}

/// A host whose installed binary is a copy of `stub-frpc` in its `check` mode (`testbin/stub_frpc.rs`), which stands
/// for what `run --check` does and passes only given `--check`, the spec's environment and `/`, with a running service
/// and the restart marker; the check runs as the current user, which stands for the service account. `outcome` is the
/// stub's `pass` or `fail`.
#[cfg(unix)]
fn host_checked_by_stub(outcome: &str) -> (TempDir, Paths, Fake) {
    let (dir, paths) = host();
    fs::create_dir(&paths.bin_dir).unwrap();
    let exe = service::exe(&paths);
    crate::test_stub::copy_to(&exe);
    let env: String = service::spec(&service::exe(&paths))
        .unwrap()
        .env
        .iter()
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect();
    let env_file = paths.bin_dir.join("expected-env");
    fs::write(&env_file, env).unwrap();
    fs::write(
        exe.with_extension("mode"),
        format!("check {outcome} {}", env_file.display()),
    )
    .unwrap();
    let manager = Fake::default();
    let spec = service::spec(&service::exe(&paths)).unwrap();
    manager.install(&spec, false).unwrap();
    manager.seed_state(spec.id.as_str(), State::Running);
    fs::write(pending_file(&paths), "").unwrap();
    (dir, paths, manager)
}

#[cfg(unix)]
fn as_current_user() -> Option<crate::account::Account> {
    Some(crate::account::Account {
        uid: uzers::get_current_uid(),
        gid: uzers::get_current_gid(),
    })
}

#[cfg(unix)]
#[test]
fn restart_with_a_failing_check_leaves_the_service_alone() {
    let (_dir, paths, manager) = host_checked_by_stub("fail");

    let err = check_and_restart_as(&manager, &paths, &service::exe(&paths), as_current_user()).unwrap_err();

    let text = format!("{err:#}");
    assert!(
        text.contains("the service would not start with this configuration"),
        "{text}"
    );
    assert!(text.contains("stub stdout line"), "{text}");
    assert!(text.contains("stub stderr line"), "{text}");
    assert_eq!(manager.calls(), []);
    assert!(pending_file(&paths).exists());
}

/// The stub fails on a dropped `--check`, an inherited environment or directory, so a pass shows the check ran as the
/// service runs.
#[cfg(unix)]
#[test]
fn restart_with_a_passing_check_kills_the_service() {
    let (_dir, paths, manager) = host_checked_by_stub("pass");
    let id = service::id();

    check_and_restart_as(&manager, &paths, &service::exe(&paths), as_current_user()).unwrap();

    assert_eq!(manager.calls(), [("kill", id.to_string())]);
    assert!(!pending_file(&paths).exists());
}

#[cfg(unix)]
#[test]
fn restart_that_fails_puts_the_marker_back() {
    let (_dir, paths, _) = host_checked_by_stub("pass");
    // Never installed: the kill fails with something other than NotRunning.
    let err = check_and_restart_as(&Fake::default(), &paths, &service::exe(&paths), as_current_user()).unwrap_err();

    let text = format!("{err:#}");
    assert!(text.contains("the service was not restarted"), "{text}");
    assert!(!text.contains("will not notice"), "{text}");
    assert!(pending_file(&paths).exists());
}

#[cfg(unix)]
#[test]
fn restart_that_fails_without_a_marker_says_install_will_not_notice() {
    let (_dir, paths, _) = host_checked_by_stub("pass");
    // The marker cannot be written without its directory.
    fs::remove_dir_all(&paths.config_dir).unwrap();
    let err = check_and_restart_as(&Fake::default(), &paths, &service::exe(&paths), as_current_user()).unwrap_err();

    let text = format!("{err:#}");
    assert!(text.contains("the service was not restarted"), "{text}");
    assert!(text.contains("`install` will not notice"), "{text}");
}

#[test]
fn restart_pending_runs_what_comes_before_the_kill_after_the_marker_is_removed() {
    let (_dir, paths) = host();
    let manager = Fake::default();
    let spec = service::spec(&service::exe(&paths)).unwrap();
    manager.install(&spec, false).unwrap();
    manager.seed_state(spec.id.as_str(), State::Running);
    mark_pending(&paths).unwrap();
    let mut seen = None;

    let outcome = restart_pending(&manager, &spec.id, &paths, || {
        seen = Some((pending_file(&paths).exists(), manager.calls().len()));
    });

    assert!(outcome.is_ok());

    assert_eq!(
        seen,
        Some((false, 0)),
        "the marker is gone and the kill has not happened"
    );
    assert_eq!(manager.calls(), [("kill", spec.id.to_string())]);
}

#[test]
fn restart_says_whether_it_killed_or_started_the_service() {
    let (_dir, paths) = host();
    let manager = Fake::default();
    let spec = service::spec(&service::exe(&paths)).unwrap();
    manager.install(&spec, false).unwrap();
    let id = &spec.id;

    assert_eq!(restart(&manager, id).unwrap(), RestartOutcome::Started);
    manager.seed_state(id.as_str(), State::Running);
    assert_eq!(restart(&manager, id).unwrap(), RestartOutcome::Killed);
}

#[test]
fn restart_without_the_installed_binary_says_the_service_is_not_installed() {
    let (_dir, paths) = host();
    let manager = Fake::default();

    let err = check_and_restart(&manager, &paths).unwrap_err();

    // Not the account lookup's message: the account database can still answer for an account just removed.
    assert_eq!(err.to_string(), "the service is not installed");
    assert_eq!(manager.calls(), []);
}

#[cfg(windows)]
#[test]
fn restart_names_the_registered_image_that_is_missing() {
    let (_dir, paths) = host();
    let manager = Fake::default();
    let image = service::image(&paths, b"gone");
    manager.install(&service::spec(&image).unwrap(), false).unwrap();

    let err = check_and_restart(&manager, &paths).unwrap_err();

    assert_eq!(
        err.to_string(),
        format!(
            "the service is registered on {}, which is missing: run `install` again",
            image.display()
        )
    );
    assert_eq!(manager.calls(), []);
}

/// A restart during a removal would restart, or write the restart marker into, what the removal is deleting.
#[cfg(unix)]
#[test]
fn restart_refuses_while_an_uninstall_has_not_finished() {
    let (_dir, paths) = host();
    fs::write(paths.config_dir.join("uninstalling"), "").unwrap();
    let manager = Fake::default();

    let err = check_and_restart(&manager, &paths).unwrap_err();

    assert!(
        err.to_string().starts_with("an uninstall is in progress or failed"),
        "{err:#}"
    );
    assert_eq!(manager.calls(), []);
}
