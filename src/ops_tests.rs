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
    fs::write(paths.config_dir.join("config.yaml"), config).unwrap();
    fs::write(paths.config_dir.join("bridge.pem"), CERT).unwrap();
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
    fs::write(paths.secrets_dir.join("bridge.token"), "frps-secret\n").unwrap();
    fs::write(paths.secrets_dir.join("host.token"), "host-secret\n").unwrap();
    let manager = Fake::default();
    manager.install(&service::spec(&paths), false).unwrap();

    let text = status_text(&manager, &paths);

    assert!(text.contains("tunnel.example.test"), "{text}");
    assert!(text.contains(FINGERPRINT), "{text}");
    assert!(text.contains("stopped"), "{text}");
    assert!(!text.contains("secret"), "{text}");
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
    let env: String = service::spec(&paths)
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
    let id = service::spec(&paths).id;
    manager.install(&service::spec(&paths), false).unwrap();
    manager.seed_state(id.as_str(), State::Running);
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

    let err = check_and_restart_as(&manager, &paths, as_current_user()).unwrap_err();

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
    let id = service::spec(&paths).id;

    check_and_restart_as(&manager, &paths, as_current_user()).unwrap();

    assert_eq!(manager.calls(), [("kill", id.to_string())]);
    assert!(!pending_file(&paths).exists());
}

#[cfg(unix)]
#[test]
fn restart_that_fails_puts_the_marker_back() {
    let (_dir, paths, _) = host_checked_by_stub("pass");
    // Never installed: the kill fails with something other than NotRunning.
    let err = check_and_restart_as(&Fake::default(), &paths, as_current_user()).unwrap_err();

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
    let err = check_and_restart_as(&Fake::default(), &paths, as_current_user()).unwrap_err();

    let text = format!("{err:#}");
    assert!(text.contains("the service was not restarted"), "{text}");
    assert!(text.contains("`install` will not notice"), "{text}");
}

#[test]
fn restart_says_whether_it_killed_or_started_the_service() {
    let (_dir, paths) = host();
    let (manager, id) = (Fake::default(), service::spec(&paths).id);
    manager.install(&service::spec(&paths), false).unwrap();

    assert_eq!(restart(&manager, &id).unwrap(), RestartOutcome::Started);
    manager.seed_state(id.as_str(), State::Running);
    assert_eq!(restart(&manager, &id).unwrap(), RestartOutcome::Killed);
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
