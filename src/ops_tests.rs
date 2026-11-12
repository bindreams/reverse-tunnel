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

/// A host whose installed binary is a link to `program`, which stands for what `run --check` does; running as the
/// current user, which stands for the service account.
#[cfg(unix)]
fn host_checked_by(program: &str) -> (TempDir, Paths, Fake) {
    let (dir, paths) = host();
    fs::create_dir(&paths.bin_dir).unwrap();
    // A link: writing a program and running it races a fork.
    std::os::unix::fs::symlink(program, service::exe(&paths)).unwrap();
    let manager = Fake::default();
    let id = service::spec(&paths).id;
    manager.install(&service::spec(&paths), false).unwrap();
    manager.seed_state(id.as_str(), State::Running);
    fs::write(pending_file(&paths), "").unwrap();
    (dir, paths, manager)
}

#[cfg(unix)]
fn as_current_user() -> Option<(u32, u32)> {
    Some((uzers::get_current_uid(), uzers::get_current_gid()))
}

#[cfg(unix)]
#[test]
fn restart_with_a_failing_check_leaves_the_service_alone() {
    let (_dir, paths, manager) = host_checked_by("/bin/false");

    let err = check_and_restart_as(&manager, &paths, as_current_user()).unwrap_err();

    assert!(format!("{err:#}").contains("ended with"), "{err:#}");
    assert_eq!(manager.calls(), []);
    assert!(pending_file(&paths).exists());
}

#[cfg(unix)]
#[test]
fn restart_with_a_passing_check_kills_the_service() {
    let (_dir, paths, manager) = host_checked_by("/bin/true");
    let id = service::spec(&paths).id;

    check_and_restart_as(&manager, &paths, as_current_user()).unwrap();

    assert_eq!(manager.calls(), [("kill", id.to_string())]);
    assert!(!pending_file(&paths).exists());
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
