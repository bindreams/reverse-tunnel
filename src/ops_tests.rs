use std::fs;

use goetia::manager::State;
use goetia::manager::fake::Fake;
use tempfile::TempDir;

use super::*;
use crate::{download, service};

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

#[test]
fn restart_with_a_broken_config_leaves_the_service_alone() {
    let (_dir, paths) = host();
    fs::write(paths.config_dir.join("config.yaml"), "services: [").unwrap();
    let manager = Fake::default();
    let id = service::spec(&paths).id;
    manager.install(&service::spec(&paths), false).unwrap();
    manager.seed_state(id.as_str(), State::Running);

    let err = check_and_restart(&manager, &paths, &download::tools(&paths)).unwrap_err();

    assert!(format!("{err:#}").contains("config.yaml"), "{err:#}");
    assert_eq!(manager.calls(), []);
}

#[cfg(unix)]
#[test]
fn restart_with_a_valid_config_kills_the_service() {
    let (_dir, paths) = host();
    for token in ["bridge.token", "host.token"] {
        fs::write(paths.secrets_dir.join(token), "secret\n").unwrap();
    }
    fs::create_dir(&paths.bin_dir).unwrap();
    // An frpc that accepts whatever it is asked to verify. A link: writing a program and running it races a fork.
    let tools = download::tools(&paths);
    std::os::unix::fs::symlink("/bin/true", &tools.frpc).unwrap();
    let manager = Fake::default();
    let id = service::spec(&paths).id;
    manager.install(&service::spec(&paths), false).unwrap();
    manager.seed_state(id.as_str(), State::Running);

    check_and_restart(&manager, &paths, &tools).unwrap();

    assert_eq!(manager.calls(), [("kill", id.to_string())]);
}
