use std::fs;

use goetia::manager::Budget;
use goetia::manager::fake::Fake;
use tempfile::TempDir;

use super::*;
use crate::paths::CONNECTION_RECORD;
use crate::service;

const CERT: &str = include_str!("../server/testdata/bridge.pem");
/// SHA-256 of `CERT`'s DER.
const FINGERPRINT: &str =
    "6C:F6:B8:24:0E:D8:DC:B3:29:84:C0:87:32:EF:1C:59:66:C0:06:8F:BB:63:B5:E4:9E:E8:AB:3B:BE:91:C4:DE";

fn host() -> (TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let paths = Paths {
        bin_dir: root.join("bin"),
        config_dir: root.join("config"),
        secrets_dir: root.join("config/secrets"),
        log_dir: root.join("logs"),
        lock: root.join("lock"),
        link: None,
    };
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
fn status_shows_the_record_only_of_the_run_that_is_the_service() {
    let (_dir, paths) = host();
    let manager = Fake::default();
    manager.install(&service::spec(&paths), false).unwrap();
    let id = service::spec(&paths).id;
    let connection = |record: Option<&str>| {
        let path = paths.log_dir.join(CONNECTION_RECORD);
        let _ = fs::remove_file(&path);
        if let Some(text) = record {
            fs::write(&path, text).unwrap();
        }
        let text = status_text(&manager, &paths);
        text.lines()
            .find(|line| line.starts_with("server connection"))
            .unwrap_or("")
            .to_string()
    };

    // A stopped service has no pid, and a service that died leaves its last record behind.
    assert_eq!(
        connection(Some("1 connected since 2026-11-03T15:54:46+01:00\n")),
        "server connection: none recorded"
    );
    manager.start(&id, Budget::Unbounded).unwrap();
    let pid = manager.status(&id).unwrap().pid.expect("a running service has a pid");
    assert_eq!(connection(None), "server connection: none recorded");
    // The service has started and its run has not written yet, or its write failed.
    assert_eq!(
        connection(Some(&format!(
            "{} connected since 2026-11-03T15:54:46+01:00\n",
            pid + 1
        ))),
        "server connection: none recorded"
    );
    assert_eq!(
        connection(Some(&format!("{pid} connected since 2026-11-03T15:54:46+01:00\n"))),
        "server connection: connected since 2026-11-03T15:54:46+01:00"
    );
}
