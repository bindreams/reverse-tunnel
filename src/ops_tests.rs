use std::fs;

use goetia::manager::fake::Fake;
use tempfile::TempDir;

use super::*;
use crate::paths::LOG_FRPC;
use crate::service;

const CERT: &str = include_str!("../server/testdata/bridge.pem");
/// SHA-256 of `CERT`'s DER.
const FINGERPRINT: &str =
    "6C:F6:B8:24:0E:D8:DC:B3:29:84:C0:87:32:EF:1C:59:66:C0:06:8F:BB:63:B5:E4:9E:E8:AB:3B:BE:91:C4:DE";
const LOGIN_SUCCESS: &str = include_str!("../server/testdata/frpc-login-success.log");
const HOST_NOT_REGISTERED: &str = include_str!("../server/testdata/frpc-host-not-registered.log");
const TOKEN_MISMATCH: &str = include_str!("../server/testdata/frpc-token-mismatch.log");

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
fn status_reports_last_login_line() {
    let (_dir, paths) = host();
    let manager = Fake::default();
    manager.install(&service::spec(&paths), false).unwrap();
    let frpc = paths.log_dir.join(LOG_FRPC);
    let rotated = paths.log_dir.join(format!("{LOG_FRPC}.1"));
    let login = |frpc_log: &str, rotated_log: Option<&str>| {
        fs::write(&frpc, frpc_log).unwrap();
        let _ = fs::remove_file(&rotated);
        if let Some(text) = rotated_log {
            fs::write(&rotated, text).unwrap();
        }
        let text = status_text(&manager, &paths);
        text.lines()
            .find(|line| line.starts_with("last login"))
            .unwrap_or("")
            .to_string()
    };

    assert_eq!(login("", None), "last login: no login recorded");
    assert_eq!(
        login(LOGIN_SUCCESS, None),
        "last login: success (2026-11-01 17:02:16.481)"
    );
    assert_eq!(
        login(HOST_NOT_REGISTERED, None),
        "last login: failed (2026-11-01 17:02:14.316): host not registered"
    );
    assert_eq!(
        login(&format!("{LOGIN_SUCCESS}{TOKEN_MISMATCH}"), None),
        "last login: failed (2026-11-01 17:02:16.471): token mismatch"
    );
    // A last line cut off mid-write is not a result yet.
    let cut =
        format!("{LOGIN_SUCCESS}2026-11-01 17:02:20.000 [W] [client/service.go:346] connect to server error: host not");
    assert_eq!(login(&cut, None), "last login: success (2026-11-01 17:02:16.481)");
    // A log that has just rotated holds no result yet.
    let fresh = "2026-11-01 17:03:00.000 [I] [client/service.go:335] try to connect to server...\n";
    assert_eq!(
        login(fresh, Some(LOGIN_SUCCESS)),
        "last login: success (2026-11-01 17:02:16.481)"
    );
    // A rotation between two chunks splits a line across the files.
    let head = format!("{LOGIN_SUCCESS}2026-11-01 17:02:");
    let tail = "14.316 [W] [client/service.go:346] connect to server error: host not registered
";
    assert_eq!(
        login(tail, Some(&head)),
        "last login: failed (2026-11-01 17:02:14.316): host not registered"
    );
}
