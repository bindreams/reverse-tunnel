use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use goetia::manager::State;
use goetia::manager::fake::Fake;
use tempfile::TempDir;

use super::*;
use crate::config::Kind;

const CODE: &str = include_str!("../server/testdata/join-code.txt");
const CERT: &str = include_str!("../server/testdata/bridge.pem");

fn code_for(domain: &str, token: &str, cert: &str) -> String {
    let json = serde_json::json!({"domain": domain, "token": token, "cert": cert});
    format!("rt1:{}", URL_SAFE_NO_PAD.encode(json.to_string()))
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

/// A host's directories in a temp dir, with the current user as the service account.
struct Machine {
    dir: TempDir,
    paths: Paths,
    account: Account,
}

impl Machine {
    fn new() -> Machine {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let paths = Paths {
            bin_dir: root.join("bin"),
            config_dir: root.join("config"),
            secrets_dir: root.join("config/secrets"),
            log_dir: root.join("logs"),
            link: None,
        };
        let account = Account {
            uid: uzers::get_current_uid(),
            gid: uzers::get_current_gid(),
        };
        Machine { dir, paths, account }
    }

    /// `write_settings` as `install` calls it; returns whether anything changed.
    fn settings(&self, host: Option<&str>, code: Option<&str>) -> bool {
        let join = code.map(|code| join::decode(code).unwrap());
        write_settings(&self.paths, &self.account, host, join.as_ref()).unwrap()
    }

    fn config(&self) -> PathBuf {
        self.paths.config_dir.join("config.yaml")
    }

    fn secret(&self, name: &str) -> String {
        fs::read_to_string(self.paths.secrets_dir.join(name)).unwrap()
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(files_under(&path));
        } else {
            files.push(path);
        }
    }
    files.sort();
    files
}

#[test]
fn hostname_normalization() {
    assert_eq!(normalize_host("DESKTOP-7Q2X").unwrap(), "desktop-7q2x");
    for machine in ["Annas-MacBook.local", "my_box"] {
        let err = format!("{:#}", normalize_host(machine).unwrap_err());
        assert!(err.contains("--host") && err.contains(machine), "{err}");
    }
}

#[test]
fn join_prompt_accepts_wrapped_code() {
    let mut input = Cursor::new(wrapped(CODE.trim()));
    let info = prompt_join(&mut input, &mut Vec::new()).unwrap();
    assert_eq!(info.domain, "tunnel.example.test");
}

#[test]
fn join_prompt_gives_up_at_a_blank_line_or_the_end_of_input() {
    let half = &CODE[..CODE.len() / 2];
    for input in [format!("{half}\n\nmore\n"), format!("{half}\n")] {
        let err = prompt_join(&mut Cursor::new(input), &mut Vec::new()).unwrap_err();
        assert!(format!("{err:#}").contains("join code"), "{err:#}");
    }
}

#[test]
fn token_file_format() {
    let machine = Machine::new();
    let code = code_for("tunnel.example.test", "shared-token", CERT);
    machine.settings(Some("mothership"), Some(&code));

    let host = machine.secret("host.token");
    let hex = host.strip_suffix('\n').expect("a newline ends the file");
    let lowercase_hex = hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    assert!(hex.len() == 64 && lowercase_hex, "{hex:?}");
    assert_eq!(machine.secret("bridge.token"), "shared-token\n");
}

#[test]
fn registration_line() {
    let line = super::registration_line("mothership", &"0".repeat(64));
    assert_eq!(
        line,
        "uv run ctl add mothership sha256:60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55"
    );
}

#[test]
fn first_config_has_ssh_default() {
    let machine = Machine::new();
    assert!(machine.settings(Some("mothership"), Some(CODE)));

    let cfg = Config::load(&machine.config()).unwrap();
    assert_eq!(cfg.host, "mothership");
    assert_eq!(cfg.bridge, "tunnel.example.test");
    assert_eq!(cfg.default.as_deref(), Some("ssh"));
    let ssh = &cfg.services["ssh"];
    assert_eq!((ssh.port, ssh.r#type), (22, Kind::Tcp));
    assert_eq!(cfg.services.len(), 1);
}

#[test]
fn uninstall_prints_revoke_line() {
    let machine = Machine::new();
    machine.settings(Some("mothership"), Some(CODE));
    assert_eq!(revoke_line(&machine.paths).unwrap(), "uv run ctl revoke mothership");
}

#[test]
fn join_code_never_stored() {
    let machine = Machine::new();
    let code = code_for("tunnel.example.test", "shared-token", CERT);
    machine.settings(Some("mothership"), Some(&wrapped(&code)));

    for file in files_under(machine.dir.path()) {
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains(&code[4..]), "{} holds the join code", file.display());
    }
    assert!(!fs::read_to_string(machine.config()).unwrap().contains("shared-token"));
}

#[test]
fn rejoin_rewrites_bridge_files_only() {
    let machine = Machine::new();
    machine.settings(Some("mothership"), Some(CODE));
    let host_token = machine.secret("host.token");
    let first = fs::read_to_string(machine.config()).unwrap();
    let edited = format!("# mine\n{first}  web:\n    port: 80\n    type: http\n");
    fs::write(machine.config(), &edited).unwrap();

    let new_cert = format!("{CERT}{CERT}");
    let code = code_for("new.example.test", "new-token", &new_cert);
    assert!(machine.settings(Some("other"), Some(&wrapped(&code))));

    let expected = edited.replace("bridge: tunnel.example.test", "bridge: new.example.test");
    assert_eq!(fs::read_to_string(machine.config()).unwrap(), expected);
    assert_eq!(machine.secret("bridge.token"), "new-token\n");
    let pem = machine.paths.config_dir.join("bridge.pem");
    assert_eq!(fs::read_to_string(pem).unwrap(), new_cert);
    assert_eq!(machine.secret("host.token"), host_token);
}

#[test]
fn rejoin_with_service_named_bridge() {
    let machine = Machine::new();
    machine.settings(Some("mothership"), Some(CODE));
    let services = "services:\n  ssh: {port: 22, type: tcp}\n  bridge:\n    port: 8080\n    type: http\n";
    fs::write(
        machine.config(),
        format!("host: mothership\nbridge: old.example.test\n{services}"),
    )
    .unwrap();

    machine.settings(None, Some(&code_for("new.example.test", "t", CERT)));

    let text = fs::read_to_string(machine.config()).unwrap();
    assert_eq!(text, format!("host: mothership\nbridge: new.example.test\n{services}"));
}

#[test]
fn rejoin_needs_exactly_one_bridge_line() {
    let config = Path::new("/etc/reverse-tunnel/config.yaml");
    for text in ["host: a\nservices: {}\n", "bridge: a\nbridge: b\n"] {
        let err = with_bridge(text, "new.example.test", config).unwrap_err();
        assert!(err.to_string().contains("/etc/reverse-tunnel/config.yaml"), "{err}");
    }
}

#[test]
fn bin_dir_loses_old_versions_and_temp_files() {
    let machine = Machine::new();
    let bin = &machine.paths.bin_dir;
    fs::create_dir(bin).unwrap();
    let (current, exe) = (download::tools(&machine.paths).frpc, service::exe(&machine.paths));
    for path in [&current, &exe, &bin.join("frpc-0.0.1"), &bin.join(".tmpAb12")] {
        fs::write(path, b"x").unwrap();
    }

    clean_bin_dir(&machine.paths).unwrap();

    let mut kept = vec![current, exe];
    kept.sort();
    assert_eq!(files_under(bin), kept);
}

#[test]
fn kill_not_running_starts() {
    let machine = Machine::new();
    let spec = service::spec(&machine.paths);
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();

    pick_up(&manager, &spec.id, true).unwrap();

    assert_eq!(manager.status(&spec.id).unwrap().state, State::Running);
    let id = spec.id.to_string();
    assert_eq!(manager.calls(), [("kill", id.clone()), ("start", id)]);
}
