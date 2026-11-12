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
        let paths = Paths::testing(root);
        fs::create_dir(&paths.config_dir).unwrap();
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
    let long = "a".repeat(64);
    for host in ["Desktop", "my_box", long.as_str(), ""] {
        let err = format!("{:#}", host_name(Some(host)).unwrap_err());
        assert!(err.contains("--host"), "{host:?}: {err}");
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
    let token = "0".repeat(64);
    let line = super::registration_line("mothership", &token);
    assert_eq!(line, format!("uv run ctl add mothership {}", join::token_hash(&token)));
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
fn host_that_differs_from_the_config_is_refused() {
    let machine = Machine::new();
    assert_eq!(
        configured_host(&machine.paths, Some("mothership")).unwrap().as_deref(),
        Some("mothership"),
        "a first install takes the name"
    );
    machine.settings(Some("mothership"), Some(CODE));

    let err = format!("{:#}", configured_host(&machine.paths, Some("flagship")).unwrap_err());
    let config = config_file(&machine.paths).display().to_string();
    assert_eq!(
        err,
        format!(
            "--host \"flagship\" differs from this host's name \"mothership\" in {config}: `install` does not rename \
             a host. To rename it, uninstall it and install it again with --host flagship"
        )
    );
    let err = format!("{:#}", configured_host(&machine.paths, Some("Not_Valid")).unwrap_err());
    assert!(err.contains("not a valid name"), "{err}");
    for same in [Some("mothership"), None] {
        assert_eq!(configured_host(&machine.paths, same).unwrap(), None);
    }
}

#[test]
fn install_refused_during_an_uninstall_says_how_to_run_it_again() {
    let machine = Machine::new();
    fs::write(uninstalling_file(&machine.paths), "").unwrap();
    let opts = InstallOpts {
        host: None,
        join: None,
        paths: machine.paths.clone(),
    };
    let err = format!("{:#}", install(opts).unwrap_err());
    assert!(err.contains(&rerun_uninstall(&machine.paths)), "{err}");
    assert!(err.contains("`uninstall` with `sudo` and any"), "{err}");

    fs::create_dir_all(&machine.paths.bin_dir).unwrap();
    fs::write(service::exe(&machine.paths), "").unwrap();
    assert_eq!(
        rerun_uninstall(&machine.paths),
        format!("run `sudo {} uninstall`", service::exe(&machine.paths).display())
    );
}

#[test]
fn host_is_checked_before_the_join_code_is_asked_for() {
    let machine = Machine::new();
    machine.settings(Some("mothership"), Some(CODE));
    fs::remove_file(machine.paths.config_dir.join("bridge.pem")).unwrap();
    let opts = InstallOpts {
        host: Some("flagship".to_string()),
        join: None,
        paths: machine.paths.clone(),
    };
    let err = format!("{:#}", install(opts).unwrap_err());
    assert!(err.contains("differs from this host's name"), "{err}");
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
fn rejoin_changes_only_the_bridge_value() {
    let services = "services:\n  ssh: {port: 22, type: tcp}\n  bridge:\n    port: 8080\n    type: http\n";
    // A service called `bridge`; a config edited on Windows; a last line without a newline.
    let rows = [
        (
            format!("host: mothership\nbridge: old.example.test\n{services}"),
            format!("host: mothership\nbridge: new.example.test\n{services}"),
        ),
        (
            "\u{feff}host: m\r\nbridge: old.example.test\r\nservices: {}\r\n".to_string(),
            "\u{feff}host: m\r\nbridge: new.example.test\r\nservices: {}\r\n".to_string(),
        ),
        (
            "host: m\nservices: {}\nbridge: old.example.test".to_string(),
            "host: m\nservices: {}\nbridge: new.example.test".to_string(),
        ),
    ];
    let machine = Machine::new();
    machine.settings(Some("mothership"), Some(CODE));
    for (before, after) in rows {
        fs::write(machine.config(), &before).unwrap();

        machine.settings(None, Some(&code_for("new.example.test", "t", CERT)));

        assert_eq!(fs::read_to_string(machine.config()).unwrap(), after, "{before:?}");
    }
}

#[test]
fn rejoin_needs_exactly_one_bridge_line() {
    let config = Path::new("/etc/reverse-tunnel/config.yaml");
    let folded = "host: a\nbridge: >-\n  old.example.test\nservices: {}\n";
    for text in ["host: a\nservices: {}\n", "bridge: a\nbridge: b\n", folded] {
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
    // What an upgrade ran from, which nothing else removes.
    let staged = crate::upgrade::stage(&machine.paths, b"x").unwrap();
    for path in [&current, &exe, &bin.join("frpc-0.0.1"), &bin.join(".tmpAb12")] {
        fs::write(path, b"x").unwrap();
    }

    clean_bin_dir(&machine.paths).unwrap();

    assert!(!staged.exists());
    let mut kept = vec![current, exe];
    kept.sort();
    assert_eq!(files_under(bin), kept);
}

#[test]
fn unchanged_install_leaves_a_running_service_alone() {
    let machine = Machine::new();
    let spec = service::spec(&machine.paths).unwrap();
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();
    manager.seed_state(spec.id.as_str(), State::Running);

    pick_up(&manager, &spec.id, &machine.paths, false).unwrap();

    assert_eq!(manager.calls(), [("start", spec.id.to_string())]);
}

#[test]
fn kill_not_running_starts() {
    let machine = Machine::new();
    let spec = service::spec(&machine.paths).unwrap();
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();

    pick_up(&manager, &spec.id, &machine.paths, true).unwrap();

    assert_eq!(manager.status(&spec.id).unwrap().state, State::Running);
    let id = spec.id.to_string();
    assert_eq!(manager.calls(), [("kill", id.clone()), ("start", id)]);
}

#[test]
fn restart_failure_is_retried_by_install() {
    let machine = Machine::new();
    // Never installed: the kill fails with something other than NotRunning.
    let err = pick_up(&Fake::default(), &service::id(), &machine.paths, true).unwrap_err();

    assert!(
        format!("{err:#}").contains("run `reverse-tunnel install` again"),
        "{err:#}"
    );
    assert!(pending_file(&machine.paths).exists());
}

#[test]
fn restart_failure_is_reported_with_a_marker_that_cannot_be_written_back() {
    let machine = Machine::new();
    let id = service::id();
    // The marker cannot be written without its directory; the kill fails, as the service was never installed.
    fs::remove_dir_all(&machine.paths.config_dir).unwrap();
    let err = pick_up(&Fake::default(), &id, &machine.paths, true).unwrap_err();

    let text = format!("{err:#}");
    assert!(text.contains("the service was not restarted"), "{text}");
    assert!(text.contains("restart-pending"), "{text}");
    // The failure of the restart itself is there too: without it the operator is not told why.
    let restart_error = ops::restart(&Fake::default(), &id).unwrap_err();
    assert!(text.contains(&format!("{restart_error:#}")), "{text}");
    assert!(!text.contains("`reverse-tunnel install` again"), "{text}");
    assert!(
        text.contains("the next `install` will not notice, so run `reverse-tunnel restart`"),
        "{text}"
    );
}

/// The binary being installed: a copy of `stub-frpc` whose `run --check` ends in `outcome`, `pass` or `fail`. The
/// staged copy finds its mode in `stub.mode`.
fn new_binary(machine: &Machine, outcome: &str) -> PathBuf {
    let bin = &machine.paths.bin_dir;
    let new = machine.dir.path().join("new-reverse-tunnel");
    crate::test_stub::copy_to(&new);
    let env_file = machine.dir.path().join("expected-env");
    fs::write(&env_file, "").unwrap();
    fs::write(bin.join("stub.mode"), format!("check {outcome} {}", env_file.display())).unwrap();
    new
}

/// A host an earlier install left, settled and picked up, with the outgoing binary and an frpc in `bin/`.
fn installed_machine() -> Machine {
    let machine = Machine::new();
    machine.settings(Some("mothership"), Some(CODE));
    fs::remove_file(pending_file(&machine.paths)).unwrap();
    fs::create_dir(&machine.paths.bin_dir).unwrap();
    fs::write(service::exe(&machine.paths), b"the outgoing binary").unwrap();
    fs::write(download::tools(&machine.paths).frpc, b"frpc").unwrap();
    machine
}

fn staged_copies(machine: &Machine) -> Vec<PathBuf> {
    files_under(&machine.paths.bin_dir)
        .into_iter()
        .filter(|path| path.file_name().unwrap().to_str().unwrap().starts_with(upgrade::STAGED))
        .collect()
}

#[test]
fn upgrade_aborts_when_the_new_binary_rejects_the_settings() {
    let machine = installed_machine();
    let new = new_binary(&machine, "fail");
    let (config, manager) = (fs::read(machine.config()).unwrap(), Fake::default());
    // Not the unit the new binary would register.
    let mut outgoing = service::spec(&machine.paths).unwrap().into_fields();
    outgoing.command.push("--outgoing".into());
    let outgoing = DaemonSpec::new(outgoing).unwrap();
    manager.install(&outgoing, false).unwrap();

    let err = apply(&manager, &machine.account, &machine.paths, &new, None, None, false).unwrap_err();

    // The outgoing binary is not executable: it is the new one's check that failed.
    let text = format!("{err:#}");
    assert!(
        text.contains("the service would not start with this configuration"),
        "{text}"
    );
    assert!(text.contains("stub stderr line"), "{text}");
    assert_eq!(fs::read(service::exe(&machine.paths)).unwrap(), b"the outgoing binary");
    assert_eq!(fs::read(machine.config()).unwrap(), config);
    assert_eq!(manager.preview_install(&outgoing).unwrap(), Outcome::UpToDate);
    assert!(!pending_file(&machine.paths).exists());
    assert_eq!(staged_copies(&machine), Vec::<PathBuf>::new());
}

#[test]
fn first_install_aborts_when_the_new_binary_rejects_the_settings() {
    let machine = Machine::new();
    fs::create_dir(&machine.paths.bin_dir).unwrap();
    fs::write(download::tools(&machine.paths).frpc, b"frpc").unwrap();
    let new = new_binary(&machine, "fail");
    let join = join::decode(CODE).unwrap();
    let manager = Fake::default();

    let err = apply(
        &manager,
        &machine.account,
        &machine.paths,
        &new,
        Some("mothership"),
        Some(&join),
        false,
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("stub stderr line"), "{err:#}");
    // Not registered: no unit points at a binary that was never placed.
    assert_eq!(
        manager
            .preview_install(&service::spec(&machine.paths).unwrap())
            .unwrap(),
        Outcome::Create
    );
    assert!(!service::exe(&machine.paths).exists());
    assert_eq!(staged_copies(&machine), Vec::<PathBuf>::new());
}

#[test]
fn a_passing_check_places_the_new_binary_and_leaves_no_staged_copy() {
    let machine = installed_machine();
    let new = new_binary(&machine, "pass");
    let manager = Fake::default();
    manager.install(&service::spec(&machine.paths).unwrap(), false).unwrap();

    apply(&manager, &machine.account, &machine.paths, &new, None, None, false).unwrap();

    assert!(machine.dir.path().join("expected-env.ran").exists(), "the check ran");
    assert_eq!(fs::read(service::exe(&machine.paths)).unwrap(), fs::read(&new).unwrap());
    assert_eq!(staged_copies(&machine), Vec::<PathBuf>::new());
}
