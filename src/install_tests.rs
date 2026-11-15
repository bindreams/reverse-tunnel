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
use crate::test_support::{CODE, Closed, NotesAtFirstWrite, host_dirs, wrapped};

const CERT: &str = include_str!("../server/testdata/bridge.pem");

fn code_for(domain: &str, token: &str, cert: &str) -> String {
    let json = serde_json::json!({"domain": domain, "token": token, "cert": cert});
    format!("rt1:{}", URL_SAFE_NO_PAD.encode(json.to_string()))
}

/// For runs that must fail before they ask.
fn no_dialog() -> Dialog<Cursor<&'static str>, Vec<u8>, Vec<u8>> {
    Dialog::new(Cursor::new(""), Vec::new(), Vec::new(), false)
}

/// A host's directories in a temp dir, with the current user as the service account.
struct Machine {
    dir: TempDir,
    paths: Paths,
    account: Account,
}

impl Machine {
    fn new() -> Machine {
        let (dir, paths) = host_dirs();
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
        self.paths.config_file()
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
fn token_file_format() {
    let machine = Machine::new();
    let code = code_for("tunnel.example.test", "shared-token", CERT);
    machine.settings(Some("myhost"), Some(&code));

    let host = fs::read_to_string(machine.paths.host_token()).unwrap();
    let hex = host.strip_suffix('\n').expect("a newline ends the file");
    let lowercase_hex = hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    assert!(hex.len() == 64 && lowercase_hex, "{hex:?}");
    assert_eq!(
        fs::read_to_string(machine.paths.bridge_token()).unwrap(),
        "shared-token\n"
    );
}

#[test]
fn the_hash_of_the_host_token_is_recorded_for_everyone_to_read() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));

    let token = fs::read_to_string(machine.paths.host_token()).unwrap();
    let hash = fs::read_to_string(machine.paths.host_token_hash()).unwrap();
    assert_eq!(hash, format!("{}\n", join::token_hash(token.trim())));
    assert_eq!(mode_of(&machine.paths.host_token_hash()), 0o644);
}

/// Whatever is in the file, and whether it is there (an install from before it was recorded), `install` records the
/// hash of the token it has, so that the file cannot disagree with the token.
#[test]
fn the_recorded_hash_is_made_to_agree_with_the_token_on_every_install() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    let right = fs::read_to_string(machine.paths.host_token_hash()).unwrap();

    fs::write(machine.paths.host_token_hash(), "sha256:stale\n").unwrap();
    machine.settings(None, Some(CODE));
    assert_eq!(fs::read_to_string(machine.paths.host_token_hash()).unwrap(), right);

    fs::remove_file(machine.paths.host_token_hash()).unwrap();
    machine.settings(None, None);
    assert_eq!(fs::read_to_string(machine.paths.host_token_hash()).unwrap(), right);
}

/// Recording the hash is no reason to restart the service: it does not read the file.
#[test]
fn recording_the_hash_alone_changes_nothing_the_service_reads() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    fs::remove_file(machine.paths.host_token_hash()).unwrap();

    assert!(!machine.settings(None, Some(CODE)));
}

fn said_by_install_with(out: &mut Vec<u8>) -> Dialog<Cursor<&'static str>, &mut Vec<u8>, Vec<u8>> {
    Dialog::new(Cursor::new(""), out, Vec::new(), false)
}

/// The files are in place and the service is restarted when `closing` runs: whatever fails in it is said on stderr, and
/// nothing is returned for `install` to fail with. Here `status` fails, as there is no `config.yaml` to read.
#[test]
fn a_failure_in_the_closing_output_is_said_on_stderr_and_does_not_fail_install() {
    let machine = Machine::new();
    let manager = Fake::default();
    manager
        .install(&service::spec(&service::exe(&machine.paths)).unwrap(), false)
        .unwrap();
    let (mut said, mut warned) = (Vec::new(), Vec::new());

    closing(
        &manager,
        &machine.paths,
        &mut Dialog::new(Cursor::new(""), &mut said, &mut warned, false),
    );

    let (said, warned) = (String::from_utf8(said).unwrap(), String::from_utf8(warned).unwrap());
    assert!(said.starts_with("Reverse-tunnel v"), "{said}");
    assert!(
        warned.contains("the install is done, but showing its status failed"),
        "{warned}"
    );
    assert!(!warned.contains("`reverse-tunnel status`"), "{warned}");
    assert!(warned.contains("config.yaml"), "{warned}");
}

/// The first line of the closing output fails: that is said on stderr, with where the output is, and `status` is not
/// run, since nothing could show what it prints.
#[test]
fn a_failure_of_the_installed_line_is_said_on_stderr_and_skips_status() {
    let machine = Machine::new();
    let mut warned = Vec::new();

    closing(
        &Fake::default(),
        &machine.paths,
        &mut Dialog::new(Cursor::new(""), Closed, &mut warned, false),
    );

    let warned = String::from_utf8(warned).unwrap();
    assert!(
        warned.contains("the install is done, but its closing output failed"),
        "{warned}"
    );
    assert!(warned.contains("`reverse-tunnel status` shows it"), "{warned}");
    assert!(!warned.contains("showing its status failed"), "{warned}");
}

/// `install` is complete without `status` and without the README: what it ends with is `status`'s output, from the same
/// function, below the line that says it worked.
#[test]
fn install_ends_with_installed_and_what_status_prints() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    let manager = Fake::default();
    manager
        .install(&service::spec(&service::exe(&machine.paths)).unwrap(), false)
        .unwrap();

    let mut said = Vec::new();
    closing(&manager, &machine.paths, &mut said_by_install_with(&mut said));

    let mut status = Vec::new();
    ops::status(&manager, &machine.paths, &mut status).unwrap();
    let expected = format!(
        "Reverse-tunnel v{} has been installed!\n{}",
        env!("CARGO_PKG_VERSION"),
        String::from_utf8(status).unwrap()
    );
    assert_eq!(String::from_utf8(said).unwrap(), expected);
    assert!(expected.contains("\nhash: sha256:"), "{expected}");
}

/// An frpc whose download fails by construction, with no port or network involved: its scheme is not one `ureq`
/// speaks, and its host is under `.invalid`, which never resolves.
fn pin_nobody_serves() -> download::Pin {
    download::Pin {
        name: "frpc",
        version: "9.9.9",
        target: "x86_64-unknown-linux-gnu",
        url: "ftp://frpc.invalid/frp.tar.gz",
        sha256: "",
        member: "frpc",
    }
}

#[test]
fn the_frpc_download_is_announced_before_it_starts() {
    let machine = Machine::new();
    fs::create_dir(&machine.paths.bin_dir).unwrap();
    let mut said = Vec::new();

    let err = ensure_frpc(
        &machine.paths,
        &pin_nobody_serves(),
        &mut said_by_install_with(&mut said),
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("frp.tar.gz"), "{err:#}");
    assert_eq!(String::from_utf8(said).unwrap(), "Downloading frpc v9.9.9...\n");
}

/// The line is information: a closed stdout does not stop the download that follows it.
#[test]
fn a_closed_stdout_does_not_stop_the_frpc_download() {
    let machine = Machine::new();
    fs::create_dir(&machine.paths.bin_dir).unwrap();

    let err = ensure_frpc(
        &machine.paths,
        &pin_nobody_serves(),
        &mut Dialog::new(Cursor::new(""), Closed, Vec::new(), false),
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("frp.tar.gz"), "{err:#}");
}

#[test]
fn an_frpc_that_is_in_place_is_not_downloaded_or_announced() {
    let machine = installed_machine();
    let mut said = Vec::new();

    ensure_frpc(
        &machine.paths,
        &pin_nobody_serves(),
        &mut said_by_install_with(&mut said),
    )
    .unwrap();

    assert_eq!(said, b"");
}

#[test]
fn first_config_has_ssh_default() {
    let machine = Machine::new();
    assert!(machine.settings(Some("myhost"), Some(CODE)));

    let cfg = Config::load(&machine.config()).unwrap();
    assert_eq!(cfg.host, "myhost");
    assert_eq!(cfg.bridge, "tunnel.example.test");
    assert_eq!(cfg.default.as_deref(), Some("ssh"));
    let ssh = &cfg.services["ssh"];
    assert_eq!((ssh.port, ssh.r#type), (22, Kind::Tcp));
    assert_eq!(cfg.services.len(), 1);
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Logs a version that made them narrower left, with their rotated files, are made readable by everyone.
#[cfg(unix)]
#[test]
fn install_widens_the_logs_an_older_version_made() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    fs::create_dir(&machine.paths.log_dir).unwrap();
    let logs: Vec<PathBuf> = ["frpc.log", "frpc.log.1", "supervisor.log", "supervisor.log.1"]
        .map(|name| machine.paths.log_dir.join(name))
        .into();
    for log in &logs {
        fs::write(log, "").unwrap();
        fs::set_permissions(log, fs::Permissions::from_mode(0o600)).unwrap();
    }

    machine.settings(Some("myhost"), Some(CODE));

    for log in &logs {
        assert_eq!(mode_of(log), 0o644, "{}", log.display());
    }
}

/// `logs/` is the service account's: a link put in place of a log is not followed to change what it points at.
#[cfg(unix)]
#[test]
fn install_does_not_follow_a_link_where_a_log_is() {
    use std::os::unix::fs::PermissionsExt;

    let machine = Machine::new();
    fs::create_dir(&machine.paths.log_dir).unwrap();
    let target = machine.dir.path().join("target");
    fs::write(&target, "").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, machine.paths.frpc_log()).unwrap();

    let err = write_settings(&machine.paths, &machine.account, Some("myhost"), None).unwrap_err();

    assert!(format!("{err:#}").contains("frpc.log"), "{err:#}");
    assert_eq!(mode_of(&target), 0o600);
}

#[test]
fn uninstall_prints_revoke_line() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    assert_eq!(revoke_line(&machine.paths).unwrap(), "uv run ctl revoke myhost");
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
    let err = format!("{:#}", install(opts, &mut no_dialog()).unwrap_err());
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
    machine.settings(Some("myhost"), Some(CODE));
    fs::remove_file(machine.paths.bridge_pem()).unwrap();
    let opts = InstallOpts {
        host: Some("otherhost".to_string()),
        join: None,
        paths: machine.paths.clone(),
    };
    let err = format!("{:#}", install(opts, &mut no_dialog()).unwrap_err());
    assert!(err.contains("differs from this host's name"), "{err}");
}

#[test]
fn a_host_that_differs_from_the_config_is_refused() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    let err = format!("{:#}", ensure_same_host(&machine.config(), "otherhost").unwrap_err());
    assert_eq!(
        err,
        format!(
            "--host \"otherhost\" differs from this host's name \"myhost\" in {}: `install` does not rename a \
             host. To rename it, uninstall it and install it again with --host otherhost",
            machine.config().display()
        )
    );
    ensure_same_host(&machine.config(), "myhost").unwrap();
}

/// What `install` says when it must ask, cannot, and was given `host` and `join` as flags, on a machine whose
/// `config.yaml` exists or not.
fn no_terminal_error(machine: &Machine, host: Option<&str>, join: Option<&str>) -> String {
    let opts = InstallOpts {
        host: host.map(str::to_string),
        join: join.map(str::to_string),
        paths: machine.paths.clone(),
    };
    format!("{:#}", install(opts, &mut no_dialog()).unwrap_err())
}

#[test]
fn a_new_host_without_a_terminal_names_both_missing_flags_in_a_command_that_runs() {
    let exe = env::current_exe().unwrap();
    let err = no_terminal_error(&Machine::new(), None, None);
    assert!(
        err.ends_with(&format!(
            "so a host name and a join code must be given: run `sudo {} install --host NAME --join CODE`",
            exe.display()
        )),
        "{err}"
    );
}

#[test]
fn the_command_for_a_host_without_a_terminal_keeps_the_flags_already_given() {
    let exe = env::current_exe().unwrap();
    let err = no_terminal_error(&Machine::new(), Some("myhost"), None);
    assert!(
        err.ends_with(&format!(
            "so a join code must be given: run `sudo {} install --host myhost --join CODE`",
            exe.display()
        )),
        "{err}"
    );
    let err = no_terminal_error(&Machine::new(), None, Some(CODE));
    assert!(
        err.ends_with(&format!(
            "so a host name must be given: run `sudo {} install --host NAME --join CODE`",
            exe.display()
        )),
        "{err}"
    );
}

#[test]
fn a_configured_host_without_its_bridge_files_asks_only_for_the_join_code() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    fs::remove_file(machine.paths.bridge_pem()).unwrap();
    let err = no_terminal_error(&machine, None, None);
    assert!(err.contains("so a join code must be given: run `sudo"), "{err}");
    assert!(err.ends_with(" install --join CODE`"), "{err}");
}

#[test]
fn join_code_never_stored() {
    let machine = Machine::new();
    let code = code_for("tunnel.example.test", "shared-token", CERT);
    machine.settings(Some("myhost"), Some(&wrapped(&code)));

    for file in files_under(machine.dir.path()) {
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains(&code[4..]), "{} holds the join code", file.display());
    }
    assert!(!fs::read_to_string(machine.config()).unwrap().contains("shared-token"));
}

#[test]
fn rejoin_rewrites_bridge_files_only() {
    let machine = Machine::new();
    machine.settings(Some("myhost"), Some(CODE));
    let host_token = fs::read_to_string(machine.paths.host_token()).unwrap();
    let first = fs::read_to_string(machine.config()).unwrap();
    let edited = format!("# mine\n{first}  web:\n    port: 80\n    type: http\n");
    fs::write(machine.config(), &edited).unwrap();

    let new_cert = format!("{CERT}{CERT}");
    let code = code_for("new.example.test", "new-token", &new_cert);
    assert!(machine.settings(Some("other"), Some(&wrapped(&code))));

    let expected = edited.replace("bridge: tunnel.example.test", "bridge: new.example.test");
    assert_eq!(fs::read_to_string(machine.config()).unwrap(), expected);
    assert_eq!(fs::read_to_string(machine.paths.bridge_token()).unwrap(), "new-token\n");
    let pem = machine.paths.bridge_pem();
    assert_eq!(fs::read_to_string(pem).unwrap(), new_cert);
    assert_eq!(fs::read_to_string(machine.paths.host_token()).unwrap(), host_token);
}

#[test]
fn rejoin_changes_only_the_bridge_value() {
    let services = "services:\n  ssh: {port: 22, type: tcp}\n  bridge:\n    port: 8080\n    type: http\n";
    // A service called `bridge`; a config edited on Windows; a last line without a newline.
    let rows = [
        (
            format!("host: myhost\nbridge: old.example.test\n{services}"),
            format!("host: myhost\nbridge: new.example.test\n{services}"),
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
    machine.settings(Some("myhost"), Some(CODE));
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
fn bin_dir_cleaning_never_recurses_into_a_directory_that_has_a_stale_name() {
    let machine = Machine::new();
    let bin = &machine.paths.bin_dir;
    let stale = bin.join("frpc-0.0.1");
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("inside"), b"x").unwrap();

    clean_bin_dir(&machine.paths).unwrap_err();

    assert!(stale.join("inside").exists());
}

#[test]
fn unchanged_install_leaves_a_running_service_alone_and_says_nothing() {
    let machine = Machine::new();
    let spec = service::spec(&service::exe(&machine.paths)).unwrap();
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();
    manager.seed_state(spec.id.as_str(), State::Running);

    let mut said = Vec::new();

    pick_up(
        &manager,
        &spec.id,
        &machine.paths,
        false,
        &mut said_by_install_with(&mut said),
    )
    .unwrap();

    assert_eq!(manager.calls(), [("start", spec.id.to_string())]);
    assert_eq!(said, b"");
}

/// A start can take a while, so it is announced; nothing runs, so there is no connection to warn.
#[test]
fn unchanged_install_announces_the_start_of_a_service_that_is_not_running() {
    let machine = Machine::new();
    let spec = service::spec(&service::exe(&machine.paths)).unwrap();
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();
    let mut said = NotesAtFirstWrite::new(|| manager.calls().len());

    pick_up(
        &manager,
        &spec.id,
        &machine.paths,
        false,
        &mut Dialog::new(Cursor::new(""), &mut said, Vec::new(), false),
    )
    .unwrap();

    assert_eq!(String::from_utf8(said.text).unwrap(), "Starting the service...\n");
    assert_eq!(said.at_first_write, Some(0), "said before the start");
    assert_eq!(manager.calls(), [("start", spec.id.to_string())]);
    assert_eq!(manager.status(&spec.id).unwrap().state, State::Running);
}

/// The notice comes first on a first install too: the service is not running, and the kill finds nothing.
#[test]
fn kill_not_running_starts() {
    let machine = Machine::new();
    let spec = service::spec(&service::exe(&machine.paths)).unwrap();
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();
    let mut said = NotesAtFirstWrite::new(|| manager.calls().len());

    pick_up(
        &manager,
        &spec.id,
        &machine.paths,
        true,
        &mut Dialog::new(Cursor::new(""), &mut said, Vec::new(), false),
    )
    .unwrap();

    assert_eq!(manager.status(&spec.id).unwrap().state, State::Running);
    assert_eq!(
        String::from_utf8(said.text).unwrap(),
        format!("{}\n", ops::RESTART_NOTICE)
    );
    assert_eq!(said.at_first_write, Some(0), "said before the kill and the start");
    let id = spec.id.to_string();
    assert_eq!(manager.calls(), [("kill", id.clone()), ("start", id)]);
}

/// The start after the kill has the service running again when `pick_up` returns, so the status that follows shows it.
#[test]
fn restarting_a_running_service_is_announced_before_the_kill_and_ends_with_it_running() {
    let machine = Machine::new();
    let spec = service::spec(&service::exe(&machine.paths)).unwrap();
    let manager = Fake::default();
    manager.install(&spec, false).unwrap();
    manager.seed_state(spec.id.as_str(), State::Running);
    let mut said = NotesAtFirstWrite::new(|| manager.calls().len());

    pick_up(
        &manager,
        &spec.id,
        &machine.paths,
        true,
        &mut Dialog::new(Cursor::new(""), &mut said, Vec::new(), false),
    )
    .unwrap();

    assert_eq!(
        String::from_utf8(said.text).unwrap(),
        format!("{}\n", ops::RESTART_NOTICE)
    );
    assert_eq!(said.at_first_write, Some(0), "said before the kill");
    let id = spec.id.to_string();
    assert_eq!(manager.calls(), [("kill", id.clone()), ("start", id)]);
    assert_eq!(manager.status(&spec.id).unwrap().state, State::Running);
}

#[test]
fn restart_failure_is_retried_by_install() {
    let machine = Machine::new();
    // Never installed: the kill fails with something other than NotRunning.
    let mut said = Vec::new();
    let err = pick_up(
        &Fake::default(),
        &service::id(),
        &machine.paths,
        true,
        &mut said_by_install_with(&mut said),
    )
    .unwrap_err();

    assert_eq!(String::from_utf8(said).unwrap(), format!("{}\n", ops::RESTART_NOTICE));

    assert!(
        format!("{err:#}").contains("run `reverse-tunnel install` again"),
        "{err:#}"
    );
    assert!(
        format!("{err:#}").contains("`reverse-tunnel status` shows the host and hash"),
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
    let err = pick_up(&Fake::default(), &id, &machine.paths, true, &mut no_dialog()).unwrap_err();

    let text = format!("{err:#}");
    assert!(
        text.contains("`reverse-tunnel status` shows the host and hash"),
        "{text}"
    );
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
    machine.settings(Some("myhost"), Some(CODE));
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
    let mut outgoing = service::spec(&service::exe(&machine.paths)).unwrap().into_fields();
    outgoing.command.push("--outgoing".into());
    let outgoing = DaemonSpec::new(outgoing).unwrap();
    manager.install(&outgoing, false).unwrap();

    let new = Binary::read(&machine.paths, &new).unwrap();
    let err = set_up(&manager, &machine.account, &machine.paths, &new, None, None, false).unwrap_err();

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
    let new = Binary::read(&machine.paths, &new).unwrap();
    let join = join::decode(CODE).unwrap();
    let manager = Fake::default();

    let err = set_up(
        &manager,
        &machine.account,
        &machine.paths,
        &new,
        Some("myhost"),
        Some(&join),
        false,
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("stub stderr line"), "{err:#}");
    // Not registered: no unit points at a binary that was never placed.
    assert_eq!(
        manager
            .preview_install(&service::spec(&service::exe(&machine.paths)).unwrap())
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
    manager
        .install(&service::spec(&service::exe(&machine.paths)).unwrap(), false)
        .unwrap();
    let new = Binary::read(&machine.paths, &new).unwrap();

    set_up(&manager, &machine.account, &machine.paths, &new, None, None, false).unwrap();

    assert!(machine.dir.path().join("expected-env.ran").exists(), "the check ran");
    assert_eq!(fs::read(service::exe(&machine.paths)).unwrap(), new.bytes);
    assert_eq!(staged_copies(&machine), Vec::<PathBuf>::new());
}

#[test]
fn random_hex_is_the_hex_of_as_many_random_bytes_as_asked() {
    let (a, b) = (
        hex_of_random_bytes::<16>().unwrap(),
        hex_of_random_bytes::<16>().unwrap(),
    );

    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()), "{a}");
    assert_ne!(a, b);
    assert_eq!(hex_of_random_bytes::<32>().unwrap().len(), 64);
}
