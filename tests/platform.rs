//! `install` and `uninstall` against the real service manager, account database and file system, as root. They run
//! only on CI's `platform` job (`RT_PLATFORM_TESTS=1`), one at a time, on a machine nothing else lives on; never on a
//! developer's machine.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use goetia::manager::{self, Installed, ServiceManager, State, Status};
use goetia::spec::Id;
use reverse_tunnel::account::{self, Account};
use reverse_tunnel::install;
use reverse_tunnel::paths::Paths;
use reverse_tunnel::service;
use rustix::process::{Pid, Signal, kill_process_group};

const BIN: &str = env!("CARGO_BIN_EXE_reverse-tunnel");
const CERT: &str = include_str!("../server/testdata/bridge.pem");

/// An account the test creates, to stand in for any local user.
const PROBE: &str = "rtprobe";

/// A join code for a domain that never resolves; its token names the domain.
fn join_code(domain: &str) -> String {
    let json = serde_json::json!({"domain": domain, "token": format!("token-for-{domain}"), "cert": CERT});
    format!("rt1:{}", URL_SAFE_NO_PAD.encode(json.to_string()))
}

fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    eprintln!("waiting until {what}");
    while !condition() {
        thread::sleep(Duration::from_millis(100));
    }
}

/// Waits for `uninstall --finish`, which `uninstall` starts, to end. On Linux it is a systemd unit named for the run,
/// and is over when it is gone: a unit that is queued reads as inactive, with no process. Call it once the removal has
/// started, as the unit exists from then on.
fn wait_until_removed() {
    wait_until("the removal ends", || {
        let unit_present = cfg!(target_os = "linux")
            && !output_of(
                "systemctl",
                &[
                    "list-units",
                    "--all",
                    "--plain",
                    "--no-legend",
                    "reverse-tunnel-uninstall-*",
                ],
            )
            .trim()
            .is_empty();
        !unit_present
            && !processes()
                .iter()
                .any(|process| process.args.ends_with("uninstall --finish"))
    });
}

fn output_of(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

struct Process {
    pid: u32,
    uid: u32,
    args: String,
}

fn processes() -> Vec<Process> {
    output_of("ps", &["-axo", "pid=,uid=,args="])
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (pid, uid) = (fields.next()?.parse().ok()?, fields.next()?.parse().ok()?);
            Some(Process {
                pid,
                uid,
                args: fields.collect::<Vec<_>>().join(" "),
            })
        })
        .collect()
}

/// The system, with the service not installed. Dropping it removes whatever a test installed.
struct Machine {
    paths: Paths,
    manager: Box<dyn ServiceManager>,
    id: Id,
}

impl Machine {
    fn begin() -> Machine {
        assert_eq!(
            env::var("RT_PLATFORM_TESTS").as_deref(),
            Ok("1"),
            "these tests install a real service; they run on CI's platform job only (RT_PLATFORM_TESTS=1)"
        );
        assert_eq!(rustix::process::getuid().as_raw(), 0, "these tests need root");
        let paths = Paths::system().unwrap();
        let id = service::spec(&paths).id;
        let manager = manager::native().unwrap();
        for dir in [&paths.bin_dir, &paths.config_dir, &paths.log_dir] {
            assert!(!dir.exists(), "{} is left from before", dir.display());
        }
        let accounts = account_names();
        for account in [service::ACCOUNT, PROBE] {
            assert!(!accounts.contains(account), "{account} is left from before");
        }
        assert!(
            matches!(manager.status(&id), Err(goetia::Error::NotInstalled { .. })),
            "the service is left from before"
        );
        if let Some(link) = &paths.link {
            assert!(
                link.symlink_metadata().is_err(),
                "{} is left from before",
                link.display()
            );
        }
        Machine { paths, manager, id }
    }

    fn install_command(&self, code: &str) -> Command {
        let mut install = Command::new(BIN);
        install.args(["install", "--host", "testhost", "--join", code]);
        install
    }

    fn run_ok(&self, mut command: Command) {
        let out = command.output().unwrap();
        assert!(
            out.status.success(),
            "{command:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn install(&self, code: &str) {
        self.run_ok(self.install_command(code));
    }

    fn status(&self) -> Status {
        self.manager.status(&self.id).unwrap()
    }

    /// The service's account, which exists once installed.
    fn service_account(&self) -> Account {
        account::lookup(service::ACCOUNT).expect("install creates the service account")
    }

    fn frpc(&self) -> Vec<Process> {
        let prefix = format!("{}/frpc-", self.paths.bin_dir.display());
        processes()
            .into_iter()
            .filter(|p| p.args.starts_with(&prefix))
            .collect()
    }

    fn wait_for_frpc(&self) -> Vec<Process> {
        wait_until("frpc runs", || !self.frpc().is_empty());
        self.frpc()
    }

    fn secrets(&self) -> PathBuf {
        self.paths.secrets_dir.clone()
    }

    /// Runs `program args` as the probe account, which `acls_as_specified` creates; whether it succeeded.
    fn probe(&self, program: &str, path: &Path) -> bool {
        let status = Command::new("sudo")
            .args(["-n", "-u", PROBE, "--", program])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        status.success()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = Command::new(BIN).args(["uninstall", "--finish"]).status();
        #[cfg(target_os = "linux")]
        {
            // `su -l` starts the account's user manager, user@<uid>.service, which outlives the session, and `userdel`
            // refuses while anything of the account runs. (`pgrep` fails for an account that is gone.)
            let _ = Command::new("loginctl").args(["terminate-user", PROBE]).status();
            wait_until("the probe account has no processes", || {
                !Command::new("pgrep").args(["-u", PROBE]).status().unwrap().success()
            });
        }
        let removed = account::remove(PROBE);
        if !thread::panicking() {
            removed.unwrap();
        }
    }
}

/// The name of every user and group, from the account database; the lookup cache that `account::lookup` goes through
/// can still answer for an account that has just been removed.
fn account_names() -> BTreeSet<String> {
    let listing = if cfg!(target_os = "macos") {
        output_of("dscl", &[".", "-list", "/Users"]) + &output_of("dscl", &[".", "-list", "/Groups"])
    } else {
        output_of("getent", &["passwd"]) + &output_of("getent", &["group"])
    };
    listing
        .lines()
        .map(|line| line.split([':', ' ']).next().unwrap().to_string())
        .collect()
}

/// A name this tool gives: `reverse-tunnel*`, or `_reverse-tunnel*` for a macOS account.
fn ours(path: &Path) -> bool {
    let name = path.file_name().and_then(|name| name.to_str());
    name.is_some_and(|name| name.trim_start_matches('_').starts_with("reverse-tunnel"))
}

/// Every name of ours the machine keeps that an install could leave behind: files and directories next to the
/// install's, the service manager's units, and every account.
fn snapshot(machine: &Machine) -> BTreeSet<String> {
    fn tree(dir: &Path, into: &mut BTreeSet<String>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries {
            let path = entry.unwrap().path();
            if ours(&path) {
                into.insert(path.display().to_string());
            }
            tree(&path, into);
        }
    }
    let mut seen = BTreeSet::new();
    let paths = &machine.paths;
    let parents = [
        paths.bin_dir.parent(),
        paths.config_dir.parent(),
        paths.log_dir.parent(),
    ];
    for parent in parents
        .into_iter()
        .flatten()
        .chain(paths.link.as_deref().and_then(Path::parent))
    {
        for entry in fs::read_dir(parent).unwrap() {
            let path = entry.unwrap().path();
            if ours(&path) {
                seen.insert(path.display().to_string());
            }
        }
    }
    let units: &[&str] = if cfg!(target_os = "macos") {
        &["/Library/LaunchDaemons", "/Library/Application Support/Goetia"]
    } else {
        &["/etc/systemd/system"]
    };
    for dir in units {
        tree(Path::new(dir), &mut seen);
    }
    seen.extend(account_names().into_iter().map(|name| format!("account {name}")));
    for installed in machine.manager.list().unwrap() {
        seen.insert(match installed {
            Installed::Ours { spec, .. } => format!("service {}", spec.id),
            other => format!("service {other:?}"),
        });
    }
    seen
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

/// The modes, the owners and the access the installation is specified to give.
fn assert_installed_as_specified(machine: &Machine) {
    let paths = &machine.paths;
    let service = machine.service_account();
    account::ensure(PROBE).unwrap();

    let secrets_dir_mode = if cfg!(target_os = "linux") { 0o2750 } else { 0o750 };
    let expected = [
        (paths.config_dir.clone(), 0o755),
        (paths.config_dir.join("config.yaml"), 0o644),
        (paths.config_dir.join("bridge.pem"), 0o644),
        (paths.log_dir.clone(), 0o755),
        (paths.secrets_dir.clone(), secrets_dir_mode),
        (machine.secrets().join("bridge.token"), 0o640),
        (machine.secrets().join("host.token"), 0o640),
        (paths.bin_dir.clone(), 0o755),
        (service::exe(paths), 0o755),
    ];
    for (path, mode) in expected {
        assert_eq!(mode_of(&path), mode, "mode of {}", path.display());
    }
    for token in ["bridge.token", "host.token"] {
        let meta = fs::metadata(machine.secrets().join(token)).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (0, service.gid), "owner of {token}");
    }
    assert_eq!(fs::metadata(&paths.log_dir).unwrap().uid(), service.uid);
    let link = paths.link.as_ref().unwrap();
    assert_eq!(
        fs::read_link(link).unwrap(),
        service::exe(paths),
        "where {} points",
        link.display()
    );

    for readable in [
        paths.config_dir.join("config.yaml"),
        paths.config_dir.join("bridge.pem"),
    ] {
        assert!(
            machine.probe("cat", &readable),
            "{} is not readable by everyone",
            readable.display()
        );
    }
    assert!(machine.probe("ls", &paths.log_dir), "logs/ is not readable by everyone");
    assert!(
        !machine.probe("ls", &paths.secrets_dir),
        "secrets/ can be listed by another user"
    );
    for token in ["bridge.token", "host.token"] {
        assert!(
            !machine.probe("cat", &machine.secrets().join(token)),
            "{token} is readable by another user"
        );
    }

    // frpc runs only after the supervisor read both tokens, which it does as the service account.
    assert!(machine.wait_for_frpc().iter().all(|frpc| frpc.uid == service.uid));
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn install_then_service_running() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    assert_eq!(machine.status().state, State::Running);
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn service_is_enabled_at_boot() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    assert!(machine.status().enabled);
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn acls_as_specified() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    assert_installed_as_specified(&machine);
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn install_under_umask_077() {
    let machine = Machine::begin();
    let mut install = Command::new("sh");
    install
        .args([
            "-c",
            "umask 077; exec \"$0\" install --host testhost --join \"$1\"",
            BIN,
        ])
        .arg(join_code("tunnel.example.test"));
    machine.run_ok(install);
    assert_installed_as_specified(&machine);
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn kill_supervisor_is_restarted() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    let supervisor = machine.status().pid.expect("a running service has a pid");
    let frpc: Vec<u32> = machine.wait_for_frpc().iter().map(|p| p.pid).collect();

    machine.manager.kill(&machine.id).unwrap();

    wait_until("the manager runs a new supervisor", || {
        let status = machine.manager.status(&machine.id).unwrap();
        status.state == State::Running && status.pid.is_some_and(|pid| pid != supervisor)
    });
    wait_until("the old frpc is gone", || {
        machine.frpc().iter().all(|process| !frpc.contains(&process.pid))
    });
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn reinstall_changes_nothing() {
    let machine = Machine::begin();
    let code = join_code("tunnel.example.test");
    machine.install(&code);
    let supervisor = machine.status().pid;

    machine.install(&code);

    let status = machine.status();
    assert_eq!((status.state, status.pid), (State::Running, supervisor));
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn rejoin_takes_effect() {
    let machine = Machine::begin();
    machine.install(&join_code("old.example.test"));
    let rendered = machine.paths.log_dir.join("frpc.toml");
    wait_until("the supervisor renders its first start", || rendered.exists());
    let supervisor = machine.status().pid;

    machine.install(&join_code("new.example.test"));

    wait_until("the supervisor starts again with the new domain", || {
        fs::read_to_string(&rendered).is_ok_and(|text| text.contains("serverAddr = \"new.example.test\""))
    });
    assert_ne!(machine.status().pid, supervisor);
}

/// Runs `session` (which must run `uninstall`, on an installed machine) until the removal has started, ends the
/// session with `end`, which is given the session and what it printed, and returns once the removal is over.
fn uninstall_survives(mut session: Command, end: impl FnOnce(&mut Child, &str)) {
    let mut session = session.stdout(Stdio::piped()).spawn().unwrap();
    let mut output = BufReader::new(session.stdout.take().unwrap());
    let mut printed = String::new();
    while !printed.lines().last().is_some_and(|line| line.starts_with("Removing.")) {
        assert_ne!(
            output.read_line(&mut printed).unwrap(),
            0,
            "uninstall ended before starting the removal"
        );
    }
    // The removal may cut the session before anything after "Removing." is read.
    let log = install::removal_log(&Paths::system().unwrap());
    assert!(
        printed.contains(&format!("Its log will be {log}.")),
        "{log} was not printed as the log before the removal started: {printed}"
    );
    end(&mut session, &printed);
    session.wait().unwrap();

    wait_until_removed();
    assert!(
        !account_names().contains(service::ACCOUNT),
        "the removal died with the session"
    );
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn uninstall_survives_session_end() {
    // A session of its own, as ssh's, which is killed once the removal has started: the tunnel it ran over goes with
    // the service.
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    let mut session = Command::new(BIN);
    session.arg("uninstall").process_group(0);
    uninstall_survives(session, |session, _| {
        let group = Pid::from_raw(session.id().try_into().unwrap()).unwrap();
        kill_process_group(group, Signal::KILL).unwrap();
    });
}

/// A file the test puts under `/etc`, removed when it drops. `restart` names a service to restart after each change.
#[cfg(target_os = "linux")]
struct EtcFile {
    path: &'static str,
    restart: Option<&'static str>,
}

#[cfg(target_os = "linux")]
impl EtcFile {
    fn write(path: &'static str, mode: u32, content: &str, restart: Option<&'static str>) -> EtcFile {
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir_all(Path::new(path).parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        let file = EtcFile { path, restart };
        file.restart();
        file
    }

    fn restart(&self) {
        if let Some(service) = self.restart {
            output_of("systemctl", &["restart", service]);
        }
    }

    /// `KillUserProcesses=yes`: logind kills what a session leaves in its scope when it ends. Not for root, whom logind
    /// leaves alone however `KillExcludeUsers=` is set.
    fn kill_user_processes() -> EtcFile {
        Self::write(
            "/etc/systemd/logind.conf.d/zz-reverse-tunnel-test.conf",
            0o644,
            "[Login]
KillUserProcesses=yes
",
            Some("systemd-logind"),
        )
    }

    /// `PROBE` may run anything as root without a password.
    fn probe_sudoers() -> EtcFile {
        Self::write(
            "/etc/sudoers.d/zz-reverse-tunnel-test",
            0o440,
            &format!(
                "{PROBE} ALL=(root) NOPASSWD: ALL
"
            ),
            None,
        )
    }
}

#[cfg(target_os = "linux")]
impl Drop for EtcFile {
    fn drop(&mut self) {
        let removed = fs::remove_file(self.path);
        if !thread::panicking() {
            removed.unwrap();
        }
        self.restart();
    }
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(target_os = "linux")]
fn uninstall_survives_logind_session_end() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    let _kill = EtcFile::kill_user_processes();
    account::ensure(PROBE).unwrap();
    let _sudoers = EtcFile::probe_sudoers();
    // A real logind session of an ordinary user, who runs `uninstall` as root with sudo, as an administrator logged in
    // over ssh does.
    let mut session = Command::new("su");
    session
        .args(["-s", "/bin/sh", "-l", PROBE, "-c"])
        .arg(format!("echo session=$XDG_SESSION_ID; exec sudo -n '{BIN}' uninstall"));
    uninstall_survives(session, |session, printed| {
        let id = printed
            .lines()
            .find_map(|line| line.strip_prefix("session="))
            .expect("su -l opens a logind session");
        // The login's command ends, so `su` ends the session as sshd does, and logind kills what is left in the scope
        // because of the drop-in. (A `su` killed outright leaves the scope alone.)
        output_of("pkill", &["-KILL", "-P", &session.id().to_string()]);
        session.wait().unwrap();
        wait_until("logind has ended the session", || {
            !Command::new("loginctl")
                .args(["show-session", id])
                .output()
                .unwrap()
                .status
                .success()
        });
    });
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn uninstall_leaves_nothing() {
    let machine = Machine::begin();
    let before = snapshot(&machine);
    machine.install(&join_code("tunnel.example.test"));
    machine.wait_for_frpc();
    // Not Linux (it opens no file): what the service account, which owns logs/, can plant for root to follow.
    #[cfg(not(target_os = "linux"))]
    let victim = env::temp_dir().join("rt-uninstall-log-victim");
    #[cfg(not(target_os = "linux"))]
    std::os::unix::fs::symlink(&victim, machine.paths.log_dir.join("uninstall.log")).unwrap();

    let mut uninstall = Command::new(BIN);
    uninstall.arg("uninstall");
    machine.run_ok(uninstall);

    #[cfg(not(target_os = "linux"))]
    assert!(!victim.exists(), "uninstall wrote through a link in logs/");
    let after = snapshot(&machine);
    assert_eq!(
        after.difference(&before).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "left behind"
    );
    assert_eq!(
        before.difference(&after).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "removed besides ours"
    );
    assert!(machine.frpc().is_empty(), "frpc outlived the service");
}

/// Makes `path` impossible to remove, even by root, until it drops.
struct Unremovable<'a>(&'a Path);

impl Unremovable<'_> {
    fn set(&self, on: bool) {
        let (program, flag) = match (cfg!(target_os = "macos"), on) {
            (true, true) => ("chflags", "uchg"),
            (true, false) => ("chflags", "nouchg"),
            (false, true) => ("chattr", "+i"),
            (false, false) => ("chattr", "-i"),
        };
        output_of(program, &[flag, self.0.to_str().unwrap()]);
    }
}

impl Drop for Unremovable<'_> {
    fn drop(&mut self) {
        self.set(false);
    }
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn a_failed_removal_logs_where_uninstall_says() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    // The removal starts, then cannot remove this file, and its failure names it: the name is this run's, so no line
    // of an earlier removal can stand in for it.
    let stuck = machine.paths.config_dir.join(format!("stuck-{}", std::process::id()));
    fs::write(&stuck, "").unwrap();
    let stuck = Unremovable(&stuck);
    stuck.set(true);

    // The unit's earlier runs are in the journal too: read from here on.
    #[cfg(target_os = "linux")]
    let cursor = {
        output_of("journalctl", &["--sync"]);
        output_of("journalctl", &["-n", "1", "-o", "cat", "--show-cursor"])
            .lines()
            .find_map(|line| line.strip_prefix("-- cursor: ").map(str::to_string))
            .expect("journalctl prints a cursor")
    };
    let failed = Command::new(BIN).arg("uninstall").output().unwrap();

    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(!failed.status.success(), "the removal should fail: {stderr}");
    let log = install::removal_log(&machine.paths);
    assert!(stderr.contains(&log), "{log} was not named as the log: {stderr}");
    #[cfg(target_os = "linux")]
    assert!(
        stderr.contains("It said:"),
        "what systemd-run said is not in the failure: {stderr}"
    );
    #[cfg(target_os = "linux")]
    let logged = {
        output_of("journalctl", &["--sync"]);
        let after = format!("--after-cursor={cursor}");
        output_of("journalctl", &["-t", "reverse-tunnel-uninstall", "--no-pager", &after])
    };
    #[cfg(not(target_os = "linux"))]
    let logged = fs::read_to_string(install::removal_log_file(&machine.paths)).unwrap();
    let removing = format!("removing {}", stuck.0.display());
    assert!(logged.contains(&removing), "the log has no `{removing}`: {logged}");
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn when_a_rejoin_fails_the_rerun_restarts_the_service() {
    let machine = Machine::begin();
    machine.install(&join_code("old.example.test"));
    let rendered = machine.paths.log_dir.join("frpc.toml");
    wait_until("the supervisor renders its first start", || rendered.exists());

    // A file copied over the link makes the rejoin fail after it wrote the new bridge files.
    let link = machine.paths.link.as_ref().unwrap();
    fs::remove_file(link).unwrap();
    fs::write(link, "").unwrap();
    let rejoin = join_code("new.example.test");
    let failed = machine.install_command(&rejoin).output().unwrap();
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        !failed.status.success() && stderr.contains(&link.display().to_string()),
        "the rejoin should fail on the file at {}: {stderr}",
        link.display()
    );
    let token = fs::read_to_string(machine.secrets().join("bridge.token")).unwrap();
    assert_eq!(
        token, "token-for-new.example.test\n",
        "the rejoin failed before it wrote the bridge files"
    );
    fs::remove_file(link).unwrap();

    machine.install(&rejoin);

    wait_until("the supervisor starts again with the new domain", || {
        fs::read_to_string(&rendered).is_ok_and(|text| text.contains("serverAddr = \"new.example.test\""))
    });
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn install_is_refused_while_an_uninstall_is_unfinished() {
    let machine = Machine::begin();
    machine.install(&join_code("old.example.test"));
    let supervisor = machine.status().pid;
    // What an uninstall leaves while its removal runs, or after it failed.
    fs::write(machine.paths.config_dir.join("uninstalling"), "").unwrap();

    let refused = machine
        .install_command(&join_code("new.example.test"))
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success() && stderr.contains("uninstall is in progress"),
        "{stderr}"
    );
    let config = fs::read_to_string(machine.paths.config_dir.join("config.yaml")).unwrap();
    assert!(
        config.contains("old.example.test"),
        "the refused install changed config.yaml"
    );
    assert_eq!(machine.status().pid, supervisor);
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn status_needs_no_elevation() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    machine.wait_for_frpc();
    account::ensure(PROBE).unwrap();
    // The installed binary: the test binary's own directory is in a home directory.
    let installed = service::exe(&machine.paths);
    let as_probe = |command: &str| {
        let out = Command::new("sudo")
            .args(["-n", "-u", PROBE, "--"])
            .arg(&installed)
            .arg(command)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{command} as {PROBE}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };

    let status = as_probe("status");
    assert!(status.contains("service: running"), "{status}");
    assert!(status.contains("bridge: tunnel.example.test"), "{status}");
    assert!(status.contains("certificate: SHA-256 "), "{status}");
}
