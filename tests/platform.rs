//! `install` and `uninstall` against the real service manager, account database and file system, as root (on Windows,
//! as an Administrator). They run only on CI's `platform` job (`RT_PLATFORM_TESTS=1`), one at a time, on a machine
//! nothing else lives on; never on a developer's machine.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use goetia::manager::{Installed, ServiceManager, State, Status};
use goetia::spec::Id;
#[cfg(unix)]
use reverse_tunnel::account::{self, Account};
use reverse_tunnel::command;
use reverse_tunnel::install;
use reverse_tunnel::paths::Paths;
#[cfg(windows)]
use reverse_tunnel::schtasks::{self, TaskState};
use reverse_tunnel::service;
use reverse_tunnel::upgrade;
#[cfg(unix)]
use rustix::process::{Pid, Signal, kill_process_group};

#[cfg(windows)]
#[path = "platform/windows.rs"]
mod windows;
#[cfg(windows)]
use windows::assert_installed_as_specified;

const BIN: &str = env!("CARGO_BIN_EXE_reverse-tunnel");
const CERT: &str = include_str!("../server/testdata/bridge.pem");

/// An account the test creates, to stand in for any local user.
#[cfg(unix)]
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

/// The removal's systemd units that are loaded in `state` (`--all` for any: a unit that is queued reads as inactive,
/// with no process).
#[cfg(target_os = "linux")]
fn removal_units(state: &str) -> String {
    output_of(
        "systemctl",
        &[
            "list-units",
            state,
            "--plain",
            "--no-legend",
            "reverse-tunnel-uninstall-*",
        ],
    )
}

/// Waits for the removal, which `uninstall` starts, to end. On Windows it is a scheduled task, over when it has an exit
/// code or is gone; call it once the removal has started.
#[cfg(windows)]
fn wait_until_removed() {
    wait_until_task_is_over(schtasks::REMOVAL);
}

/// Waits until the scheduled task `name` has ended or is gone, and returns which. A task that cannot be read fails
/// the test.
#[cfg(windows)]
fn wait_until_task_is_over(name: &str) -> TaskState {
    let mut state = TaskState::Running;
    wait_until(&format!("task {name} is over"), || {
        state = schtasks::state(name).unwrap();
        state != TaskState::Running
    });
    state
}

/// Waits for `uninstall --finish`, which `uninstall` starts, to end. On Linux it is a systemd unit named for the run,
/// and is over when it is gone. Call it once the removal has started, as the unit exists from then on.
#[cfg(unix)]
fn wait_until_removed() {
    wait_until("the removal ends", || {
        #[cfg(target_os = "linux")]
        let unit_present = !removal_units("--all").trim().is_empty();
        #[cfg(not(target_os = "linux"))]
        let unit_present = false;
        !unit_present
            && !processes()
                .iter()
                .any(|process| process.args.ends_with("uninstall --finish"))
    });
}

fn output_of(program: &str, args: &[&str]) -> String {
    command::run(&[&[program], args].concat()).unwrap()
}

/// A running process: `owner` is its uid, or on Windows its user's name; `args` is its command line, or on Windows its
/// image name.
struct Process {
    pid: u32,
    owner: String,
    args: String,
}

#[cfg(unix)]
fn processes() -> Vec<Process> {
    output_of("ps", &["-axo", "pid=,uid=,args="])
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (pid, owner) = (fields.next()?.parse().ok()?, fields.next()?.to_string());
            Some(Process {
                pid,
                owner,
                args: fields.collect::<Vec<_>>().join(" "),
            })
        })
        .collect()
}

#[cfg(windows)]
fn processes() -> Vec<Process> {
    // "Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name",...
    output_of("tasklist", &["/V", "/FO", "CSV", "/NH"])
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.trim().trim_matches('"').split("\",\"").collect();
            Some(Process {
                pid: fields.get(1)?.parse().ok()?,
                owner: fields.get(6)?.to_string(),
                args: fields[0].to_string(),
            })
        })
        .collect()
}

/// What `Process::owner` is for the service's account.
#[cfg(unix)]
fn service_owner() -> String {
    account::lookup(service::ACCOUNT)
        .expect("install creates the service account")
        .uid
        .to_string()
}

#[cfg(windows)]
fn service_owner() -> String {
    service::ACCOUNT.to_string()
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
        assert!(
            cosca::elevation::is_elevated(),
            "these tests need root, or an Administrator"
        );
        let paths = Paths::system().unwrap();
        let id = service::id();
        let manager = service::manager(&paths).unwrap();
        for dir in [&paths.bin_dir, &paths.config_dir, &paths.log_dir] {
            assert!(!dir.exists(), "{} is left from before", dir.display());
        }
        #[cfg(unix)]
        {
            let accounts = account_names();
            for account in [service::ACCOUNT, PROBE] {
                assert!(!accounts.contains(account), "{account} is left from before");
            }
        }
        assert!(
            matches!(manager.status(&id), Err(err) if matches!(err.cause(), goetia::Error::NotInstalled { .. })),
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

    /// Has root write `config.yaml` anew, readable by root only: a check run as root would pass it, and the service
    /// account cannot read it. Returns its path.
    #[cfg(unix)]
    fn break_config(&self) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let config = self.paths.config_dir.join("config.yaml");
        let text = fs::read(&config).unwrap();
        fs::remove_file(&config).unwrap();
        fs::write(&config, text).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        config
    }

    /// Has `config.yaml` hold what no binary accepts. Returns its path. (On Windows the check runs as the caller, so a
    /// file only the service account cannot read is not caught.)
    #[cfg(windows)]
    fn break_config(&self) -> PathBuf {
        let config = self.paths.config_dir.join("config.yaml");
        fs::write(&config, "host: [unclosed").unwrap();
        config
    }

    /// The service's account, which exists once installed.
    #[cfg(unix)]
    fn service_account(&self) -> Account {
        account::lookup(service::ACCOUNT).expect("install creates the service account")
    }

    fn frpc(&self) -> Vec<Process> {
        let prefix = if cfg!(windows) {
            "frpc-".to_string()
        } else {
            format!("{}/frpc-", self.paths.bin_dir.display())
        };
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
    #[cfg(unix)]
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
        // What a removal that was cut short, or that failed, leaves.
        #[cfg(windows)]
        {
            let _ = schtasks::delete(schtasks::REMOVAL);
            let _ = fs::remove_dir_all(self.paths.bin_dir.with_file_name("reverse-tunnel-uninstall"));
        }
        #[cfg(target_os = "linux")]
        {
            // `su -l` starts the account's user manager, user@<uid>.service, which outlives the session, and `userdel`
            // refuses while anything of the account runs. (`pgrep` fails for an account that is gone.)
            let _ = Command::new("loginctl").args(["terminate-user", PROBE]).status();
            wait_until("the probe account has no processes", || {
                !Command::new("pgrep").args(["-u", PROBE]).status().unwrap().success()
            });
        }
        #[cfg(unix)]
        {
            let removed = account::remove(PROBE);
            if !thread::panicking() {
                removed.unwrap();
            }
        }
    }
}

/// The name of every user and group, from the account database; the lookup cache that `account::lookup` goes through
/// can still answer for an account that has just been removed.
#[cfg(unix)]
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
    // On Windows, `logs/` is in `config_dir`, which an install creates.
    for parent in parents
        .into_iter()
        .flatten()
        .chain(paths.link.as_deref().and_then(Path::parent))
        .filter(|parent| parent.exists())
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
    } else if cfg!(windows) {
        &[]
    } else {
        &["/etc/systemd/system"]
    };
    for dir in units {
        tree(Path::new(dir), &mut seen);
    }
    #[cfg(unix)]
    seen.extend(account_names().into_iter().map(|name| format!("account {name}")));
    #[cfg(windows)]
    if schtasks::state(schtasks::REMOVAL).unwrap() != TaskState::Gone {
        seen.insert(format!("task {}", schtasks::REMOVAL));
    }
    for installed in machine.manager.list().unwrap() {
        seen.insert(match installed {
            Installed::Ours { spec, .. } => format!("service {}", spec.id),
            other => format!("service {other:?}"),
        });
    }
    seen
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o7777
}

/// The modes, the owners and the access the installation is specified to give.
#[cfg(unix)]
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
    assert!(machine.wait_for_frpc().iter().all(|frpc| frpc.owner == service_owner()));
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
#[cfg(unix)]
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

/// Runs `session` (which must run `uninstall`, on an installed machine), after `begin` has been given it, until the
/// removal has started, ends the session with `end`, which is given the session and what it printed, and returns once
/// the removal is over.
fn uninstall_survives(mut session: Command, begin: impl FnOnce(&mut Child), end: impl FnOnce(&mut Child, &str)) {
    let mut session = session.stdout(Stdio::piped()).spawn().unwrap();
    begin(&mut session);
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
    #[cfg(unix)]
    let removed = !account_names().contains(service::ACCOUNT);
    #[cfg(windows)]
    let removed = matches!(
        service::manager(&Paths::system().unwrap()).unwrap().status(&service::id()),
        Err(err) if matches!(err.cause(), goetia::Error::NotInstalled { .. })
    );
    assert!(removed, "the removal died with the session");
    // The removal deletes its own task and directory, last.
    #[cfg(windows)]
    {
        let paths = Paths::system().unwrap();
        assert_eq!(
            schtasks::state(schtasks::REMOVAL).unwrap(),
            TaskState::Gone,
            "the removal's task is left"
        );
        assert!(
            !install::removal_log_file(&paths).parent().unwrap().exists(),
            "the removal's directory is left"
        );
    }
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn uninstall_survives_session_end() {
    // A session of its own, as ssh's, which is killed once the removal has started: the tunnel it ran over goes with
    // the service.
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    #[cfg(unix)]
    {
        let mut session = Command::new(BIN);
        session.arg("uninstall").process_group(0);
        uninstall_survives(
            session,
            |_| {},
            |session, _| {
                let group = Pid::from_raw(session.id().try_into().unwrap()).unwrap();
                kill_process_group(group, Signal::KILL).unwrap();
            },
        );
    }
    // The session is a job object that kills all it holds when it closes, as OpenSSH's does. `cmd` waits for a line
    // before it runs `uninstall`, so that everything `uninstall` starts is in the job too.
    #[cfg(windows)]
    {
        use std::io::Write;
        use std::os::windows::process::CommandExt;

        let job = windows::Job::kill_on_close();
        let mut session = Command::new("cmd");
        session
            .raw_arg(format!(r#"/s /c "set /p go=& "{BIN}" uninstall""#))
            .stdin(Stdio::piped());
        uninstall_survives(
            session,
            |session| {
                job.add(session);
                session.stdin.take().unwrap().write_all(b"\r\n").unwrap();
            },
            |_, _| job.close(),
        );
    }
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
            self.restart();
        } else if let Some(service) = self.restart {
            // A second panic would abort, and the cleanups after this one would not run.
            let _ = Command::new("systemctl").args(["restart", service]).status();
        }
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
    uninstall_survives(
        session,
        |_| {},
        |session, printed| {
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
        },
    );
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn uninstall_leaves_nothing() {
    let machine = Machine::begin();
    let before = snapshot(&machine);
    machine.install(&join_code("tunnel.example.test"));
    machine.wait_for_frpc();
    // macOS (Linux opens no file, and Windows keeps the log outside logs/): what the service account, which owns
    // logs/, can plant for root to follow.
    #[cfg(target_os = "macos")]
    let victim = env::temp_dir().join("rt-uninstall-log-victim");
    #[cfg(target_os = "macos")]
    std::os::unix::fs::symlink(&victim, machine.paths.log_dir.join("uninstall.log")).unwrap();

    let mut uninstall = Command::new(BIN);
    uninstall.arg("uninstall");
    machine.run_ok(uninstall);

    #[cfg(target_os = "macos")]
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

/// Makes `path` impossible to remove, even by root, until it drops. On Windows a handle without delete sharing does.
#[cfg(unix)]
struct Unremovable<'a>(&'a Path);

#[cfg(windows)]
struct Unremovable<'a>(&'a Path, #[allow(dead_code)] fs::File);

impl<'a> Unremovable<'a> {
    #[cfg(unix)]
    fn new(path: &'a Path) -> Self {
        let held = Unremovable(path);
        held.set(true);
        held
    }

    #[cfg(windows)]
    fn new(path: &'a Path) -> Self {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 1;
        let handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .unwrap();
        Unremovable(path, handle)
    }

    #[cfg(unix)]
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

#[cfg(unix)]
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
    let stuck = Unremovable::new(&stuck);

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
    // The unit's own result, not systemd-run's text.
    #[cfg(target_os = "linux")]
    assert!(
        stderr.contains("Result=exit-code"),
        "the unit's result is not in the failure: {stderr}"
    );
    // A failed unit stays loaded until it is reset.
    #[cfg(target_os = "linux")]
    assert_eq!(removal_units("--failed").trim(), "", "the failed unit was not reset");
    #[cfg(target_os = "linux")]
    let logged = {
        output_of("journalctl", &["--sync"]);
        let after = format!("--after-cursor={cursor}");
        output_of(
            "journalctl",
            &["-u", "reverse-tunnel-uninstall-*", "--no-pager", &after],
        )
    };
    #[cfg(not(target_os = "linux"))]
    let logged = fs::read_to_string(install::removal_log_file(&machine.paths)).unwrap();
    let removing = format!("removing {}", stuck.0.display());
    assert!(logged.contains(&removing), "the log has no `{removing}`: {logged}");
    // A removal that failed leaves its task, its directory and its log for the rerun.
    #[cfg(windows)]
    {
        assert_eq!(
            schtasks::state(schtasks::REMOVAL).unwrap(),
            TaskState::Ended(1),
            "the failed removal's task is gone, or did not end with `uninstall --finish`'s failure"
        );
        assert!(
            install::removal_log_file(&machine.paths).exists(),
            "the failed removal's log is gone"
        );
    }
}

/// A newer build in a directory of its own: this one with a byte appended, which differs and which the loader ignores.
/// Returns the directory, which removes it when it drops, and the build.
fn newer_build() -> (tempfile::TempDir, PathBuf) {
    let newer = [fs::read(BIN).unwrap(), b"newer".to_vec()].concat();
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch
        .path()
        .join(format!("reverse-tunnel{}", env::consts::EXE_SUFFIX));
    fs::write(&path, newer).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    (scratch, path)
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn when_a_rejoin_fails_the_rerun_restarts_the_service() {
    let machine = Machine::begin();
    machine.install(&join_code("old.example.test"));
    let rendered = machine.paths.log_dir.join("frpc.toml");
    wait_until("the supervisor renders its first start", || rendered.exists());

    // A file copied over the link makes the rejoin fail after it wrote the new bridge files. On Windows there is no
    // link, and a different binary cannot replace the one the running service holds (`upgrade` will).
    let rejoin = join_code("new.example.test");
    #[cfg(unix)]
    let (blocker, mut failing) = {
        let link = machine.paths.link.as_ref().unwrap();
        fs::remove_file(link).unwrap();
        fs::write(link, "").unwrap();
        (link.clone(), machine.install_command(&rejoin))
    };
    #[cfg(windows)]
    let (blocker, mut failing, _scratch) = {
        let (scratch, newer) = newer_build();
        let mut install = Command::new(&newer);
        install.args(["install", "--host", "testhost", "--join", &rejoin]);
        (service::exe(&machine.paths), install, scratch)
    };
    let failed = failing.output().unwrap();
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        !failed.status.success() && stderr.contains(&blocker.display().to_string()),
        "the rejoin should fail on the file at {}: {stderr}",
        blocker.display()
    );
    let token = fs::read_to_string(machine.secrets().join("bridge.token")).unwrap();
    assert_eq!(
        token, "token-for-new.example.test\n",
        "the rejoin failed before it wrote the bridge files"
    );
    #[cfg(unix)]
    fs::remove_file(&blocker).unwrap();

    machine.install(&rejoin);

    wait_until("the supervisor starts again with the new domain", || {
        fs::read_to_string(&rendered).is_ok_and(|text| text.contains("serverAddr = \"new.example.test\""))
    });
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(unix)]
fn upgrade_from_local_build() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    let supervisor = machine.status().pid.expect("a running service has a pid");
    let (_scratch, path) = newer_build();
    let newer = fs::read(&path).unwrap();

    let mut upgrade = Command::new(BIN);
    upgrade.arg("upgrade").arg("--from").arg(&path);
    machine.run_ok(upgrade);

    wait_until("the manager runs a new supervisor", || {
        let status = machine.status();
        status.state == State::Running && status.pid.is_some_and(|pid| pid != supervisor)
    });
    assert_eq!(fs::read(service::exe(&machine.paths)).unwrap(), newer);
}

/// Whether `stderr` says that the check refused `config`: unreadable by the service account, or, on Windows where the
/// check runs as the caller, invalid.
fn rejects_config(stderr: &str, config: &Path) -> bool {
    if cfg!(windows) {
        stderr.contains("the service would not start with this configuration")
    } else {
        stderr.contains("reading")
            && stderr.contains(&config.display().to_string())
            && stderr.contains("Permission denied")
    }
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn restart_checks_the_configuration_as_the_service_account() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    let first = machine.status().pid.expect("a running service has a pid");
    let old_frpc: Vec<u32> = machine.wait_for_frpc().iter().map(|p| p.pid).collect();

    // The check runs with nothing inherited (on Windows as the caller): it must pass, and the service run again.
    let mut restart = Command::new(BIN);
    restart.arg("restart");
    machine.run_ok(restart);
    wait_until("the manager runs a new supervisor", || {
        let status = machine.status();
        status.state == State::Running && status.pid.is_some_and(|pid| pid != first)
    });
    // The new supervisor has read config.yaml once its frpc runs; a file broken before that stops the service itself.
    wait_until("the new supervisor's frpc runs", || {
        machine.frpc().iter().any(|process| !old_frpc.contains(&process.pid))
    });
    let running = machine.status().pid;

    let config = machine.break_config();
    let failed = Command::new(BIN).arg("restart").output().unwrap();

    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        !failed.status.success() && rejects_config(&stderr, &config),
        "restart should fail on {}: {stderr}",
        config.display()
    );
    let status = machine.status();
    assert_eq!((status.state, status.pid), (State::Running, running));
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn install_checks_the_configuration_as_the_service_account() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    // The supervisor has read config.yaml once frpc runs; a file broken before that stops the service itself.
    machine.wait_for_frpc();
    let status = machine.status();
    let outgoing = fs::read(service::exe(&machine.paths)).unwrap();
    let config = machine.break_config();
    // A newer build in a directory the service account cannot enter.
    let (_scratch, path) = newer_build();

    let failed = Command::new(&path).arg("install").output().unwrap();

    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        !failed.status.success() && rejects_config(&stderr, &config),
        "install should fail on {}: {stderr}",
        config.display()
    );
    assert_eq!(fs::read(service::exe(&machine.paths)).unwrap(), outgoing);
    let staged = fs::read_dir(&machine.paths.bin_dir)
        .unwrap()
        .filter_map(|entry| entry.unwrap().file_name().into_string().ok())
        .filter(|name| name.starts_with(upgrade::STAGED))
        .collect::<Vec<_>>();
    assert_eq!(staged, Vec::<String>::new(), "the staged copy is removed");
    let after = machine.status();
    assert_eq!((after.state, after.pid), (State::Running, status.pid));
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn restart_without_the_service_installed_says_so() {
    let _machine = Machine::begin();

    let failed = Command::new(BIN).arg("restart").output().unwrap();

    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        !failed.status.success() && stderr.contains("the service is not installed"),
        "{stderr}"
    );
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
#[cfg(windows)]
fn status_needs_no_elevation() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));
    machine.wait_for_frpc();
    let probe = windows::Probe::create();

    // The installed binary: the test binary's own directory is in the runner's profile.
    let out = probe.run(&service::exe(&machine.paths), "status");

    let (status, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "status as an unelevated user: {status}{stderr}");
    assert!(status.contains("service: running"), "{status}");
    assert!(status.contains("bridge: tunnel.example.test"), "{status}");
    assert!(status.contains("certificate: SHA-256 "), "{status}");
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(windows)]
fn install_refuses_a_data_directory_someone_else_made() {
    let machine = Machine::begin();
    let probe = windows::Probe::create();
    // What a standard user can do in %ProgramData% before the install: make the directory, owned by itself.
    let squat = probe.run(
        Path::new("cmd.exe"),
        &format!("/c mkdir {}", machine.paths.config_dir.display()),
    );
    assert!(squat.status.success(), "the probe user could not make the directory");

    let refused = machine
        .install_command(&join_code("tunnel.example.test"))
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success()
            && stderr.contains(&machine.paths.config_dir.display().to_string())
            && stderr.contains("delete it"),
        "install should refuse {}: {stderr}",
        machine.paths.config_dir.display()
    );
    assert_eq!(
        fs::read_dir(&machine.paths.config_dir).unwrap().count(),
        0,
        "install wrote into it"
    );
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(windows)]
fn install_removes_a_stray_ace_from_secrets() {
    let machine = Machine::begin();
    let code = join_code("tunnel.example.test");
    machine.install(&code);
    // An Administrator's hand edit: Everyone may read the tokens.
    let secrets = machine.paths.secrets_dir.display().to_string();
    output_of("icacls", &[&secrets, "/grant", "*S-1-1-0:(OI)(CI)R"]);
    let token = machine.secrets().join("host.token");
    assert_ne!(
        windows::effective_rights(&token, "S-1-1-0"),
        0,
        "the stray ACE did not reach the token"
    );

    machine.install(&code);

    assert_eq!(
        windows::effective_rights(&machine.paths.secrets_dir, "S-1-1-0"),
        0,
        "Everyone has secrets/"
    );
    assert_eq!(windows::effective_rights(&token, "S-1-1-0"), 0, "Everyone has a token");
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(unix)]
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

/// Deletes the scheduled task `name` when it drops, so that a test that panics leaves none registered.
#[cfg(windows)]
struct TaskGuard(&'static str);

#[cfg(windows)]
impl Drop for TaskGuard {
    fn drop(&mut self) {
        let _ = schtasks::delete(self.0);
    }
}

/// Runs the removal's own script as a SYSTEM task, on a machine with nothing installed (its `uninstall --finish` has run
/// if the config directory the test made is gone), with a file made impossible to delete while it runs: `hold` is given
/// the removal's directory and the copy in it, and names that file. Returns how the task ended, with the directory,
/// the copy and the log.
#[cfg(windows)]
fn run_removal_script_holding(
    hold: impl FnOnce(&Path, &Path) -> PathBuf,
) -> (TaskState, tempfile::TempDir, PathBuf, PathBuf) {
    let machine = Machine::begin();
    fs::create_dir(&machine.paths.config_dir).unwrap();
    let dir = tempfile::tempdir_in(r"C:\Users\Public").unwrap();
    let (copy, log) = (dir.path().join("reverse-tunnel.exe"), dir.path().join("uninstall.log"));
    fs::copy(BIN, &copy).unwrap();
    let held = hold(dir.path(), &copy);
    // Held open without delete sharing, as an antivirus scan may.
    let held = Unremovable::new(&held);
    let task = "reverse-tunnel-removal-script-test";
    let _guard = TaskGuard(task);
    assert_eq!(
        schtasks::state(task).unwrap(),
        TaskState::Gone,
        "a task that was never registered is gone"
    );
    schtasks::start(task, &schtasks::removal_script(&copy, &log, dir.path(), task)).unwrap();

    let state = wait_until_task_is_over(task);

    assert!(!machine.paths.config_dir.exists(), "the removal did not run");
    drop(held);
    (state, dir, copy, log)
}

/// `del` reports a copy that something holds only in its message. The removal's script must still fail, with its own
/// code, and keep its task, its directory and its log.
#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(windows)]
fn a_held_copy_fails_the_removal_and_keeps_its_log() {
    let (state, _dir, copy, log) = run_removal_script_holding(|_, copy| copy.to_path_buf());

    assert_eq!(
        state,
        TaskState::Ended(2),
        "the task should end with the copy's failure"
    );
    assert!(log.exists(), "the log is gone");
    assert!(copy.exists(), "the held copy is gone");
}

/// `rmdir /s /q` reports a file that something holds only in its message. The removal's script must still fail, with
/// its own code, and keep its directory.
#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(windows)]
fn a_held_file_in_the_removal_directory_fails_the_removal() {
    let (state, dir, copy, _log) = run_removal_script_holding(|dir, _| {
        let other = dir.join("other.txt");
        fs::write(&other, "").unwrap();
        other
    });

    assert_eq!(
        state,
        TaskState::Ended(3),
        "the task should end with the directory's failure"
    );
    assert!(dir.path().join("other.txt").exists(), "the held file is gone");
    assert!(!copy.exists(), "the copy should have been deleted before the directory");
}

/// The removal's task is registered as SYSTEM: `whoami` in it says so.
#[test]
#[ignore = "registers a real scheduled task; CI's platform job runs it"]
#[cfg(windows)]
fn the_removal_task_runs_as_system() {
    let dir = tempfile::tempdir_in(r"C:\Users\Public").unwrap();
    let answer = dir.path().join("whoami.txt");
    let task = "reverse-tunnel-system-test";
    let _guard = TaskGuard(task);
    schtasks::start(task, &format!(r#"whoami /user > "{}""#, answer.display())).unwrap();

    assert_eq!(wait_until_task_is_over(task), TaskState::Ended(0));

    let said = fs::read_to_string(&answer).unwrap();
    assert!(said.contains("S-1-5-18"), "the task ran as: {said}");
}

/// The removal deletes the installed binary's directory, which Windows cannot do while that binary runs: `uninstall`
/// run by it refuses before it changes anything, and prints a PowerShell line that runs it from a copy. Run under
/// Windows PowerShell 5.1, that line removes the host and its own copy.
#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
#[cfg(windows)]
fn uninstall_run_by_the_installed_binary_refuses_and_its_copy_out_line_removes_the_host() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));

    let refused = Command::new(service::exe(&machine.paths))
        .arg("uninstall")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "uninstall should refuse: {stderr}");
    let line = stderr
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("Set-Location -LiteralPath"))
        .unwrap_or_else(|| panic!("the copy-out line is not in: {stderr}"));
    assert_eq!(machine.status().state, State::Running, "the service was touched");
    assert!(
        !machine.paths.config_dir.join("uninstalling").exists(),
        "the uninstalling marker was written"
    );

    // From inside the directory the removal deletes: the line moves out of it first.
    // The line leaves the copy's exit code in $LASTEXITCODE and does not end the session; the process exit shows it.
    let ran = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("{line}; exit $LASTEXITCODE"),
        ])
        .current_dir(&machine.paths.bin_dir)
        .output()
        .unwrap();

    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(ran.status.success(), "the line exited with {}: {said}", ran.status);
    assert!(said.contains("Removed."), "the copy did not remove the host: {said}");
    let removed = matches!(
        machine.manager.status(&machine.id),
        Err(err) if matches!(err.cause(), goetia::Error::NotInstalled { .. })
    );
    assert!(removed, "the service is left: {said}");
    for left in [
        &machine.paths.bin_dir,
        &machine.paths.config_dir,
        &machine.paths.log_dir,
        &machine.paths.bin_dir.with_file_name("reverse-tunnel-uninstall"),
        &machine.paths.bin_dir.with_file_name("reverse-tunnel-copy"),
    ] {
        assert!(!left.exists(), "{} is left: {said}", left.display());
    }
    assert_eq!(schtasks::state(schtasks::REMOVAL).unwrap(), TaskState::Gone);
}
