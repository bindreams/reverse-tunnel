//! `install` and `uninstall` against the real service manager, account database and file system, as root. They run
//! only on CI's `platform` job (`RT_PLATFORM_TESTS=1`), one at a time, on a machine nothing else lives on; never on a
//! developer's machine.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use goetia::manager::{self, Installed, ServiceManager, State, Status};
use goetia::spec::Id;
use reverse_tunnel::account::{self, Account};
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

/// Waits for the detached `uninstall --finish`, which `uninstall` starts, to end.
fn wait_until_removed() {
    wait_until("the removal ends", || {
        !processes()
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
        for account in [service::ACCOUNT, PROBE] {
            assert!(account::lookup(account).is_none(), "{account} is left from before");
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
        let _ = account::remove(PROBE);
    }
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
    let accounts = if cfg!(target_os = "macos") {
        output_of("dscl", &[".", "-list", "/Users"]) + &output_of("dscl", &[".", "-list", "/Groups"])
    } else {
        output_of("getent", &["passwd"]) + &output_of("getent", &["group"])
    };
    seen.extend(
        accounts
            .lines()
            .map(|line| format!("account {}", line.split([':', ' ']).next().unwrap())),
    );
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

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn uninstall_survives_session_end() {
    let machine = Machine::begin();
    machine.install(&join_code("tunnel.example.test"));

    // A session of its own, as ssh's, which is killed once the removal has started: the tunnel it ran over goes with
    // the service.
    let mut session = Command::new(BIN);
    session.arg("uninstall").stdout(Stdio::piped()).process_group(0);
    let mut session = session.spawn().unwrap();
    let mut output = BufReader::new(session.stdout.take().unwrap());
    let mut line = String::new();
    while !line.starts_with("Removing.") {
        line.clear();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "uninstall ended before starting the removal"
        );
    }
    let group = Pid::from_raw(session.id().try_into().unwrap()).unwrap();
    kill_process_group(group, Signal::KILL).unwrap();
    session.wait().unwrap();

    wait_until_removed();
    assert!(
        account::lookup(service::ACCOUNT).is_none(),
        "the removal died with the session"
    );
}

#[test]
#[ignore = "installs a real service; CI's platform job runs it"]
fn uninstall_leaves_nothing() {
    let machine = Machine::begin();
    let before = snapshot(&machine);
    machine.install(&join_code("tunnel.example.test"));
    machine.wait_for_frpc();
    // What the service account, which owns logs/ and runs frpc, can plant for root to follow.
    let victim = env::temp_dir().join("rt-uninstall-log-victim");
    symlink(&victim, machine.paths.log_dir.join("uninstall.log")).unwrap();

    let mut uninstall = Command::new(BIN);
    uninstall.arg("uninstall");
    machine.run_ok(uninstall);

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
