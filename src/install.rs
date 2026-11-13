//! `reverse-tunnel install` and `uninstall`.
//!
//! Everything a run writes is final when it is written: modes and owners are set before any content (see `files`),
//! and each step can be repeated, so an install that failed midway is finished by running it again.

use std::env;
use std::fs;
use std::io::{self, BufRead, ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use goetia::decide::Outcome;
use goetia::manager::{Budget, ServiceManager};
use goetia::spec::{DaemonSpec, Id};
use named_lock::{NamedLock, NamedLockGuard};

use crate::account::{self, Account};
#[cfg(target_os = "linux")]
use crate::command;
use crate::config::{Config, valid_label};
use crate::files::{Perm, Replace, WriteOutcome, make_dir, make_missing_dirs, open_file, remove_entry, write_atomic};
use crate::join::{self, JoinInfo};
use crate::ops::{mark_pending, pending_file};
use crate::paths::Paths;
#[cfg(windows)]
use crate::schtasks::{self, TaskState};
#[cfg(windows)]
use crate::system_path;
use crate::{download, ops, service, upgrade};

/// Directories, and files everyone may read.
const PUBLIC_DIR: Perm = Perm::new(0o755);
const PUBLIC_FILE: Perm = Perm::new(0o644);

/// `secrets/` is setgid on Linux, so that a file put there by hand joins the service account's group.
const SECRETS_DIR_MODE: u32 = if cfg!(target_os = "linux") { 0o2750 } else { 0o750 };

pub struct InstallOpts {
    /// Names a new `config.yaml`; without it, the machine's name. When `config.yaml` exists it must be that name.
    pub host: Option<String>,
    /// Without it the join code is asked for, unless a previous install left the bridge files.
    pub join: Option<String>,
    pub paths: Paths,
}

/// Holds the exclusive lock until the guard is dropped. `install` and `uninstall --finish` take it for their whole
/// run; a second one waits.
pub fn lock(paths: &Paths) -> Result<NamedLockGuard> {
    // On Windows `paths.lock` names a global mutex, which only administrators and SYSTEM can open.
    #[cfg(windows)]
    let lock = NamedLock::create(paths.lock.to_str().context("the lock's name is not Unicode")?);
    // Made here, owner-only: named-lock would use the umask's mode, and whoever can open the file can hold the lock.
    #[cfg(unix)]
    let lock = {
        open_file(&paths.lock, Perm::new(0o600), false)?;
        NamedLock::with_path(&paths.lock)
    };
    lock.and_then(|lock| lock.lock())
        .with_context(|| format!("locking {}", paths.lock.display()))
}

/// Exists from the moment `uninstall` commits to removing everything until the removal is done. While it does,
/// `install` and `restart` refuse, so that they cannot install or restart what the removal is about to delete.
fn uninstalling_file(paths: &Paths) -> PathBuf {
    paths.config_dir.join("uninstalling")
}

/// Fails while the uninstalling marker exists, saying how to finish the removal.
pub(crate) fn refuse_while_uninstalling(paths: &Paths) -> Result<()> {
    ensure!(
        !uninstalling_file(paths).try_exists()?,
        "an uninstall is in progress or failed: see {}, and {} to finish it",
        removal_log(paths),
        rerun_uninstall(paths)
    );
    Ok(())
}

/// Installs, or updates, the service so that it runs this binary, and starts it, or restarts it if anything `install`
/// writes changed. Prints the line that registers the host on the bridge.
pub fn install(opts: InstallOpts) -> Result<()> {
    let paths = &opts.paths;
    let _lock = lock(paths)?;
    refuse_while_uninstalling(paths)?;
    make_dir(&paths.config_dir, PUBLIC_DIR)?;
    let changed = pending_file(paths).try_exists()?;
    let host = configured_host(paths, opts.host.as_deref())?;
    let join = match opts.join.as_deref() {
        Some(code) => Some(join::decode(code)?),
        None if needs_join(paths)? => Some(prompt_join(&mut io::stdin().lock(), &mut io::stderr())?),
        None => None,
    };

    let account = account::ensure(service::ACCOUNT)?;
    let new = env::current_exe().context("finding this binary")?;
    apply(
        &*service::manager(paths)?,
        &account,
        paths,
        &new,
        host.as_deref(),
        join.as_ref(),
        changed,
    )
}

/// What `install` does once it holds the lock and knows its inputs. `new` is the binary being installed. `changed`: an
/// earlier run changed something that has not been restarted yet.
fn apply(
    manager: &dyn ServiceManager,
    account: &Account,
    paths: &Paths,
    new: &Path,
    host: Option<&str>,
    join: Option<&JoinInfo>,
    mut changed: bool,
) -> Result<()> {
    let spec = service::spec(paths)?;
    let binary = fs::read(new).with_context(|| format!("reading {}", new.display()))?;
    // The check reads the settings (as the account, except on Windows), so they are written first (a new join code's
    // or host's settings stay even if the binary is rejected); the binary and the unit come after it, so a rejected
    // binary leaves both as they were. The binary is in place before the unit: on Windows it is the unit's host, which
    // the manager looks at.
    changed |= write_settings(paths, account, host, join)?;
    verify_tools(paths, &binary, Some(*account))?;
    changed |= place_binaries(paths, &binary)?;
    #[cfg(windows)]
    system_path::add(&paths.bin_dir)?;
    changed |= register(manager, &spec, paths)?;

    println!(
        "Register this host on the bridge by running:\n    {}",
        registration(paths)?
    );
    manager.enable(&spec.id)?;
    pick_up(manager, &spec.id, paths, changed)
}

/// Runs the removal: see `hand_off`. On Windows it first checks that its working directory is not one the removal
/// deletes: the shell that ran `uninstall` would stay in it whatever this process does.
pub fn uninstall(paths: &Paths) -> Result<()> {
    let exe = env::current_exe()?;
    #[cfg(windows)]
    refuse_deleted_working_directory(paths, &env::current_dir()?)?;
    hand_off(paths, &exe)
}

/// Prepares the removal, hands it to `uninstall --finish` (see `spawn_finish`) and waits for it. `exe` is this binary.
/// Once the marker is written, an error says how to finish the removal.
fn hand_off(paths: &Paths, exe: &Path) -> Result<()> {
    let lock = lock(paths)?;
    match revoke_line(paths) {
        Ok(line) => println!("Revoke this host on the bridge by running:\n    {line}"),
        Err(err) => eprintln!("{err:#}\nRevoke this host on the bridge by running: uv run ctl revoke <host>"),
    }
    make_dir(&paths.config_dir, PUBLIC_DIR)?;
    open_file(&uninstalling_file(paths), Perm::new(0o600), false)?;
    // Before the removal starts: over the tunnel it can cut the session before anything is printed after.
    println!("Its log will be {}.", removal_log(paths));
    // `--finish` takes the lock itself; an `install` in between is refused by the marker.
    drop(lock);
    let removal = spawn_finish(exe, paths).with_context(|| not_started(&rerun_uninstall(paths)))?;
    ops::println_best_effort("Removing. If this session ends, the removal continues.");
    let outcome = removal.wait().with_context(|| {
        format!(
            "could not tell how the removal ended; its log is {}, and to finish it {}",
            removal_log(paths),
            rerun_uninstall(paths)
        )
    })?;
    // The removal's own broadcast, from the task, does not reach the desktop, and `--finish` may already have taken the
    // entry off the `Path` before the removal failed.
    #[cfg(windows)]
    system_path::broadcast();
    match outcome {
        WaitOutcome::Ended => {}
        // Nothing to finish but the task: the log is gone with the rest.
        #[cfg(windows)]
        WaitOutcome::LeftBehind(why) => bail!(why),
        WaitOutcome::Failed(why) => {
            return Err(anyhow!(why)).with_context(|| {
                format!(
                    "the removal failed: see {}, and {} to finish it",
                    removal_log(paths),
                    rerun_uninstall(paths)
                )
            });
        }
    }
    ops::println_best_effort("Removed.");
    Ok(())
}

/// The context of the error of a removal that could not be started: `rerun` says how to run `uninstall` again.
fn not_started(rerun: &str) -> String {
    format!("starting the removal failed; to finish it {rerun}")
}

/// Where the removal's output is, for the operator: the journal, where the lines of earlier failed runs of the unit
/// come first, and which a host without persistent storage loses at a reboot.
#[cfg(target_os = "linux")]
pub fn removal_log(_paths: &Paths) -> String {
    "the journal (`journalctl -u 'reverse-tunnel-uninstall-*' -e`; this run's lines are the last, and without a \
     persistent journal they are gone after a reboot)"
        .to_string()
}

/// Where the removal's output is, for the operator: a file, which the removal deletes when it succeeds.
#[cfg(not(target_os = "linux"))]
pub fn removal_log(paths: &Paths) -> String {
    removal_log_file(paths).display().to_string()
}

/// The file the removal's output goes to: in `logs/`.
#[cfg(target_os = "macos")]
pub fn removal_log_file(paths: &Paths) -> PathBuf {
    paths.log_dir.join("uninstall.log")
}

/// The file the removal's output goes to: in `removal_dir`.
#[cfg(windows)]
pub fn removal_log_file(paths: &Paths) -> PathBuf {
    removal_dir(paths).join("uninstall.log")
}

/// Windows: where the removal runs from, a directory next to the bin dir (so only administrators can have made it): a
/// running binary cannot be deleted, so the removal runs a copy, which its task deletes with the directory.
#[cfg(windows)]
fn removal_dir(paths: &Paths) -> PathBuf {
    paths.bin_dir.with_file_name("reverse-tunnel-uninstall")
}

/// How a waited-for removal ended, when it could be waited for.
enum WaitOutcome {
    Ended,
    Failed(String),
    /// Windows: everything is removed, but the removal's task is still registered.
    #[cfg(windows)]
    LeftBehind(String),
}

/// A started `uninstall --finish`: the transient unit it runs in.
#[cfg(target_os = "linux")]
struct Removal {
    unit: String,
}

/// The value of `key` in `systemctl show` output.
#[cfg(target_os = "linux")]
fn property<'a>(shown: &'a str, key: &str) -> Result<&'a str> {
    shown
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .ok_or_else(|| anyhow!("`systemctl show` printed no {key}"))
}

#[cfg(target_os = "linux")]
impl Removal {
    /// Waits for the removal's unit to end, then resets the failed units of removals, this one's among them.
    ///
    /// A removal that the operator stops (`systemctl stop` on its unit: systemd counts an exit by SIGTERM as clean) or
    /// resets (`systemctl reset-failed`) while this waits reads as ended. This is a stated limit: running `uninstall`
    /// again finishes the removal.
    fn wait(self) -> Result<WaitOutcome> {
        let show = [
            "systemctl",
            "show",
            "-p",
            "LoadState,ActiveState,Result,ExecMainStatus",
            self.unit.as_str(),
        ];
        let outcome = loop {
            let shown = command::run(&show)?;
            let (load, active) = (property(&shown, "LoadState")?, property(&shown, "ActiveState")?);
            if active == "failed" {
                break WaitOutcome::Failed(format!(
                    "the removal's unit failed: Result={}, ExecMainStatus={}",
                    property(&shown, "Result")?,
                    property(&shown, "ExecMainStatus")?
                ));
            }
            if load == "not-found" || active == "inactive" {
                break WaitOutcome::Ended;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        };
        if let Err(err) = command::run(&["systemctl", "reset-failed", "reverse-tunnel-uninstall-*"]) {
            eprintln!("could not clear the removal's failed unit: {err:#}");
        }
        Ok(outcome)
    }
}

/// A started removal: its directory, which it deletes when it has succeeded, and the folder that holds the leftover
/// files it leaves when it fails (see `leftover_dir`).
#[cfg(windows)]
struct Removal {
    dir: PathBuf,
    leftovers: PathBuf,
}

/// What the removal's task says of how it went, or none while it runs. A task that is gone deleted itself, which it
/// does last, after the directory; one that ended has the code of the step that failed (see `removal_script`).
#[cfg(windows)]
fn removal_outcome(state: TaskState, dir: &Path, dir_present: bool, leftovers: &Path) -> Option<WaitOutcome> {
    let leftovers = schtasks::leftover_pattern(leftovers);
    let dir = dir.display();
    let failed = |why: String| Some(WaitOutcome::Failed(why));
    match state {
        TaskState::Running => None,
        TaskState::Disabled => failed("the removal's task is disabled, so the removal will not run".to_string()),
        TaskState::Gone if dir_present => failed("the removal's task was deleted before it finished".to_string()),
        TaskState::Gone => Some(WaitOutcome::Ended),
        TaskState::Ended(1) => failed("the removal's `uninstall --finish` failed".to_string()),
        TaskState::Ended(2) => failed("the removal's copy of this binary could not be deleted".to_string()),
        TaskState::Ended(3) => failed(format!(
            "the removal could not delete {dir}; its log may be gone with it: delete {dir} by hand"
        )),
        TaskState::Ended(4) => Some(WaitOutcome::LeftBehind(format!(
            "the removal is done, but its task is still registered: delete it with `schtasks /Delete /TN {}`, and the \
             files {} by hand",
            schtasks::REMOVAL,
            leftovers.display()
        ))),
        TaskState::Ended(code) => failed(format!("the removal's task ended with {code:#x}")),
    }
}

#[cfg(windows)]
impl Removal {
    /// Waits, with no cap, until the task has ended or is gone (it deletes itself when the removal has succeeded). The
    /// task is read first: it deletes itself after the directory, so a task that is gone says the directory has been
    /// deleted by the time it is looked at. A task that cannot be read is an error.
    fn wait(self) -> Result<WaitOutcome> {
        loop {
            let state = schtasks::state(schtasks::REMOVAL)?;
            if let Some(outcome) = removal_outcome(state, &self.dir, self.dir.try_exists()?, &self.leftovers) {
                return Ok(outcome);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

#[cfg(target_os = "macos")]
struct Removal(std::process::Child);

#[cfg(target_os = "macos")]
impl Removal {
    /// Waits for the removal to end.
    fn wait(mut self) -> Result<WaitOutcome> {
        let status = self.0.wait().context("waiting for the removal")?;
        Ok(if status.success() {
            WaitOutcome::Ended
        } else {
            WaitOutcome::Failed(format!("the removal ended with {status}"))
        })
    }
}

/// Starts `uninstall --finish` so that it outlives the session that runs `uninstall`, with its output where
/// `removal_log` says. Returns once the removal has started; `Removal::wait` ends with it. After an error it may
/// not have started; `uninstall` can be run again either way.
///
/// Linux: a transient systemd unit, since logind kills what a session leaves behind under `KillUserProcesses=yes`, and
/// a process of its own does not escape that. With `Type=exec`, `systemd-run` returns once the binary was exec'd, so
/// its exit status says the removal has started, and from then on it outlives the session; this needs systemd 240, and
/// goetia's floor is 242. A service's output goes to the journal. Each run's unit has a name of its own, under a
/// prefix that selects them all.
#[cfg(target_os = "linux")]
fn spawn_finish(exe: &Path, _paths: &Paths) -> Result<Removal> {
    use std::ffi::OsStr;

    let unit = format!("reverse-tunnel-uninstall-{}", hex_of_random_bytes::<16>()?);
    let unit_arg = format!("--unit={unit}");
    command::run(&[
        OsStr::new("systemd-run"),
        OsStr::new(&unit_arg),
        OsStr::new("-p"),
        OsStr::new("Type=exec"),
        OsStr::new("--"),
        exe.as_os_str(),
        OsStr::new("uninstall"),
        OsStr::new("--finish"),
    ])
    .context("the removal may not have started")?;
    Ok(Removal { unit })
}

/// Windows: a one-time scheduled task run by SYSTEM, since an OpenSSH session ends everything it started, and no job
/// object can be left. It runs a copy of `exe` from `removal_dir`, with the output in the log, and if the removal
/// succeeded deletes the directory and then itself, and then the files that a removal renamed (see
/// `schtasks::removal_script`). What a failed removal left in `removal_dir`, `exe` included, goes by the rule of
/// `remove_or_rename`.
#[cfg(windows)]
fn spawn_finish(exe: &Path, paths: &Paths) -> Result<Removal> {
    let dir = removal_dir(paths);
    let leftovers = leftover_dir(paths)?;
    // Open before the directory is cleared: `exe` may be the copy that a failed removal left in it.
    let mut source = fs::File::open(exe).with_context(|| format!("opening {}", exe.display()))?;
    remove_or_rename(&dir, leftovers)?;
    make_dir(&dir, Perm::new(0o700))?;
    // Named as the installed binary is, whatever `exe` is called.
    let copy = dir.join(
        service::exe(paths)
            .file_name()
            .context("the installed binary has no file name")?,
    );
    let mut target = fs::File::create_new(&copy).with_context(|| format!("creating {}", copy.display()))?;
    io::copy(&mut source, &mut target).with_context(|| format!("copying {}", copy.display()))?;
    drop(target);
    let script = schtasks::removal_script(&copy, &removal_log_file(paths), &dir, schtasks::REMOVAL, leftovers);
    schtasks::start(schtasks::REMOVAL, &script)?;
    Ok(Removal {
        dir,
        leftovers: leftovers.to_path_buf(),
    })
}

/// macOS: a process group of its own, which the session's hangup does not reach, and which launchd leaves alone. It
/// inherits the log, which is opened here, by root without following a link: `logs/` belongs to the service account,
/// which may have left anything in it.
#[cfg(target_os = "macos")]
fn spawn_finish(exe: &Path, paths: &Paths) -> Result<Removal> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    make_dir(&paths.log_dir, PUBLIC_DIR)?;
    let path = removal_log_file(paths);
    remove_entry(&path)?;
    let log = open_file(&path, PUBLIC_FILE, true)?;
    let child = Command::new(exe)
        .args(["uninstall", "--finish"])
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()?;
    Ok(Removal(child))
}

/// How to run `uninstall` again: by the installed binary, or by any `reverse-tunnel` binary once that is gone.
#[cfg(not(windows))]
pub fn rerun_uninstall(paths: &Paths) -> String {
    let exe = service::exe(paths);
    if exe.exists() {
        format!("run `sudo {} uninstall`", exe.display())
    } else {
        "run `uninstall` with `sudo` and any `reverse-tunnel` binary (the installed one is gone)".to_string()
    }
}

/// How to run `uninstall` again: by the command on the `PATH`, or, once the installed binary is gone, by any
/// `reverse-tunnel` binary, which includes the leftover images of the installed binary in the folder that holds the bin
/// dir (see `remove_or_rename`): a removal that ran from the installed binary may have left that as the only copy.
#[cfg(windows)]
pub fn rerun_uninstall(paths: &Paths) -> String {
    if service::exe(paths).exists() {
        return concat!(
            "run `reverse-tunnel uninstall` in an elevated prompt ",
            "(with any `reverse-tunnel` binary, if that is not found)"
        )
        .to_string();
    }
    // Advice: a folder that cannot be listed has no image to name.
    let binary = service::exe(paths);
    let binary = binary.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    let images: Vec<_> = leftover_images(paths)
        .unwrap_or_default()
        .into_iter()
        .filter(|image| {
            let name = image.file_name().and_then(|name| name.to_str());
            name.is_some_and(|name| schtasks::is_leftover_of(name, binary))
        })
        .collect();
    if images.is_empty() {
        return "run `uninstall` in an elevated prompt with any `reverse-tunnel` binary (the installed one is gone)"
            .to_string();
    }
    let by_image: Vec<_> = images
        .iter()
        .map(|image| format!("`\"{}\" uninstall`", image.display()))
        .collect();
    format!(
        "run {} in an elevated prompt (the installed binary is gone)",
        by_image.join(" or ")
    )
}

/// Windows: every directory the removal deletes: the bin dir, the config dir, the logs, and the removal's own.
#[cfg(windows)]
fn deleted_dirs(paths: &Paths) -> [PathBuf; 4] {
    [
        paths.bin_dir.clone(),
        paths.config_dir.clone(),
        paths.log_dir.clone(),
        removal_dir(paths),
    ]
}

/// Windows: the directory the removal deletes (see `deleted_dirs`) that `dir` is, or is inside of. The OS resolves the
/// directories, so short names and case do not matter.
#[cfg(windows)]
fn deleted_dir_holding(paths: &Paths, dir: &Path) -> Result<Option<PathBuf>> {
    let canonical = |path: &Path| {
        fs::canonicalize(path).with_context(|| {
            format!(
                "resolving {} to check whether it is a directory the removal deletes",
                path.display()
            )
        })
    };
    let dir = canonical(dir)?;
    for deleted in deleted_dirs(paths) {
        if deleted.try_exists()? && dir.starts_with(canonical(&deleted)?) {
            return Ok(Some(deleted));
        }
    }
    Ok(None)
}

/// Windows: fails if the working directory `cwd` is in a directory the removal deletes, since Windows cannot delete a
/// directory that a process is in, and the shell that ran `uninstall` stays there whatever this process does.
#[cfg(windows)]
fn refuse_deleted_working_directory(paths: &Paths, cwd: &Path) -> Result<()> {
    if let Some(held) = deleted_dir_holding(paths, cwd)? {
        bail!(
            concat!(
                "`uninstall` has its current directory in {}, which the removal deletes, and Windows cannot delete a ",
                "directory that a process is in. Change to another directory first."
            ),
            held.display()
        );
    }
    Ok(())
}

/// Windows: the folder that holds the bin dir, `%ProgramFiles%`, where a removal puts what it cannot delete (see
/// `remove_or_rename`). Only administrators can write to it, and the removal leaves it alone.
#[cfg(windows)]
fn leftover_dir(paths: &Paths) -> Result<&Path> {
    paths.bin_dir.parent().context("the bin dir has no parent")
}

/// Windows: the leftover files that earlier removals renamed (see `remove_or_rename`), which a removal's task deletes
/// once they can be.
#[cfg(windows)]
pub fn leftover_images(paths: &Paths) -> Result<Vec<PathBuf>> {
    let dir = leftover_dir(paths)?;
    let mut images = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        if schtasks::is_leftover(&entry.file_name().to_string_lossy()) {
            images.push(entry.path());
        }
    }
    images.sort();
    Ok(images)
}

/// Removes the service, then the files and the account. Repeating it finishes what a failed run left.
pub fn finish_uninstall(paths: &Paths) -> Result<()> {
    let _lock = lock(paths)?;
    if let Err(err) = service::manager(paths)?.uninstall(&service::id())
        && !matches!(err.cause(), goetia::Error::NotInstalled { .. })
    {
        return Err(err).context("removing the service");
    }
    // The order leaves no gap where something is wrong, or where the reason is lost: the tokens go before the account,
    // so they never belong to a freed gid; the link goes before the binary, so it never dangles; the marker stays
    // until the rest of `config_dir` is gone, since `install` is refused while it exists; and `logs/` is last, so that
    // a failure above is still in the log.
    remove_entry(&paths.secrets_dir)?;
    account::remove(service::ACCOUNT)?;
    #[cfg(unix)]
    remove_link(paths)?;
    remove_files(paths).with_context(|| rerun_uninstall(paths))?;
    // Last: until then the rerun that a failure advises is run by name, and the `PATH` finds it.
    #[cfg(windows)]
    system_path::remove(&paths.bin_dir)?;
    Ok(())
}

/// Removes the link to the binary, unless it points elsewhere.
#[cfg(unix)]
fn remove_link(paths: &Paths) -> Result<()> {
    let Some(link) = &paths.link else { return Ok(()) };
    match fs::read_link(link) {
        Ok(target) if target == service::exe(paths) => {
            fs::remove_file(link).with_context(|| format!("removing {}", link.display()))
        }
        Ok(target) => {
            eprintln!("Leaving {}: it points to {}.", link.display(), target.display());
            Ok(())
        }
        Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::InvalidInput) => Ok(()),
        Err(err) => Err(err).with_context(|| format!("reading the link {}", link.display())),
    }
}

/// Windows: removes `path`, a file or a directory with what is in it (see `remove_entry`). Windows will not delete the
/// image of a process that runs, and one may: the waiting `uninstall`'s binary, or a binary of the service that is
/// still ending, since goetia returns once SCM says the service is stopped. So the process that deletes a directory
/// owns what in it cannot be deleted: a regular file directly in `path` that cannot be deleted is renamed, which
/// Windows allows for a running image, to a leftover file in `leftovers` that keeps its name (see
/// `schtasks::leftover_name`), and the removal's task deletes it once it has exited (see `schtasks::removal_script`).
/// The rename is logged. A file that can be neither deleted nor renamed fails the removal, naming both errors. A
/// directory, junction or link that cannot be deleted is never renamed, since the task's `del` could not delete it.
#[cfg(windows)]
fn remove_or_rename(path: &Path, leftovers: &Path) -> Result<()> {
    if !fs::symlink_metadata(path).is_ok_and(|entry| entry.is_dir()) {
        return delete_or_rename(path, leftovers);
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    for entry in entries {
        delete_or_rename(&entry?.path(), leftovers)?;
    }
    remove_entry(path)
}

/// Windows: deletes `path` (see `remove_entry`), or if it cannot be, renames it (see `remove_or_rename`).
#[cfg(windows)]
fn delete_or_rename(path: &Path, leftovers: &Path) -> Result<()> {
    let Err(refused) = remove_entry(path) else {
        return Ok(());
    };
    if !fs::symlink_metadata(path).is_ok_and(|entry| entry.is_file()) {
        return Err(refused.context("it is not a regular file, so it is not renamed"));
    }
    let original = path.file_name().context("the file has no name")?;
    let to = leftovers.join(schtasks::leftover_name(&hex_of_random_bytes::<16>()?, original));
    fs::rename(path, &to).map_err(|err| anyhow!("{refused:#}; moving it to {}: {err}", to.display()))?;
    println!(
        "{refused:#}: moved it to {}, where the removal's task deletes it",
        to.display()
    );
    Ok(())
}

/// Removes the bin dir, the config dir's contents, the marker, the config dir and, last, the logs. On Windows what
/// cannot be deleted is renamed (see `remove_or_rename`).
fn remove_files(paths: &Paths) -> Result<()> {
    #[cfg(windows)]
    let leftovers = leftover_dir(paths)?;
    #[cfg(windows)]
    let remove = |path: &Path| remove_or_rename(path, leftovers);
    #[cfg(not(windows))]
    let remove = |path: &Path| remove_entry(path);
    let bin_dir = remove(&paths.bin_dir);
    // On Windows a shell or program whose working directory is in the folder holds it.
    #[cfg(windows)]
    let bin_dir = bin_dir.with_context(|| {
        format!(
            "if a shell or program has its working directory in {}, it holds it",
            paths.bin_dir.display()
        )
    });
    bin_dir?;
    let marker = uninstalling_file(paths);
    match fs::read_dir(&paths.config_dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path != marker {
                    remove(&path)?;
                }
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("reading {}", paths.config_dir.display())),
    }
    remove_entry(&marker)?;
    remove_entry(&paths.config_dir)?;
    remove(&paths.log_dir)
}

/// The hex digits of `N` random bytes from the OS.
fn hex_of_random_bytes<const N: usize>() -> Result<String> {
    let mut random = [0u8; N];
    getrandom::fill(&mut random).context("reading random bytes from the OS")?;
    Ok(hex::encode(random))
}

fn config_file(paths: &Paths) -> PathBuf {
    paths.config_dir.join("config.yaml")
}

/// Whether a join code is needed: some file it provides is missing.
fn needs_join(paths: &Paths) -> Result<bool> {
    let files = [
        config_file(paths),
        paths.config_dir.join("bridge.pem"),
        paths.secrets_dir.join("bridge.token"),
    ];
    for file in files {
        if !file.try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The name for a new `config.yaml`, or none when one exists. Refuses an explicit name that differs from the existing
/// config's.
fn configured_host(paths: &Paths, explicit: Option<&str>) -> Result<Option<String>> {
    let config = config_file(paths);
    if !config.try_exists()? {
        return host_name(explicit).map(Some);
    }
    if let Some(asked) = explicit {
        let asked = host_name(Some(asked))?;
        let current = Config::load(&config)?.host;
        ensure!(
            asked == current,
            "--host {asked:?} differs from this host's name {current:?} in {}: `install` does not rename a host. \
             To rename it, uninstall it and install it again with --host {asked}",
            config.display()
        );
    }
    Ok(None)
}

/// The host name for a new `config.yaml`.
fn host_name(explicit: Option<&str>) -> Result<String> {
    match explicit {
        Some(host) => {
            ensure!(
                valid_label(host),
                "--host {host:?} is not a valid name: one DNS label of lowercase letters, digits and hyphens"
            );
            Ok(host.to_string())
        }
        None => normalize_host(&gethostname::gethostname().to_string_lossy()),
    }
}

/// A machine name as a host name: lowercased, and it must then be one valid DNS label.
fn normalize_host(machine: &str) -> Result<String> {
    let host = machine.to_lowercase();
    ensure!(
        valid_label(&host),
        "this machine's name {machine:?} is not a valid host name (one DNS label); pass --host"
    );
    Ok(host)
}

/// Reads lines until they form a join code, which may be wrapped over several. A blank line, or the end of the input,
/// gives up.
fn prompt_join(input: &mut impl BufRead, prompt: &mut impl Write) -> Result<JoinInfo> {
    writeln!(
        prompt,
        "Paste the join code (`uv run ctl join-code` on the bridge) and press Enter; a blank line gives up:"
    )?;
    let mut code = String::new();
    loop {
        let mut line = String::new();
        input.read_line(&mut line)?;
        code += &line;
        if line.trim().is_empty() {
            return join::decode(&code).context("no complete join code was entered");
        }
        if let Ok(info) = join::decode(&code) {
            return Ok(info);
        }
    }
}

/// Registers the service without starting it. Whether it was created or changed.
fn register(manager: &dyn ServiceManager, spec: &DaemonSpec, paths: &Paths) -> Result<bool> {
    if manager.preview_install(spec)? != Outcome::UpToDate {
        mark_pending(paths)?;
    }
    match manager.install(spec, false)? {
        Outcome::UpToDate => Ok(false),
        Outcome::Create | Outcome::Update { .. } | Outcome::Stale { .. } => Ok(true),
        refused => bail!("the service manager would not register {}: {refused:?}", spec.id),
    }
}

/// Creates the directories and writes `config.yaml`, `bridge.pem` and the two tokens, each with its final mode and
/// owner. A first run writes `config.yaml` and `secrets/host.token`, both create-new; with `join`, every run
/// rewrites the `bridge:` line, `bridge.pem` and `secrets/bridge.token`. Whether any file changed.
fn write_settings(paths: &Paths, account: &Account, host: Option<&str>, join: Option<&JoinInfo>) -> Result<bool> {
    let secret = Perm::new(0o640).group(*account);
    make_dir(&paths.secrets_dir, Perm::new(SECRETS_DIR_MODE).group(*account))?;
    make_dir(&paths.log_dir, Perm::new(0o755).owner(*account).group(*account))?;

    let config = config_file(paths);
    let created = !config.try_exists()? && create_config(paths, host, join)?;
    let mut changed = created;
    if let Some(join) = join {
        if !created {
            let text = fs::read_to_string(&config).with_context(|| format!("reading {}", config.display()))?;
            changed |= replace_if_changed(paths, &config, with_bridge(&text, &join.domain, &config)?, PUBLIC_FILE)?;
        }
        changed |= replace_if_changed(paths, &paths.config_dir.join("bridge.pem"), &join.cert_pem, PUBLIC_FILE)?;
        let token = format!("{}\n", join.token);
        changed |= replace_if_changed(paths, &paths.secrets_dir.join("bridge.token"), token, secret)?;
    }

    let host_token = paths.secrets_dir.join("host.token");
    if !host_token.try_exists()? {
        let token = format!("{}\n", hex_of_random_bytes::<32>()?);
        mark_pending(paths)?;
        changed |= write_atomic(&host_token, token.as_bytes(), secret, Replace::Never)? == WriteOutcome::Written;
    }
    // A file left by an earlier account keeps that account's group, whatever its content.
    for name in ["host.token", "bridge.token"] {
        open_file(&paths.secrets_dir.join(name), secret, false)?;
    }
    Ok(changed)
}

/// Writes a first `config.yaml` publishing ssh. False if it appeared meanwhile.
fn create_config(paths: &Paths, host: Option<&str>, join: Option<&JoinInfo>) -> Result<bool> {
    let host = host.context("there is no config.yaml and no host name for one")?;
    let join = join.context("there is no config.yaml, so a join code is needed")?;
    let text = format!(
        "host: {host}\nbridge: {}\ndefault: ssh\nservices:\n  ssh:\n    port: 22\n    type: tcp\n",
        join.domain
    );
    mark_pending(paths)?;
    let written = write_atomic(&config_file(paths), text.as_bytes(), PUBLIC_FILE, Replace::Never)?;
    Ok(written == WriteOutcome::Written)
}

/// Replaces `dest` with `data` unless it holds it already. Whether it wrote.
fn replace_if_changed(paths: &Paths, dest: &Path, data: impl AsRef<[u8]>, perm: Perm) -> Result<bool> {
    let data = data.as_ref();
    if fs::read(dest).is_ok_and(|current| current == data) {
        return Ok(false);
    }
    mark_pending(paths)?;
    write_atomic(dest, data, perm, Replace::Always)?;
    Ok(true)
}

/// `text` with its one top-level `bridge:` line naming `domain`; the rest is untouched.
fn with_bridge(text: &str, domain: &str, file: &Path) -> Result<String> {
    // Windows editors write a BOM, which the config accepts.
    let (bom, body) = match text.strip_prefix('\u{feff}') {
        Some(body) => ("\u{feff}", body),
        None => ("", text),
    };
    let lines: Vec<&str> = body.split_inclusive('\n').collect();
    let mut found = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("bridge:"))
        .map(|(at, _)| at);
    let (Some(at), None) = (found.next(), found.next()) else {
        bail!("{} must have exactly one `bridge:` line at column 0", file.display());
    };
    let line = lines[at];
    let eol = &line[line.trim_end_matches(['\r', '\n']).len()..];
    let rewritten = format!(
        "{bom}{}bridge: {domain}{eol}{}",
        lines[..at].concat(),
        lines[at + 1..].concat()
    );
    // A value that does not sit on the `bridge:` line (a folded or next-line scalar) would be read differently.
    let config = Config::parse(&rewritten).with_context(|| format!("{} after setting its bridge", file.display()))?;
    ensure!(
        config.bridge == domain,
        "{} would name the bridge {:?} instead of {domain}: put the value of `bridge:` on its line",
        file.display(),
        config.bridge
    );
    Ok(rewritten)
}

/// Makes the bin dir, fetches the pinned frpc if it is missing, and has a copy of `binary`, the new one, staged in the
/// bin dir where `run_as` can run it, check the settings as `run_as` (see `ops::check`). The copy is removed whatever
/// the outcome. A fetch needs no restart: a new frpc version only arrives with a new binary, which `place_binaries`
/// marks.
fn verify_tools(paths: &Paths, binary: &[u8], run_as: Option<Account>) -> Result<()> {
    let parents = [paths.bin_dir.parent(), paths.link.as_deref().and_then(Path::parent)];
    for parent in parents.into_iter().flatten() {
        make_missing_dirs(parent, PUBLIC_DIR)?;
    }
    make_dir(&paths.bin_dir, PUBLIC_DIR)?;

    // The pinned frpc first: the binary that names it is not put in place unless it can be fetched.
    if !download::tools(paths).frpc.try_exists()? {
        download::fetch(download::host_pin()?, &paths.bin_dir)?;
    }
    let staged = upgrade::stage(paths, binary)?;
    let checked = ops::check(paths, &staged, run_as, "the new binary's `run --check`");
    upgrade::discard(&staged);
    checked
}

/// Puts the binary `binary` and the symlink in place. Whether the binary changed.
fn place_binaries(paths: &Paths, binary: &[u8]) -> Result<bool> {
    let exe = service::exe(paths);
    let changed = replace_if_changed(paths, &exe, binary, Perm::EXECUTABLE)?;
    clean_bin_dir(paths)?;
    #[cfg(windows)]
    for entry in fs::read_dir(&paths.bin_dir).with_context(|| format!("reading {}", paths.bin_dir.display()))? {
        crate::files::own_by_administrators(&entry?.path())?;
    }
    #[cfg(unix)]
    if let Some(link) = &paths.link {
        point_link(link, &exe)?;
    }
    Ok(changed)
}

/// Removes from the bin dir the frpc versions that are not the current one, temp files a crashed write left, and the
/// copies `upgrade` ran from (`upgrade-*`), this process's own among them.
fn clean_bin_dir(paths: &Paths) -> Result<()> {
    let current = download::tools(paths).frpc;
    for entry in fs::read_dir(&paths.bin_dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        let stale = path != current && (name.starts_with("frpc-") || name.starts_with(".tmp"));
        if name.starts_with(upgrade::STAGED) {
            // A copy that something still holds (just run, or being scanned) is not worth failing `install` over.
            upgrade::discard(&path);
        } else if stale {
            remove_entry(&path)?;
        }
    }
    Ok(())
}

/// Makes `link` a symlink to `target`.
#[cfg(unix)]
fn point_link(link: &Path, target: &Path) -> Result<()> {
    match fs::read_link(link) {
        Ok(current) if current == target => return Ok(()),
        Ok(_) => fs::remove_file(link).with_context(|| format!("replacing {}", link.display()))?,
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) if err.kind() == ErrorKind::InvalidInput => {
            return Err(err).with_context(|| format!("{} exists and is not a symlink", link.display()));
        }
        Err(err) => return Err(err).with_context(|| format!("reading the link {}", link.display())),
    }
    symlink(target, link).with_context(|| format!("linking {}", link.display()))
}

fn registration(paths: &Paths) -> Result<String> {
    let host = Config::load(&config_file(paths))?.host;
    let token_file = paths.secrets_dir.join("host.token");
    let token = fs::read_to_string(&token_file).with_context(|| format!("reading {}", token_file.display()))?;
    Ok(registration_line(&host, token.trim()))
}

fn registration_line(host: &str, token: &str) -> String {
    format!("uv run ctl add {host} {}", join::token_hash(token))
}

fn revoke_line(paths: &Paths) -> Result<String> {
    Ok(format!("uv run ctl revoke {}", Config::load(&config_file(paths))?.host))
}

/// Has the service run what is now in place: after a change `ops::restart_pending` restarts it, and without one it is
/// started, which leaves a running service alone.
fn pick_up(manager: &dyn ServiceManager, id: &Id, paths: &Paths, changed: bool) -> Result<()> {
    if !changed {
        manager.start(id, Budget::Unbounded)?;
        return Ok(());
    }
    let Err(failed) = ops::restart_pending(manager, id, paths) else {
        return Ok(());
    };
    let err = failed.error;
    let restart_failed = "the new files are in place, but the service was not restarted";
    // The remedy leads because the restart's own error is appended after the last words.
    match failed.marker {
        Ok(()) => Err(err.context(format!("run `reverse-tunnel install` again to retry; {restart_failed}"))),
        Err(write) => Err(err.context(format!(
            "the marker for retrying the restart could not be written ({write:#}): the next `install` will not \
            notice, so run `reverse-tunnel restart`; {restart_failed}"
        ))),
    }
}

#[cfg(all(test, unix))]
#[path = "install_tests.rs"]
mod tests;

#[cfg(all(test, windows))]
#[path = "install_windows_tests.rs"]
mod windows_tests;
