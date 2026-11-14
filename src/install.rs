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
#[cfg(windows)]
use crate::files::is_access_denied;
use crate::files::{
    Perm, Replace, WriteOutcome, hex_of_random_bytes, make_dir, make_missing_dirs, open_file, remove_entry,
    remove_file, restore_binary, same_name, write_atomic,
};
use crate::join::{self, JoinInfo};
#[cfg(windows)]
use crate::leftovers;
use crate::ops::{mark_pending, pending_file};
use crate::paths::Paths;
#[cfg(windows)]
use crate::processes;
#[cfg(windows)]
use crate::schtasks::{self, TaskState};
#[cfg(windows)]
use crate::system_path;
use crate::{download, ops, output, service, upgrade};

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
/// run; a second run waits or, on Windows while the removal's task holds it, may fail to open it.
pub fn lock(paths: &Paths) -> Result<NamedLockGuard> {
    // On Windows `paths.lock` names a global mutex, which has its creator's default access.
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
    let new = Binary::read(paths, &env::current_exe().context("finding this binary")?)?;
    apply(
        &*service::registering_manager(&new.image)?,
        &account,
        paths,
        &new,
        host.as_deref(),
        join.as_ref(),
        changed,
    )
}

/// The binary that `install` puts in place, and the file the service runs it from (see `service::image`).
struct Binary {
    bytes: Vec<u8>,
    image: PathBuf,
}

impl Binary {
    /// The binary at `from`.
    fn read(paths: &Paths, from: &Path) -> Result<Binary> {
        let bytes = fs::read(from).with_context(|| format!("reading {}", from.display()))?;
        Ok(Binary {
            image: service::image(paths, &bytes),
            bytes,
        })
    }
}

/// What `install` does once it holds the lock and knows its inputs. `new` is the binary being installed, which
/// `manager` registers as the service's host. `changed`: an earlier run changed something that has not been restarted
/// yet.
fn apply(
    manager: &dyn ServiceManager,
    account: &Account,
    paths: &Paths,
    new: &Binary,
    host: Option<&str>,
    join: Option<&JoinInfo>,
    mut changed: bool,
) -> Result<()> {
    let spec = service::spec(&new.image)?;
    // The check reads the settings (as the account, except on Windows), so they are written first; the binary and the
    // unit come after it, so a rejected binary leaves both as they were. The image goes in before the unit: on
    // Windows it is the unit's host path, which the manager reads.
    changed |= write_settings(paths, account, host, join)?;
    verify_tools(paths, &new.bytes, Some(*account))?;
    changed |= place_binaries(paths, new)?;
    changed |= register(manager, &spec, paths)?;
    // Only now: until the service is registered on the new image, it is registered on the old one, which may be the
    // binary on the `PATH`.
    #[cfg(windows)]
    {
        place_path_copy(paths, new)?;
        system_path::add(&paths.bin_dir)?;
        say_kept(sweep_old_images(paths, &new.image));
    }

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
    output::println_best_effort("Removing. If this session ends, the removal continues.");
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
    output::println_best_effort("Removed.");
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
/// files it leaves when it fails (see `leftovers`).
#[cfg(windows)]
struct Removal {
    dir: PathBuf,
    leftover_dir: PathBuf,
}

/// What the removal's task says of how it went, or none while it runs. A task that is gone deleted itself, which it
/// does after the directory; one that ended has the code of the step that failed (see `removal_script`).
#[cfg(windows)]
fn removal_outcome(state: TaskState, dir_present: bool, leftover_dir: &Path) -> Option<WaitOutcome> {
    let pattern = leftovers::pattern(leftover_dir);
    let failed = |why: String| Some(WaitOutcome::Failed(why));
    match state {
        TaskState::Running => None,
        TaskState::Disabled => failed("the removal's task is disabled, so the removal will not run".to_string()),
        TaskState::Gone if dir_present => failed("the removal's task was deleted before it finished".to_string()),
        TaskState::Gone => Some(WaitOutcome::Ended),
        TaskState::Ended(1) => failed("the removal's `uninstall --finish` failed".to_string()),
        TaskState::Ended(4) => Some(WaitOutcome::LeftBehind(format!(
            "the removal is done, but its task is still registered: delete it with `schtasks /Delete /TN {}`. The files \
             that remain ({}) can be deleted by hand once this `uninstall` has exited",
            schtasks::REMOVAL,
            pattern.display()
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
            if let Some(outcome) = removal_outcome(state, self.dir.try_exists()?, &self.leftover_dir) {
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
/// succeeded deletes the directory and then itself, and then the leftovers (see `schtasks::removal_script`). What a
/// failed removal left in `removal_dir`, `exe` included, becomes a leftover if it cannot be deleted (see `leftovers`).
#[cfg(windows)]
fn spawn_finish(exe: &Path, paths: &Paths) -> Result<Removal> {
    let dir = removal_dir(paths);
    let leftover_dir = leftovers::dir(paths)?;
    // Open before the directory is cleared: `exe` may be the copy that a failed removal left in it.
    let mut source = fs::File::open(exe).with_context(|| format!("opening {}", exe.display()))?;
    remove_saying_what_it_moved_aside(&dir, leftover_dir)?;
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
    let script = schtasks::removal_script(&copy, &removal_log_file(paths), &dir, schtasks::REMOVAL, leftover_dir);
    schtasks::start(schtasks::REMOVAL, &script)?;
    Ok(Removal {
        dir,
        leftover_dir: leftover_dir.to_path_buf(),
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
/// `reverse-tunnel` binary, which includes the leftovers of the installed binary (see
/// `leftovers::images_of_the_binary`).
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
    let images = leftovers::images_of_the_binary(paths).unwrap_or_default();
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
    let unresolved = |path: &Path, err: io::Error| {
        anyhow::Error::new(err).context(format!(
            "resolving {} to check whether it is a directory the removal deletes",
            path.display()
        ))
    };
    let dir = fs::canonicalize(dir).map_err(|err| unresolved(dir, err))?;
    for deleted in deleted_dirs(paths) {
        match fs::canonicalize(&deleted) {
            Ok(resolved) if dir.starts_with(&resolved) => return Ok(Some(deleted)),
            Ok(_) => {}
            // A directory that is not there holds nothing.
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(unresolved(&deleted, err)),
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

/// Removes the service, then the files and the account. Repeating it finishes what a failed run left.
pub fn finish_uninstall(paths: &Paths) -> Result<()> {
    let _lock = lock(paths)?;
    if let Err(err) = service::manager(paths)?.uninstall(&service::id())
        && !matches!(err.cause(), goetia::Error::NotInstalled { .. })
    {
        return Err(err).context("removing the service");
    }
    // goetia's `uninstall` returns before the service's processes end (see `processes`).
    #[cfg(windows)]
    processes::wait_until_none_runs_as_the_service()?;
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
    {
        system_path::remove(&paths.bin_dir)?;
        delete_leftover_images_at_reboot(paths);
    }
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

/// Windows: like `remove_entry`, but a file directly in `path` that Windows refuses to delete is moved aside (see
/// `delete_or_move_aside`) and said so on stdout. Directories, junctions and links are never moved, and fail the
/// removal.
#[cfg(windows)]
fn remove_saying_what_it_moved_aside(path: &Path, leftover_dir: &Path) -> Result<()> {
    let delete = |file: &Path| -> Result<()> {
        if let Some(to) = delete_or_move_aside(file, leftover_dir, remove_entry)? {
            output::println_best_effort(&format!(
                "{}: deleting it was refused (access denied), {MOVED_IT_TO} {}, where the removal's task deletes it",
                file.display(),
                to.display()
            ));
        }
        Ok(())
    };
    if !fs::symlink_metadata(path).is_ok_and(|entry| entry.is_dir()) {
        return delete(path);
    }
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    for entry in entries {
        delete(&entry?.path())?;
    }
    remove_entry(path)
}

/// Windows: once the removal has succeeded, has the system delete the leftovers (see `leftovers`) at the next boot. The
/// task sweeps them after it has deleted itself, so possibly after `uninstall` has returned, and a reboot before then
/// would orphan them. Scheduling earlier would delete, after a failed removal, the renamed binary that the rerun advice
/// names. A failure is printed and does not fail the removal.
#[cfg(windows)]
fn delete_leftover_images_at_reboot(paths: &Paths) {
    let images = leftovers::images(paths).unwrap_or_else(|err| {
        output::eprintln_best_effort(&format!("{err:#}: nothing is scheduled for deletion at the next boot"));
        Vec::new()
    });
    for image in images {
        if let Err(err) = delete_at_reboot(&image) {
            output::eprintln_best_effort(&format!(
                "{err:#}: it stays after a reboot until it is deleted by hand or by a later removal"
            ));
        }
    }
}

/// Windows: has the system delete the file or empty directory `path` at its next boot.
#[cfg(windows)]
fn delete_at_reboot(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};

    let wide = crate::security::wide(path);
    // SAFETY: `wide` is NUL-terminated and outlives the call; a null new name means deletion.
    if unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) } == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("scheduling the deletion of {} at the next boot", path.display()));
    }
    Ok(())
}

/// What the removal says, before where, when it renamed a file that it could not delete.
#[cfg(windows)]
pub const MOVED_IT_TO: &str = "so it was moved to";

/// Windows: deletes `path` with `delete` (`remove_entry`, or `remove_file` where only a file may go). When Windows
/// refuses with access denied, which a running image gets and which another process holding it open does not (that
/// waits), `path` is renamed into `leftover_dir` (see `leftovers::move_aside`, which moves only a regular file) and its
/// new path returned. A refused rename, or a `path` that is not a regular file, is an error that has the OS's answer to
/// the delete and to the move, and nothing is moved. A `path` not found after the delete was refused is done: `None`.
/// A delete-pending file whose metadata read is refused is an error. Any other failure is an error. Nothing asks
/// whether a process runs `path`: the OS's answer decides.
#[cfg(windows)]
fn delete_or_move_aside(
    path: &Path,
    leftover_dir: &Path,
    delete: impl FnOnce(&Path) -> Result<()>,
) -> Result<Option<PathBuf>> {
    let refused = match delete(path) {
        Ok(()) => return Ok(None),
        Err(err) if is_access_denied(&err) => err,
        Err(err) => return Err(err),
    };
    match leftovers::move_aside(path, leftover_dir) {
        Ok(to) => Ok(Some(to)),
        Err(_) if fs::symlink_metadata(path).is_err_and(|err| err.kind() == ErrorKind::NotFound) => Ok(None),
        Err(moving) => Err(leftovers::refused_and_not_moved(refused, &moving)),
    }
}

/// Removes the file `path` (never a directory), which may be running; on Windows see `delete_or_move_aside`.
fn remove_file_that_may_run(paths: &Paths, path: &Path) -> Result<()> {
    #[cfg(windows)]
    return delete_or_move_aside(path, leftovers::dir(paths)?, remove_file).map(drop);
    #[cfg(not(windows))]
    {
        let _ = paths;
        remove_file(path)
    }
}

/// Windows: deletes the service images (see `service::image`) in the bin dir other than `registered`, the one that the
/// service is registered on, once `register` has moved it there: nothing before that may delete the image it names.
/// The previous build's image still runs when this runs, since the restart that ends it comes after (see
/// `delete_or_move_aside`). The sweep goes on past every failure, and returns one error for each, with the path and the
/// cause, except that a failure to read the directory ends it.
#[cfg(windows)]
fn sweep_old_images(paths: &Paths, registered: &Path) -> Vec<anyhow::Error> {
    let registered = registered
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let reading = || format!("reading {}", paths.bin_dir.display());
    let listing = match fs::read_dir(&paths.bin_dir) {
        Ok(listing) => listing,
        Err(err) => return vec![anyhow::Error::new(err).context(reading())],
    };
    let mut old = Vec::new();
    for entry in listing {
        let path = match entry {
            Ok(entry) => entry.path(),
            // A listing that fails once can fail on every step after it.
            Err(err) => return vec![anyhow::Error::new(err).context(reading())],
        };
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if service::is_image(name) && !same_name(name, registered) {
            old.push(path);
        }
    }
    let leftover_dir = match leftovers::dir(paths) {
        Ok(leftover_dir) => leftover_dir,
        Err(err) => return vec![err],
    };
    let mut kept = Vec::new();
    for image in old {
        let swept = match leftovers::is_there_to_delete(&image) {
            Ok(true) => delete_or_move_aside(&image, leftover_dir, remove_file).map(drop),
            Ok(false) => Ok(()),
            Err(err) => Err(err),
        };
        kept.extend(swept.err());
    }
    kept
}

/// Prints what a sweep kept, one line for each.
#[cfg(windows)]
fn say_kept(kept: Vec<anyhow::Error>) {
    for err in kept {
        output::eprintln_best_effort(&format!("{err:#}"));
    }
}

/// Removes the bin dir, the config dir's contents, the marker, the config dir and, last, the logs. On Windows what in
/// the bin dir cannot be deleted is moved aside (see `delete_or_move_aside`).
fn remove_files(paths: &Paths) -> Result<()> {
    #[cfg(windows)]
    let bin_dir = remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(paths)?);
    #[cfg(not(windows))]
    let bin_dir = remove_entry(&paths.bin_dir);
    bin_dir?;
    let marker = uninstalling_file(paths);
    match fs::read_dir(&paths.config_dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path != marker {
                    remove_entry(&path)?;
                }
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("reading {}", paths.config_dir.display())),
    }
    remove_entry(&marker)?;
    remove_entry(&paths.config_dir)?;
    remove_entry(&paths.log_dir)
}

/// Whether a join code is needed: some file it provides is missing.
fn needs_join(paths: &Paths) -> Result<bool> {
    let files = [paths.config_file(), paths.bridge_pem(), paths.bridge_token()];
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
    let config = paths.config_file();
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

    let config = paths.config_file();
    let created = !config.try_exists()? && create_config(paths, host, join)?;
    let mut changed = created;
    if let Some(join) = join {
        if !created {
            let text = fs::read_to_string(&config).with_context(|| format!("reading {}", config.display()))?;
            changed |= replace_if_changed(
                Some(paths),
                &config,
                with_bridge(&text, &join.domain, &config)?,
                PUBLIC_FILE,
                Replace::Always,
            )?;
        }
        changed |= replace_if_changed(
            Some(paths),
            &paths.bridge_pem(),
            &join.cert_pem,
            PUBLIC_FILE,
            Replace::Always,
        )?;
        let token = format!("{}\n", join.token);
        changed |= replace_if_changed(Some(paths), &paths.bridge_token(), token, secret, Replace::Always)?;
    }

    let host_token = paths.host_token();
    if !host_token.try_exists()? {
        let token = format!("{}\n", hex_of_random_bytes::<32>()?);
        mark_pending(paths)?;
        changed |= write_atomic(&host_token, token.as_bytes(), secret, Replace::Never)? == WriteOutcome::Written;
    }
    // A file left by an earlier account keeps that account's group, whatever its content.
    for file in [paths.host_token(), paths.bridge_token()] {
        open_file(&file, secret, false)?;
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
    let written = write_atomic(&paths.config_file(), text.as_bytes(), PUBLIC_FILE, Replace::Never)?;
    Ok(written == WriteOutcome::Written)
}

/// Replaces `dest` with `data` unless it holds it already. Whether it wrote. With `pending`, a write is first marked as
/// one that the service has not picked up (see `mark_pending`).
fn replace_if_changed(
    pending: Option<&Paths>,
    dest: &Path,
    data: impl AsRef<[u8]>,
    perm: Perm,
    replace: Replace,
) -> Result<bool> {
    let data = data.as_ref();
    if fs::read(dest).is_ok_and(|current| current == data) {
        return Ok(false);
    }
    if let Some(paths) = pending {
        mark_pending(paths)?;
    }
    write_atomic(dest, data, perm, replace)?;
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
/// the outcome. A kept frpc is restored (`restore_binary`). The staged copy gets the installed binary's access, so the
/// check sees what the service will run. A fetch needs no restart: a new frpc version only arrives with a new binary,
/// which `place_binaries` marks.
fn verify_tools(paths: &Paths, binary: &[u8], run_as: Option<Account>) -> Result<()> {
    let parents = [paths.bin_dir.parent(), paths.link.as_deref().and_then(Path::parent)];
    for parent in parents.into_iter().flatten() {
        make_missing_dirs(parent, PUBLIC_DIR)?;
    }
    make_dir(&paths.bin_dir, PUBLIC_DIR)?;

    // The pinned frpc first: the binary that names it is not put in place unless it can be fetched.
    let frpc = download::tools(paths).frpc;
    if frpc.try_exists()? {
        restore_binary(&frpc)?;
    } else {
        download::fetch(download::host_pin()?, &paths.bin_dir)?;
    }
    let staged = upgrade::stage(paths, binary)?;
    let checked = ops::check(&staged, run_as, "the new binary's `run --check`");
    upgrade::discard(&staged);
    checked
}

/// Puts the binary and the symlink in place, and on Windows the service's image instead of the binary: nothing deletes
/// or moves aside the image that the registered service names (see `sweep_old_images`), and the binary on the `PATH` is
/// placed once the service is registered (see `place_path_copy`). Whether anything changed.
fn place_binaries(paths: &Paths, new: &Binary) -> Result<bool> {
    // Before this run moves anything aside: what is left then is not this run's.
    #[cfg(windows)]
    say_kept(leftovers::delete_what_can_be(leftovers::images(paths)?));
    #[cfg(windows)]
    let changed = place_binary(Some(paths), &new.image, &new.bytes, Replace::Always)?;
    #[cfg(not(windows))]
    let changed = place_binary(Some(paths), &service::exe(paths), &new.bytes, Replace::Always)?;
    clean_bin_dir(paths)?;
    #[cfg(windows)]
    for entry in fs::read_dir(&paths.bin_dir).with_context(|| format!("reading {}", paths.bin_dir.display()))? {
        crate::files::own_by_administrators(&entry?.path())?;
    }
    #[cfg(unix)]
    if let Some(link) = &paths.link {
        point_link(link, &service::exe(paths))?;
    }
    Ok(changed)
}

/// Windows: replaces the binary on the `PATH`, which runs when this is an `upgrade` run from it and is where a service
/// of an earlier build is registered until `register` moves it. Windows will not overwrite a running image, and lets it
/// be renamed (see `Replace::OrMoveAside`). The service runs its image, so a change here is no reason to restart it.
#[cfg(windows)]
fn place_path_copy(paths: &Paths, new: &Binary) -> Result<()> {
    let exe = service::exe(paths);
    place_binary(None, &exe, &new.bytes, Replace::OrMoveAside(leftovers::dir(paths)?))?;
    crate::files::own_by_administrators(&exe)
}

/// Puts `binary` at `dest`, unless it is there. Whether it changed, and with `pending` that is marked (see
/// `replace_if_changed`). A hand-edited ACL, mode or owner of an unchanged binary does not outlive a reinstall.
fn place_binary(pending: Option<&Paths>, dest: &Path, binary: &[u8], replace: Replace) -> Result<bool> {
    let changed = replace_if_changed(pending, dest, binary, Perm::executable(), replace)?;
    if !changed {
        restore_binary(dest)?;
    }
    Ok(changed)
}

/// Removes from the bin dir the frpc versions that are not the current one, temp files a crashed write left, and the
/// copies `upgrade` ran from (`upgrade-*`), this process's own among them. On Windows what Windows refuses to delete (a
/// running old frpc or this process's image) is moved aside (see `remove_file_that_may_run`). A staged copy that cannot
/// be removed is a warning.
fn clean_bin_dir(paths: &Paths) -> Result<()> {
    let current = download::tools(paths).frpc;
    let current = current.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    for entry in fs::read_dir(&paths.bin_dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        let stale = !same_name(name, current) && (name.starts_with("frpc-") || name.starts_with(".tmp"));
        if name.starts_with(upgrade::STAGED) {
            upgrade::warn_if_kept(remove_file_that_may_run(paths, &path));
        } else if stale {
            remove_file_that_may_run(paths, &path)?;
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
    let host = Config::load(&paths.config_file())?.host;
    let token_file = paths.host_token();
    let token = fs::read_to_string(&token_file).with_context(|| format!("reading {}", token_file.display()))?;
    Ok(registration_line(&host, token.trim()))
}

fn registration_line(host: &str, token: &str) -> String {
    format!("uv run ctl add {host} {}", join::token_hash(token))
}

fn revoke_line(paths: &Paths) -> Result<String> {
    Ok(format!(
        "uv run ctl revoke {}",
        Config::load(&paths.config_file())?.host
    ))
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
