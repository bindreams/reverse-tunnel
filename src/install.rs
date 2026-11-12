//! `reverse-tunnel install` and `uninstall` on Linux and macOS.
//!
//! Everything a run writes is final when it is written: modes and owners are set before any content (see `files`),
//! and each step can be repeated, so an install that failed midway is finished by running it again.

use std::env;
use std::fs;
use std::io::{self, BufRead, ErrorKind, Write};
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
    // Made here, owner-only: named-lock would use the umask's mode, and whoever can open the file can hold the lock.
    open_file(&paths.lock, Perm::new(0o600), false)?;
    NamedLock::with_path(&paths.lock)
        .and_then(|lock| lock.lock())
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
        &*goetia::manager::native()?,
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
    let spec = service::spec(paths);
    // Read once: the binary that is checked is the one that is placed.
    let binary = fs::read(new).with_context(|| format!("reading {}", new.display()))?;
    // The settings come first because the check reads them as the account: on a settled host `write_settings` writes no
    // content and only re-applies owners and modes. The unit is registered after the check, so that a rejected binary
    // leaves the unit as it was.
    changed |= write_settings(paths, account, host, join)?;
    verify_tools(paths, &binary, account)?;
    // The binary is not in place yet; the manager does not look.
    changed |= register(manager, &spec, paths)?;
    changed |= place_binaries(paths, &binary)?;

    println!(
        "Register this host on the bridge by running:\n    {}",
        registration(paths)?
    );
    manager.enable(&spec.id)?;
    pick_up(manager, &spec.id, paths, changed)
}

/// Prepares the removal, hands it to `uninstall --finish` (see `spawn_finish`) and waits for it.
pub fn uninstall(paths: &Paths) -> Result<()> {
    let lock = lock(paths)?;
    match revoke_line(paths) {
        Ok(line) => println!("Revoke this host on the bridge by running:\n    {line}"),
        Err(err) => eprintln!("{err:#}\nRevoke this host on the bridge by running: uv run ctl revoke <host>"),
    }
    let exe = env::current_exe()?;
    make_dir(&paths.config_dir, PUBLIC_DIR)?;
    open_file(&uninstalling_file(paths), Perm::new(0o600), false)?;
    // `--finish` takes the lock itself; an `install` in between is refused by the marker.
    drop(lock);
    // Before the removal starts: over the tunnel it can cut the session before anything is printed after.
    println!("Its log will be {}.", removal_log(paths));
    let removal = spawn_finish(&exe, paths).context("starting the removal")?;
    ops::println_best_effort("Removing. If this session ends, the removal continues.");
    let outcome = removal.wait().with_context(|| {
        format!(
            "could not tell how the removal ended; its log is {}, and to finish it {}",
            removal_log(paths),
            rerun_uninstall(paths)
        )
    })?;
    if let WaitOutcome::Failed(why) = outcome {
        return Err(anyhow!(why)).with_context(|| {
            format!(
                "the removal failed: see {}, and {} to finish it",
                removal_log(paths),
                rerun_uninstall(paths)
            )
        });
    }
    ops::println_best_effort("Removed.");
    Ok(())
}

/// Where the removal's output is, for the operator: the journal, where the lines of earlier failed runs of the unit
/// come first, and which a host without persistent storage loses at a reboot.
#[cfg(target_os = "linux")]
pub fn removal_log(_paths: &Paths) -> String {
    "the journal (`journalctl -u 'reverse-tunnel-uninstall-*' -e`; this run's lines are the last, and without a \
     persistent journal they are gone after a reboot)"
        .to_string()
}

/// Where the removal's output is, for the operator: a file in `logs/`, which the removal deletes when it succeeds.
#[cfg(not(target_os = "linux"))]
pub fn removal_log(paths: &Paths) -> String {
    removal_log_file(paths).display().to_string()
}

/// The file the removal's output goes to.
#[cfg(not(target_os = "linux"))]
pub fn removal_log_file(paths: &Paths) -> PathBuf {
    paths.log_dir.join("uninstall.log")
}

/// How a waited-for removal ended, when it could be waited for.
enum WaitOutcome {
    Ended,
    Failed(String),
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

#[cfg(not(target_os = "linux"))]
struct Removal(std::process::Child);

#[cfg(not(target_os = "linux"))]
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

    let mut random = [0u8; 16];
    getrandom::fill(&mut random).context("reading random bytes from the OS")?;
    let unit = format!("reverse-tunnel-uninstall-{}", hex::encode(random));
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

/// macOS: a process group of its own, which the session's hangup does not reach, and which launchd leaves alone. It
/// inherits the log, which is opened here, by root without following a link: `logs/` belongs to the service account,
/// which may have left anything in it.
#[cfg(not(target_os = "linux"))]
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
fn rerun_uninstall(paths: &Paths) -> String {
    let exe = service::exe(paths);
    if exe.exists() {
        format!("run `sudo {} uninstall`", exe.display())
    } else {
        "run `uninstall` with `sudo` and any `reverse-tunnel` binary (the installed one is gone)".to_string()
    }
}

/// Removes the service, then the files and the account. Repeating it finishes what a failed run left.
pub fn finish_uninstall(paths: &Paths) -> Result<()> {
    let _lock = lock(paths)?;
    let spec = service::spec(paths);
    match goetia::manager::native()?.uninstall(&spec.id) {
        Ok(()) | Err(goetia::Error::NotInstalled { .. }) => {}
        Err(err) => return Err(err).context("removing the service"),
    }
    // The order leaves no gap where something is wrong, or where the reason is lost: the tokens go before the account,
    // so they never belong to a freed gid; the link goes before the binary, so it never dangles; the marker stays
    // until the rest of `config_dir` is gone, since `install` is refused while it exists; and `logs/` is last, so that
    // a failure above is still in the log.
    remove_entry(&paths.secrets_dir)?;
    account::remove(service::ACCOUNT)?;
    remove_link(paths)?;
    remove_files(paths).with_context(|| rerun_uninstall(paths))
}

/// Removes the link to the binary, unless it points elsewhere.
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

/// Removes the bin dir, the config dir's contents, the marker, the config dir and, last, the logs.
fn remove_files(paths: &Paths) -> Result<()> {
    remove_entry(&paths.bin_dir)?;
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
    let secret = Perm::new(0o640).gid(account.gid);
    make_dir(&paths.secrets_dir, Perm::new(SECRETS_DIR_MODE).gid(account.gid))?;
    make_dir(&paths.log_dir, Perm::new(0o755).uid(account.uid).gid(account.gid))?;

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
        let mut random = [0; 32];
        getrandom::fill(&mut random).context("reading random bytes from the OS")?;
        let token = format!("{}\n", hex::encode(random));
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

/// Makes the bin dir, fetches the pinned frpc if it is missing, and has the new binary `binary` check the settings as
/// the service account will read them: `binary` is written into the bin dir, where the account can run it wherever it
/// came from, and the copy's `run --check` runs as `account` (see `ops::check`). The copy is removed whatever the
/// outcome. A fetch needs no restart: a new frpc version only arrives with a new binary, which `place_binaries` marks.
fn verify_tools(paths: &Paths, binary: &[u8], account: &Account) -> Result<()> {
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
    let checked = ops::check(paths, &staged, Some(*account), "the new binary's `run --check`");
    upgrade::discard(&staged);
    checked
}

/// Puts the binary `binary` and the symlink in place. Whether the binary changed.
fn place_binaries(paths: &Paths, binary: &[u8]) -> Result<bool> {
    let exe = service::exe(paths);
    let changed = replace_if_changed(paths, &exe, binary, Perm::EXECUTABLE)?;
    clean_bin_dir(paths)?;
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
        if stale || name.starts_with(upgrade::STAGED) {
            remove_entry(&path)?;
        }
    }
    Ok(())
}

/// Makes `link` a symlink to `target`.
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
    match failed.marker {
        Ok(()) => Err(err.context(format!("{restart_failed}; run `reverse-tunnel install` again to retry"))),
        Err(write) => Err(write.context(format!(
            "{restart_failed} ({err:#}), and the marker for retrying it could not be written; the next `install` will \
            not notice, so run `reverse-tunnel restart`"
        ))),
    }
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
