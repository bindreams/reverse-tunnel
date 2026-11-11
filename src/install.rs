//! `reverse-tunnel install` and `uninstall` on Linux and macOS.
//!
//! Everything a run writes is final when it is written: modes and owners are set before any content (see `files`),
//! and each step can be repeated, so an install that failed midway is finished by running it again.

use std::env;
use std::fs;
use std::io::{self, BufRead, ErrorKind, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail, ensure};
use goetia::decide::Outcome;
use goetia::manager::{Budget, ServiceManager};
use goetia::spec::{DaemonSpec, Id};
use named_lock::{NamedLock, NamedLockGuard};

use crate::account::{self, Account};
use crate::config::{Config, valid_label};
use crate::files::{Perm, Replace, WriteOutcome, make_dir, make_missing_dirs, open_file, write_atomic};
use crate::join::{self, JoinInfo};
use crate::paths::Paths;
use crate::{download, ops, service};

/// Directories, and files everyone may read.
const PUBLIC_DIR: Perm = Perm::new(0o755);
const PUBLIC_FILE: Perm = Perm::new(0o644);

/// `secrets/` is setgid on Linux, so that a file put there by hand joins the service account's group.
const SECRETS_DIR_MODE: u32 = if cfg!(target_os = "linux") { 0o2750 } else { 0o750 };

pub struct InstallOpts {
    /// Names a new `config.yaml`; without it, the machine's name. Ignored when `config.yaml` exists.
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
/// `install` refuses, so that it cannot install what the removal is about to delete.
fn uninstalling_file(paths: &Paths) -> PathBuf {
    paths.config_dir.join("uninstalling")
}

/// Exists from the first change to what the service runs until the service has picked it up, so that a run that fails
/// in between is made up for by the next.
fn pending_file(paths: &Paths) -> PathBuf {
    paths.config_dir.join("restart-pending")
}

fn mark_pending(paths: &Paths) -> Result<()> {
    open_file(&pending_file(paths), Perm::new(0o600), false)?;
    Ok(())
}

/// Installs, or updates, the service so that it runs this binary, and starts it, or restarts it if anything it reads
/// changed. Prints the line that registers the host on the bridge.
pub fn install(opts: InstallOpts) -> Result<()> {
    let paths = &opts.paths;
    let _lock = lock(paths)?;
    ensure!(
        !uninstalling_file(paths).try_exists()?,
        "an uninstall is in progress or failed: see {}, and run `reverse-tunnel uninstall` to finish it",
        removal_log(paths)
    );
    make_dir(&paths.config_dir, PUBLIC_DIR)?;
    let mut changed = pending_file(paths).try_exists()?;
    let join = match opts.join.as_deref() {
        Some(code) => Some(join::decode(code)?),
        None if needs_join(paths)? => Some(prompt_join(&mut io::stdin().lock(), &mut io::stderr())?),
        None => None,
    };
    let host = if config_file(paths).try_exists()? {
        None
    } else {
        Some(host_name(opts.host.as_deref())?)
    };

    let account = account::ensure(service::ACCOUNT)?;
    let spec = service::spec(paths);
    let manager = goetia::manager::native()?;
    // The binary and the settings may not exist yet; the manager does not look.
    changed |= register(&*manager, &spec, paths)?;
    changed |= write_settings(paths, &account, host.as_deref(), join.as_ref())?;
    changed |= place_binaries(paths)?;

    println!(
        "Register this host on the bridge by running:\n    {}",
        registration(paths)?
    );
    manager.enable(&spec.id)?;
    pick_up(&*manager, &spec.id, paths, changed)
}

/// Prepares the removal, hands it to `uninstall --finish`, detached (see `spawn_finish`; stopping the service cuts the
/// tunnel, and with it the session this runs in) and waits for it. If the session ends, the removal carries on.
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
    // The removal may already have cut the session.
    ops::println_best_effort("Removing. If this session ends, the removal continues.");
    let outcome = removal.wait().with_context(|| {
        format!(
            "could not tell how the removal ended; its log is {}, and `uninstall` can be run again",
            removal_log(paths)
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
    "the journal (`journalctl -u reverse-tunnel-uninstall -e`; this run's lines are the last, and without a persistent \
     journal they are gone after a reboot)"
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
    /// Why it failed.
    Failed(String),
}

/// A started `uninstall --finish`.
#[cfg(target_os = "linux")]
struct Removal {
    client: std::process::Child,
    stderr: io::BufReader<std::process::ChildStderr>,
    /// What `systemd-run` printed before the unit started.
    said: String,
    /// The read error that ended that reading, if one did.
    unread: Option<io::Error>,
}

/// What `systemd-run` did, for the operator: its status, what it printed, and the errors from reading it.
#[cfg(target_os = "linux")]
fn client_report(status: std::process::ExitStatus, said: &str, read_errors: &[io::Error]) -> String {
    use std::fmt::Write as _;

    let mut report = format!("systemd-run ended with {status}");
    if !said.trim().is_empty() {
        let _ = write!(report, ". It said: {}", said.trim_end());
    }
    for err in read_errors {
        let _ = write!(report, ". Reading its output failed: {err}");
    }
    report
}

#[cfg(target_os = "linux")]
impl Removal {
    /// Waits for the removal to end. A failure carries everything `systemd-run` printed, including the result lines it
    /// prints when the unit ends; a failure to read them is added to it, and does not fail a removal that succeeded.
    fn wait(mut self) -> Result<WaitOutcome> {
        let mut read_errors: Vec<io::Error> = self.unread.take().into_iter().collect();
        let mut rest = Vec::new();
        // To the end, since the client's output is complete when it exits; not again after an error, which is already
        // reported.
        if read_errors.is_empty()
            && let Err(err) = io::Read::read_to_end(&mut self.stderr, &mut rest)
        {
            read_errors.push(err);
        }
        let status = self.client.wait().context("waiting for systemd-run")?;
        if status.success() {
            return Ok(WaitOutcome::Ended);
        }
        let said = format!("{}{}", self.said, String::from_utf8_lossy(&rest));
        Ok(WaitOutcome::Failed(client_report(status, &said, &read_errors)))
    }
}

/// A started `uninstall --finish`.
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
/// `removal_log` says. Returns once the removal has started; `Removal::wait` ends with it. An error means nothing
/// started.
///
/// Linux: a transient systemd unit, since logind kills what a session leaves behind under `KillUserProcesses=yes`, and
/// a process of its own does not escape that. A service's output goes to the journal. `systemd-run` says "Running as
/// unit" once the unit is started; until then, the end of the session could end the removal before it began.
#[cfg(target_os = "linux")]
fn spawn_finish(exe: &Path, _paths: &Paths) -> Result<Removal> {
    let mut client = Command::new("systemd-run")
        .args(["--wait", "--collect", "--unit=reverse-tunnel-uninstall", "--"])
        .arg(exe)
        .args(["uninstall", "--finish"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running systemd-run")?;
    // Kept open for `wait`: the client's later lines would otherwise kill it with SIGPIPE, and the removal would look
    // failed.
    let mut stderr = io::BufReader::new(client.stderr.take().expect("stderr is piped"));
    let mut said = String::new();
    let mut unread = None;
    loop {
        let mut line = Vec::new();
        let read = stderr.read_until(b'\n', &mut line);
        let text = String::from_utf8_lossy(&line);
        match read {
            Ok(0) => {
                let status = client.wait().context("waiting for systemd-run")?;
                bail!("the removal did not start: {}", client_report(status, &said, &[]));
            }
            Ok(_) if text.starts_with("Running as unit:") => break,
            Ok(_) => said.push_str(&text),
            // No sign that the unit did not start: carry on as if it had, and its end tells.
            Err(err) => {
                said.push_str(&text);
                unread = Some(err);
                break;
            }
        }
    }
    Ok(Removal {
        client,
        stderr,
        said,
        unread,
    })
}

/// macOS: a process group of its own, which the session's hangup does not reach, and which launchd leaves alone. It
/// inherits the log, which is opened here, by root without following a link: `logs/` belongs to the service account,
/// which may have left anything in it.
#[cfg(not(target_os = "linux"))]
fn spawn_finish(exe: &Path, paths: &Paths) -> Result<Removal> {
    use std::os::unix::process::CommandExt;

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
        format!("run `{} uninstall`", exe.display())
    } else {
        "run `uninstall` with any `reverse-tunnel` binary (the installed one is gone)".to_string()
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
    // until the rest is gone, since `install` is refused while it exists; and `logs/` is last, so that a failure above
    // is written to `uninstall.log` on macOS.
    remove_entry(&paths.secrets_dir)?;
    account::remove(service::ACCOUNT)?;
    remove_link(paths)?;
    remove_files(paths)
        .context("the binary may be gone, but any `reverse-tunnel` binary can run `reverse-tunnel uninstall` again")
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

/// Removes `path`, a directory with its contents, unless it is already gone. A link is removed, not followed.
fn remove_entry(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(entry) if entry.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(err) => Err(err),
    };
    match removed {
        Err(err) if err.kind() != ErrorKind::NotFound => {
            Err(err).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
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

/// Puts this binary, the pinned frpc and the symlink in place. Whether the binary or frpc changed.
fn place_binaries(paths: &Paths) -> Result<bool> {
    let parents = [paths.bin_dir.parent(), paths.link.as_deref().and_then(Path::parent)];
    for parent in parents.into_iter().flatten() {
        make_missing_dirs(parent, PUBLIC_DIR)?;
    }
    make_dir(&paths.bin_dir, PUBLIC_DIR)?;

    // The pinned frpc first: the binary that names it is not put in place unless it can be fetched.
    let mut changed = false;
    if !download::tools(paths).frpc.try_exists()? {
        mark_pending(paths)?;
        download::fetch(download::host_pin()?, &paths.bin_dir)?;
        changed = true;
    }
    let exe = service::exe(paths);
    let me = env::current_exe().context("finding this binary")?;
    let binary = fs::read(&me).with_context(|| format!("reading {}", me.display()))?;
    changed |= replace_if_changed(paths, &exe, binary, Perm::EXECUTABLE)?;
    clean_bin_dir(paths)?;
    if let Some(link) = &paths.link {
        point_link(link, &exe)?;
    }
    Ok(changed)
}

/// Removes the frpc versions that are not the current one, and temp files a crashed write left, from the bin dir.
fn clean_bin_dir(paths: &Paths) -> Result<()> {
    let current = download::tools(paths).frpc;
    for entry in fs::read_dir(&paths.bin_dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
        if path != current && (name.starts_with("frpc-") || name.starts_with(".tmp")) {
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
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

/// Has the service run what is now in place. After a change it is killed, and the manager restarts it; it is never
/// stopped first, because run over the tunnel the stop cuts this session and the start never comes. Without one, it
/// is started, which leaves a running service alone.
///
/// The restart marker is removed just before, since nothing that runs after the kill is sure to run; it is put back
/// if the service was not picked up.
fn pick_up(manager: &dyn ServiceManager, id: &Id, paths: &Paths, changed: bool) -> Result<()> {
    if !changed {
        manager.start(id, Budget::Unbounded)?;
        return Ok(());
    }
    remove_entry(&pending_file(paths))?;
    let Err(err) = restart(manager, id) else {
        return Ok(());
    };
    let restart_failed = "the new files are in place, but the service was not restarted";
    match mark_pending(paths) {
        Ok(()) => Err(err.context(format!("{restart_failed}; run `reverse-tunnel install` again to retry"))),
        // `install` would not notice that the service is behind, so the remedy is by hand, and from a console: stopping
        // the service over the tunnel cuts the session before `start`.
        Err(write) => Err(write.context(format!(
            "{restart_failed} ({err:#}), and the marker for retrying it could not be written; the next `install` will \
             not notice, so from a console run `reverse-tunnel stop` and then `reverse-tunnel start`"
        ))),
    }
}

fn restart(manager: &dyn ServiceManager, id: &Id) -> Result<()> {
    match manager.kill(id) {
        Ok(()) => Ok(()),
        Err(goetia::Error::NotRunning { .. }) => Ok(manager.start(id, Budget::Unbounded)?),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod tests;
