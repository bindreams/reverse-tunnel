//! `start`, `stop`, `restart` and `status`: the service through goetia, and the files in `config_dir`, which every local
//! user may read. Nothing here reads `secrets_dir`.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use goetia::manager::{Budget, ServiceManager, State};
use goetia::spec::Id;
use sha2::{Digest, Sha256};

use crate::account;
use crate::command;
use crate::config::Config;
use crate::files::{Perm, open_file, remove_entry};
use crate::install::refuse_while_uninstalling;
use crate::paths::Paths;
use crate::service;

pub fn start(manager: &dyn ServiceManager) -> Result<()> {
    manager.start(&service::id(), Budget::Unbounded)?;
    println_best_effort("The service is running.");
    Ok(())
}

pub fn stop(manager: &dyn ServiceManager) -> Result<()> {
    manager.stop(&service::id(), Budget::Unbounded)?;
    println_best_effort("The service is stopped. It starts again at boot if it is enabled.");
    Ok(())
}

/// Has the service read its configuration again, after the installed binary has checked it as the service account: a
/// file that account cannot read, or that the installed binary rejects, leaves the service as it is.
pub fn check_and_restart(manager: &dyn ServiceManager, paths: &Paths) -> Result<()> {
    refuse_while_uninstalling(paths)?;
    // Decided from the binary: the account database can answer for an account that has just been removed.
    ensure!(service::exe(paths).try_exists()?, "the service is not installed");
    check_and_restart_as(manager, paths, service_identity()?)
}

/// `check_and_restart`, with the check run as `run_as` (`None`: as the caller).
fn check_and_restart_as(manager: &dyn ServiceManager, paths: &Paths, run_as: Option<RunAs>) -> Result<()> {
    let exe = service::exe(paths);
    check(
        paths,
        &exe,
        run_as,
        &format!("the installed binary `{}`'s `run --check`", exe.display()),
    )?;
    let outcome = restart_pending(manager, &service::id(), paths).map_err(|failed| {
        failed.error.context(match failed.marker {
            Ok(()) => "the service was not restarted".to_string(),
            Err(write) => format!("the service was not restarted, and `install` will not notice ({write:#})"),
        })
    })?;
    println_best_effort(match outcome {
        RestartOutcome::Killed => "The service is restarting.",
        RestartOutcome::Started => "The service was not running; it is started.",
    });
    Ok(())
}

/// `exe`'s `run --check`, started as the service starts it: the arguments and environment from `service::spec`, nothing
/// inherited, as `run_as`. `what` names the check in a failure. Fails with what the check printed.
///
/// On Unix it starts in `/`, as the service does (the spec names no working directory). Run by root, as `restart` and
/// `install` are, it has the account's primary group as its gid and only group (std's `.uid()/.gid()` would leave
/// macOS's effective gid 0), so a file it reads only through another group is refused. The files it reads are
/// install's and open to the account by contract.
pub(crate) fn check(paths: &Paths, exe: &Path, run_as: Option<RunAs>, what: &str) -> Result<()> {
    let spec = service::spec(paths)?;
    let args = spec.command.split_first().expect("the service has a command").1;
    let mut check = process::Command::new(exe);
    check.args(args).arg("--check").env_clear().envs(&spec.env);
    #[cfg(unix)]
    {
        debug_assert!(spec.cwd.is_none(), "the service starts in /, and so does the check");
        check.current_dir("/");
        if let Some(account::Account { uid, gid }) = run_as {
            let root = cosca::elevation::is_elevated();
            // SAFETY: the closure allocates nothing and makes only the syscalls setgroups, setgid and setuid.
            unsafe { check.pre_exec(move || drop_to(root, uid, gid)) };
        }
    }
    let who = match run_as {
        Some(_) => format!("as the `{}` account", service::ACCOUNT),
        None => "as the caller".to_string(),
    };
    command::run_built(&format!("{what} {who}"), &mut check)
        .context("the service would not start with this configuration")?;
    Ok(())
}

/// In the forked child: for `root`, the group list `[gid]`; then the gid, then the uid. A caller that is not root cannot
/// change its groups, and keeps them.
#[cfg(unix)]
fn drop_to(root: bool, uid: u32, gid: u32) -> std::io::Result<()> {
    // SAFETY: plain syscalls; `gid` is a live `gid_t` and the count is 1.
    if (root && unsafe { libc::setgroups(1 as _, &gid) } != 0)
        || unsafe { libc::setgid(gid) } != 0
        || unsafe { libc::setuid(uid) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Who the check runs as: the service's account on Linux and macOS; on Windows, always the caller (`None`).
pub(crate) type RunAs = account::Account;

#[cfg(unix)]
fn service_identity() -> Result<Option<RunAs>> {
    let account = account::lookup(service::ACCOUNT).with_context(|| {
        format!(
            "the service is not installed: there is no account `{}`",
            service::ACCOUNT
        )
    })?;
    Ok(Some(account))
}

#[cfg(not(unix))]
fn service_identity() -> Result<Option<RunAs>> {
    Ok(None)
}

/// How `restart` had the service run again.
#[derive(Debug, PartialEq, Eq)]
pub enum RestartOutcome {
    Killed,
    /// It was not running: the kill found nothing, and it was started.
    Started,
}

/// Why `restart_pending` did not restart the service, and whether the marker is back.
pub struct NotRestarted {
    pub error: anyhow::Error,
    pub marker: Result<()>,
}

/// Exists from the first change to what the service runs until the service has picked it up, so that a run that fails
/// in between is made up for by the next.
pub fn pending_file(paths: &Paths) -> PathBuf {
    paths.config_dir.join("restart-pending")
}

pub fn mark_pending(paths: &Paths) -> Result<()> {
    open_file(&pending_file(paths), Perm::new(0o600), false)?;
    Ok(())
}

/// `restart` for a service that must run what is in place now. The restart marker is removed just before, since
/// nothing that runs after the kill is sure to run; it is put back if the service was not picked up.
pub fn restart_pending(manager: &dyn ServiceManager, id: &Id, paths: &Paths) -> Result<RestartOutcome, NotRestarted> {
    if let Err(error) = remove_entry(&pending_file(paths)) {
        return Err(NotRestarted { error, marker: Ok(()) });
    }
    restart(manager, id).map_err(|error| NotRestarted {
        error,
        marker: mark_pending(paths),
    })
}

/// Has the service run again. It is killed, and the manager starts it again; it is never stopped first, because run
/// over the tunnel the stop cuts this session and the start never comes. A service that is not running is started.
pub fn restart(manager: &dyn ServiceManager, id: &Id) -> Result<RestartOutcome> {
    match manager.kill(id) {
        Ok(()) => Ok(RestartOutcome::Killed),
        Err(err) if matches!(err.cause(), goetia::Error::NotRunning { .. }) => {
            manager.start(id, Budget::Unbounded)?;
            Ok(RestartOutcome::Started)
        }
        Err(err) => Err(err.into()),
    }
}

/// Prints a line reporting what is already done, and ignores a closed stdout rather than panicking: a command that
/// stops the service over the tunnel ends the session that would read it.
pub fn println_best_effort(message: &str) {
    let _ = writeln!(std::io::stdout(), "{message}");
}

/// Never prints a token.
pub fn status(manager: &dyn ServiceManager, paths: &Paths, out: &mut impl Write) -> Result<()> {
    let state = manager.status(&service::id())?;
    let word = match state.state {
        State::Running => "running",
        State::Stopped => "stopped",
        State::Failed => "failed",
        State::Unknown => "unknown",
    };
    write!(out, "service: {word}")?;
    if let Some(pid) = state.pid {
        write!(out, " (pid {pid})")?;
    }
    writeln!(
        out,
        ", {}",
        if state.enabled {
            "enabled at boot"
        } else {
            "not enabled at boot"
        }
    )?;

    let config = Config::load(&paths.config_dir.join("config.yaml"))?;
    writeln!(out, "host: {}\nbridge: {}", config.host, config.bridge)?;
    let pem_path = paths.config_dir.join("bridge.pem");
    let pem = fs::read_to_string(&pem_path).with_context(|| format!("reading {}", pem_path.display()))?;
    for fingerprint in fingerprints(&pem).with_context(|| format!("in {}", pem_path.display()))? {
        writeln!(out, "certificate: SHA-256 {fingerprint}")?;
    }
    Ok(())
}

/// SHA-256 of each certificate's DER, formatted like `openssl x509 -fingerprint -sha256`.
fn fingerprints(pem: &str) -> Result<Vec<String>> {
    let found = pem
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|rest| {
            let (body, _) = rest
                .split_once("-----END CERTIFICATE-----")
                .context("a certificate has no end")?;
            let der = STANDARD.decode(body.split_ascii_whitespace().collect::<String>())?;
            let digest = Sha256::digest(der);
            Ok(digest
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(":"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!found.is_empty(), "no certificate");
    Ok(found)
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
