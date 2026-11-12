//! `start`, `stop`, `restart` and `status`: the service through goetia, and the files in `config_dir`, which every local
//! user may read. Only `check_and_restart` reads `secrets_dir`, as root, through the configuration check.

use std::fs;
use std::io::Write;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use goetia::manager::{Budget, ServiceManager, State};
use goetia::spec::Id;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::download::Tools;
use crate::paths::Paths;
use crate::{service, supervisor};

pub fn start(manager: &dyn ServiceManager, paths: &Paths) -> Result<()> {
    manager.start(&service::spec(paths).id, Budget::Unbounded)?;
    println_best_effort("The service is running.");
    Ok(())
}

pub fn stop(manager: &dyn ServiceManager, paths: &Paths) -> Result<()> {
    manager.stop(&service::spec(paths).id, Budget::Unbounded)?;
    println_best_effort("The service is stopped. It starts again at boot if it is enabled.");
    Ok(())
}

/// Has the service read its configuration again, after checking it. The check is `run --check`, in this process; when
/// it fails the service is left as it is.
pub fn check_and_restart(manager: &dyn ServiceManager, paths: &Paths, tools: &Tools) -> Result<()> {
    supervisor::run(paths, tools, true)?;
    restart(manager, &service::spec(paths).id)?;
    println_best_effort("The service is restarting.");
    Ok(())
}

/// Has the service run again. It is killed, and the manager starts it again; it is never stopped first, because run
/// over the tunnel the stop cuts this session and the start never comes. A service that is not running is started.
pub fn restart(manager: &dyn ServiceManager, id: &Id) -> Result<()> {
    match manager.kill(id) {
        Ok(()) => Ok(()),
        Err(goetia::Error::NotRunning { .. }) => Ok(manager.start(id, Budget::Unbounded)?),
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
    let state = manager.status(&service::spec(paths).id)?;
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
