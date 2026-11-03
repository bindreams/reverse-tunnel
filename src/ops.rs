//! `start`, `stop` and `status`: the service through goetia, and the files in `config_dir` and `log_dir`, which every
//! local user may read. Nothing here reads `secrets_dir`.

use std::fs::{self, File, TryLockError};
use std::io::{ErrorKind, Write};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use goetia::manager::{Budget, ServiceManager, State};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::paths::{CONNECTION_LOCK, CONNECTION_RECORD, Paths};
use crate::service;

pub fn start(manager: &dyn ServiceManager, paths: &Paths) -> Result<()> {
    manager.start(&service::spec(paths).id, Budget::Unbounded)?;
    println!("The service is running.");
    Ok(())
}

pub fn stop(manager: &dyn ServiceManager, paths: &Paths) -> Result<()> {
    manager.stop(&service::spec(paths).id, Budget::Unbounded)?;
    println!("The service is stopped. It starts again at boot if it is enabled.");
    Ok(())
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
    let connection = server_connection(paths)?.unwrap_or_else(|| "none recorded".into());
    writeln!(out, "server connection: {connection}")?;
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

/// The text of the record of frpc's connection to the server, while the `run` that keeps it holds the lock on
/// `CONNECTION_LOCK`. The OS drops that lock when the process ends, however it ends, so a record left by a dead run,
/// or one whose first write or lock failed, is not shown: `None`.
fn server_connection(paths: &Paths) -> Result<Option<String>> {
    let lock_path = paths.log_dir.join(CONNECTION_LOCK);
    let lock = match File::open(&lock_path) {
        Ok(lock) => lock,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("opening {}", lock_path.display())),
    };
    match lock.try_lock_shared() {
        // Nobody holds it. The lock is released with `lock`.
        Ok(()) => return Ok(None),
        Err(TryLockError::WouldBlock) => {}
        Err(TryLockError::Error(err)) => return Err(err).with_context(|| format!("locking {}", lock_path.display())),
    }
    let path = paths.log_dir.join(CONNECTION_RECORD);
    let record = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(record.trim_end().to_string()))
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
