//! `start`, `stop` and `status`: the service through goetia, and the files in `config_dir` and `log_dir`, which every
//! local user may read. Nothing here reads `secrets_dir`.

use std::fs;
use std::io::{ErrorKind, Write};

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use goetia::manager::{Budget, ServiceManager, State};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::paths::{LOG_FRPC, Paths};
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
    writeln!(out, "last login: {}", last_login(paths)?)?;
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

/// The newest login result in `frpc.log.1` followed by `frpc.log`, read as one stream: a rotation can fall inside a
/// line.
fn last_login(paths: &Paths) -> Result<String> {
    let mut log = Vec::new();
    for name in [format!("{LOG_FRPC}.1"), LOG_FRPC.to_string()] {
        let path = paths.log_dir.join(name);
        match fs::read(&path) {
            Ok(bytes) => log.extend(bytes),
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        }
    }
    let text = String::from_utf8_lossy(&log);
    // Only a line ended by its newline is whole: `pump` can leave the file cut off mid-line.
    let whole = &text[..text.rfind('\n').map_or(0, |end| end + 1)];
    Ok(whole
        .lines()
        .rev()
        .find_map(login_result)
        .unwrap_or_else(|| "no login recorded".into()))
}

/// The login result a frpc log line `<date> <time> [level] [source] ...` reports, if any.
fn login_result(line: &str) -> Option<String> {
    let mut fields = line.splitn(3, ' ');
    let stamp = format!("{} {}", fields.next()?, fields.next()?);
    let message = fields.next()?;
    if message.contains("login to server success") {
        return Some(format!("success ({stamp})"));
    }
    let (_, reason) = message.split_once("connect to server error: ")?;
    Some(format!("failed ({stamp}): {}", reason.trim_end()))
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
