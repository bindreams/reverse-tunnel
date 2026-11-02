//! `start`, `stop`, `status` and `logs`: the service through goetia, and the files in `config_dir` and `log_dir`, which
//! every local user may read. Nothing here reads `secrets_dir`.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use goetia::manager::{Budget, ServiceManager};
use same_file::Handle;
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::paths::{LOG_FRPC, LOG_SUPERVISOR, Paths};
use crate::service;

/// How often `logs -f` looks for new data.
const POLL: Duration = Duration::from_millis(250);

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

/// Prints the service's state, the host and bridge it is set up for with the bridge certificate's fingerprint, and
/// the last login result from frpc's log. Never prints a token.
pub fn status(manager: &dyn ServiceManager, paths: &Paths, out: &mut impl Write) -> Result<()> {
    let state = manager.status(&service::spec(paths).id)?;
    write!(out, "service: {}", format!("{:?}", state.state).to_lowercase())?;
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

/// The SHA-256 of each certificate's DER, as `openssl x509 -fingerprint -sha256` prints it.
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

/// The newest login result in `frpc.log`, else in `frpc.log.1`, else `no login recorded`.
fn last_login(paths: &Paths) -> Result<String> {
    for name in [LOG_FRPC.to_string(), format!("{LOG_FRPC}.1")] {
        let path = paths.log_dir.join(name);
        let text = match fs::read(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        if let Some(result) = text.lines().rev().find_map(login_result) {
            return Ok(result);
        }
    }
    Ok("no login recorded".into())
}

/// A frpc log line `<date> <time> [level] [source] ...` that reports a login, as `success (<date> <time>)` or
/// `failed (<date> <time>): <reason>`.
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

/// Prints `supervisor.log` and `frpc.log`, each under a `==> name <==` line, and with `follow` keeps printing what
/// they gain, including across a rotation, until `out` is closed. `frpc.toml` and the rotated `.1` files are not shown.
pub fn logs(paths: &Paths, follow: bool, out: &mut impl Write) -> Result<()> {
    let mut tails = [LOG_SUPERVISOR, LOG_FRPC].map(|name| Tail {
        name,
        path: paths.log_dir.join(name),
        open: None,
    });
    let mut shown = None;
    let ended = loop {
        let pass = tails
            .iter_mut()
            .try_for_each(|tail| tail.drain(out, &mut shown))
            .and_then(|()| out.flush());
        match pass {
            Err(err) => break Err(err),
            Ok(()) if !follow => break Ok(()),
            // Waiting for new data to appear in a file: there is nothing to be notified by on every OS, so it looks.
            Ok(()) => thread::sleep(POLL),
        }
    };
    match ended {
        // `logs | head`
        Err(err) if err.kind() == ErrorKind::BrokenPipe => Ok(()),
        ended => Ok(ended?),
    }
}

/// One log being read.
struct Tail {
    name: &'static str,
    path: PathBuf,
    /// The file read so far. A rotation renames it, and it stays readable.
    open: Option<Handle>,
}

impl Tail {
    /// Writes what the file has gained. After a rotation, the rest of the old file, then the new one from its start.
    /// `shown` is the name last written under a header.
    fn drain(&mut self, out: &mut impl Write, shown: &mut Option<&'static str>) -> io::Result<()> {
        // Looked at before reading: once the path names another file, the one held gains nothing more.
        let rotated = self
            .open
            .as_ref()
            .is_some_and(|open| Handle::from_path(&self.path).is_ok_and(|now| now != *open));
        if let Some(open) = &mut self.open {
            copy(self.name, open.as_file_mut(), out, shown)?;
        }
        if rotated || self.open.is_none() {
            self.open = match Handle::from_path(&self.path) {
                Ok(handle) => Some(handle),
                Err(err) if err.kind() == ErrorKind::NotFound => None,
                Err(err) => return Err(err),
            };
            if let Some(open) = &mut self.open {
                copy(self.name, open.as_file_mut(), out, shown)?;
            }
        }
        Ok(())
    }
}

fn copy(name: &'static str, file: &mut File, out: &mut impl Write, shown: &mut Option<&'static str>) -> io::Result<()> {
    let mut buf = [0; 8192];
    loop {
        let len = file.read(&mut buf)?;
        if len == 0 {
            return Ok(());
        }
        if *shown != Some(name) {
            writeln!(out, "==> {name} <==")?;
            *shown = Some(name);
        }
        out.write_all(&buf[..len])?;
    }
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
