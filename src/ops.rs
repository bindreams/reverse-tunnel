//! `start`, `stop`, `status` and `logs`: the service through goetia, and the files in `config_dir` and `log_dir`, which
//! every local user may read. Nothing here reads `secrets_dir`.

use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
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
        // Only a line ended by its newline is whole: `pump` can leave the file cut off mid-line.
        let whole = &text[..text.rfind('\n').map_or(0, |end| end + 1)];
        if let Some(result) = whole.lines().rev().find_map(login_result) {
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

/// Prints `supervisor.log` and `frpc.log`, each under a `==> name <==` line and each preceded by its rotated `.1`, and
/// with `follow` keeps printing what they gain, including across rotations and truncation, until `out` is closed.
/// `frpc.toml` is not shown.
pub fn logs(paths: &Paths, follow: bool, out: &mut impl Write) -> Result<()> {
    let mut tails = [LOG_SUPERVISOR, LOG_FRPC].map(|name| Tail {
        name,
        path: paths.log_dir.join(name),
        open: None,
        done: Vec::new(),
        pending: Vec::new(),
    });
    let mut shown = None;
    let ended = loop {
        let pass = tails
            .iter_mut()
            .try_for_each(|tail| tail.drain(out, &mut shown, !follow))
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
    /// Every file read to its end since the last pass that left a file in `open`: the held file after a rotation and
    /// each `.1` shown. A `.1` among them is not shown again.
    done: Vec<Handle>,
    /// The unterminated last line read so far, held back until its newline arrives.
    pending: Vec<u8>,
}

impl Tail {
    /// Writes the lines the file has gained. At the start, the rotated `.1` comes first. After a rotation, the rest of
    /// the old file, then a `.1` that was not shown yet and is not the new file (more rotations happened since the
    /// last look), then the new file from its start. `shown` is the name last written under a header. With `finish`,
    /// an unterminated last line is written too.
    fn drain(&mut self, out: &mut impl Write, shown: &mut Option<&'static str>, finish: bool) -> io::Result<()> {
        // `.1` is looked at before the current file, so it is never newer than the file the path names. Both are looked
        // at before reading: once the path names another file, the one held gains nothing more.
        let older = open_if_present(&self.path.with_file_name(format!("{}.1", self.name)))?;
        let current = open_if_present(&self.path)?;
        let rotated = matches!((&self.open, &current), (Some(open), Some(now)) if open != now);
        if let Some(open) = &mut self.open {
            copy(
                self.name,
                &mut self.pending,
                open.as_file_mut(),
                out,
                shown,
                finish || rotated,
            )?;
        }
        if rotated || self.open.is_none() {
            self.done.extend(self.open.take());
            if let Some(mut older) = older {
                let seen = self.done.iter().chain(&current).any(|known| *known == older);
                if !seen {
                    copy(self.name, &mut self.pending, older.as_file_mut(), out, shown, true)?;
                    self.done.push(older);
                }
            }
            self.open = current;
            if let Some(open) = &mut self.open {
                copy(self.name, &mut self.pending, open.as_file_mut(), out, shown, finish)?;
                // Only the held file can be `.1` from here on.
                self.done.clear();
            }
        }
        Ok(())
    }
}

fn open_if_present(path: &Path) -> io::Result<Option<Handle>> {
    match Handle::from_path(path) {
        Ok(handle) => Ok(Some(handle)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Writes the complete lines `file` has gained under a header, and holds the rest in `pending`. A file shorter than
/// the read position was truncated: it is read again from its start. With `finish`, `pending` is written as a line.
fn copy(
    name: &'static str,
    pending: &mut Vec<u8>,
    file: &mut File,
    out: &mut impl Write,
    shown: &mut Option<&'static str>,
    finish: bool,
) -> io::Result<()> {
    if file.stream_position()? > file.metadata()?.len() {
        show_pending(name, pending, out, shown)?;
        file.seek(SeekFrom::Start(0))?;
    }
    let mut buf = [0; 8192];
    loop {
        let len = file.read(&mut buf)?;
        if len == 0 {
            break;
        }
        // `pending` holds no newline, so the last one is in what was just read.
        match buf[..len].iter().rposition(|&byte| byte == b'\n') {
            Some(end) => {
                pending.extend_from_slice(&buf[..=end]);
                show(name, pending, out, shown)?;
                pending.clear();
                pending.extend_from_slice(&buf[end + 1..len]);
            }
            None => pending.extend_from_slice(&buf[..len]),
        }
    }
    if finish {
        show_pending(name, pending, out, shown)?;
    }
    Ok(())
}

/// Writes an unterminated line, ended, and forgets it.
fn show_pending(
    name: &'static str,
    pending: &mut Vec<u8>,
    out: &mut impl Write,
    shown: &mut Option<&'static str>,
) -> io::Result<()> {
    if !pending.is_empty() {
        pending.push(b'\n');
        show(name, pending, out, shown)?;
        pending.clear();
    }
    Ok(())
}

fn show(name: &'static str, data: &[u8], out: &mut impl Write, shown: &mut Option<&'static str>) -> io::Result<()> {
    if *shown != Some(name) {
        writeln!(out, "==> {name} <==")?;
        *shown = Some(name);
    }
    out.write_all(data)
}

#[cfg(test)]
#[path = "ops_tests.rs"]
mod tests;
