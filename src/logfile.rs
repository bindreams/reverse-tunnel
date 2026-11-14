use std::ffi::OsString;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use anyhow::{Context, Result};
use jiff::fmt::strtime;
use jiff::tz::TimeZone;
use jiff::{Unit, Zoned};

use crate::output::eprintln_best_effort;

/// What a rotated log's name ends with.
pub const ROTATED: &str = ".1";

/// The size at which a log is rotated.
pub const ROTATE_AT: u64 = 10 * 1024 * 1024;

/// An append-only log file shared between tasks. At `limit` bytes it becomes `<name>.1`, replacing the previous one,
/// so a log occupies at most two files.
#[derive(Clone)]
pub struct LogFile(Arc<Mutex<Active>>);

struct Active {
    path: PathBuf,
    file: File,
    size: u64,
    limit: u64,
    /// The size at which the next rotation is tried: `limit`, or `limit` bytes past the size at a failed one.
    rotate_at: u64,
}

impl LogFile {
    pub fn open(path: PathBuf, limit: u64) -> Result<LogFile> {
        let file = open(&path)?;
        let size = file.metadata()?.len();
        Ok(LogFile(Arc::new(Mutex::new(Active {
            path,
            file,
            size,
            limit,
            rotate_at: limit,
        }))))
    }

    /// Appends `data`. A write that fails is reported on stderr, which the service manager keeps, and dropped, so a
    /// full disk cannot stop what is being logged.
    pub fn write(&self, data: &[u8]) {
        let mut log = self.lock();
        log.rotate_if_due();
        log.append(data);
    }

    /// Appends `message` as a line stamped with the local time (see `now`).
    pub fn line(&self, message: impl Display) {
        let mut log = self.lock();
        log.rotate_if_due();
        // Read under the lock, so stamps never go backwards in the file.
        let line = format!("{} {message}\n", now());
        log.append(line.as_bytes());
    }

    /// A panic in another thread must not stop logging.
    fn lock(&self) -> MutexGuard<'_, Active> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Active {
    fn append(&mut self, data: &[u8]) {
        match self.file.write_all(data) {
            Ok(()) => self.size += data.len() as u64,
            Err(err) => {
                eprintln_best_effort(&format!("writing {}: {err}", self.path.display()));
                // A partial write still counts toward rotation.
                self.size = self.file.metadata().map_or(self.size, |meta| meta.len());
            }
        }
    }

    fn rotate_if_due(&mut self) {
        if self.size >= self.rotate_at
            && let Err(err) = self.rotate()
        {
            let note = format!(
                "{} log rotation failed, retrying in {} bytes: {err:#}\n",
                now(),
                self.limit
            );
            self.append(note.as_bytes());
            self.rotate_at = self.size + self.limit;
        }
    }

    fn rotate(&mut self) -> Result<()> {
        let mut old = OsString::from(&self.path);
        old.push(ROTATED);
        // A missing log was already renamed by a rotation that then failed to open the new one.
        match fs::rename(&self.path, &old) {
            Err(err) if err.kind() != ErrorKind::NotFound => {
                return Err(err).with_context(|| format!("renaming {}", self.path.display()));
            }
            _ => {}
        }
        self.file = open(&self.path)?;
        self.size = 0;
        self.rotate_at = self.limit;
        Ok(())
    }
}

/// Opens `path` for appending, created if missing. A new file gets mode 0644 less the umask.
fn open(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o644);
    options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// The local time and its UTC offset in whole minutes, e.g. `2026-11-02T21:04:05+01:00`; `1970-01-01T00:00:00+00:00`
/// if the clock or the zone cannot be read.
fn now() -> String {
    stamp().unwrap_or_else(|_| "1970-01-01T00:00:00+00:00".to_string())
}

fn stamp() -> Result<String, jiff::Error> {
    let zoned = Zoned::try_from(SystemTime::now())?;
    let offset = zoned.offset().round(Unit::Minute)?;
    strtime::format("%Y-%m-%dT%H:%M:%S%:z", &zoned.with_time_zone(TimeZone::fixed(offset)))
}

#[cfg(test)]
#[path = "logfile_tests.rs"]
mod tests;
