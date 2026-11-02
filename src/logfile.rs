use std::ffi::OsString;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result};

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
        if log.size >= log.rotate_at
            && let Err(err) = log.rotate()
        {
            let note = format!("log rotation failed, retrying in {} bytes: {err:#}\n", log.limit);
            log.append(note.as_bytes());
            log.rotate_at = log.size + log.limit;
        }
        log.append(data);
    }

    pub fn line(&self, message: impl Display) {
        self.write(format!("{message}\n").as_bytes());
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
                // `eprintln!` would panic on a closed stderr.
                let _ = writeln!(io::stderr(), "writing {}: {err}", self.path.display());
                // A partial write still counts toward rotation.
                self.size = self.file.metadata().map_or(self.size, |meta| meta.len());
            }
        }
    }

    fn rotate(&mut self) -> Result<()> {
        let mut old = OsString::from(&self.path);
        old.push(".1");
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

fn open(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}
