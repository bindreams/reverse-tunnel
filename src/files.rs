//! Files and directories are created the way an installation needs them: the final mode and owner are set on the open
//! handle before any content exists, whatever the umask.

use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::path::Path;

use anyhow::{Context, Result};

/// Mode and owner for a file or directory. `None` leaves the creator as owner or group. Windows files take their
/// directory's ACL, and ignore this.
#[derive(Debug, Clone, Copy)]
pub struct Perm {
    pub mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Perm {
    pub const fn new(mode: u32) -> Perm {
        Perm {
            mode,
            uid: None,
            gid: None,
        }
    }

    pub const EXECUTABLE: Perm = Perm::new(0o755);
}

/// What `write_atomic` does when `dest` exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replace {
    Always,
    Never,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Written,
    /// `Replace::Never` found `dest` there, and left it alone.
    Existed,
}

/// Gives `file` the owner and mode in `perm`.
pub fn apply(file: &File, perm: Perm) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, fchown};
        // Before the mode: a chown can clear setuid and setgid bits.
        fchown(file, perm.uid, perm.gid)?;
        file.set_permissions(fs::Permissions::from_mode(perm.mode))?;
    }
    #[cfg(windows)]
    let _ = (file, perm);
    Ok(())
}

/// Creates `path` if it is missing (not its parents), then gives it `perm`, whatever it had.
pub fn make_dir(path: &Path, perm: Perm) -> Result<()> {
    match fs::create_dir(path) {
        Err(err) if err.kind() != ErrorKind::AlreadyExists => {
            return Err(err).with_context(|| format!("creating {}", path.display()));
        }
        _ => {}
    }
    let dir = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    apply(&dir, perm).with_context(|| format!("setting the mode and owner of {}", path.display()))
}

/// Creates `path` and the ancestors it lacks with `perm`. Directories that exist are left as they are.
pub fn make_missing_dirs(path: &Path, perm: Perm) -> Result<()> {
    if path.try_exists()? {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        make_missing_dirs(parent, perm)?;
    }
    make_dir(path, perm)
}

/// Writes `data` to `dest` through a temp file in the same directory, which has `perm` before it gets any data, so
/// `dest` is never partial and never briefly readable by others. The data and then the directory are synced.
pub fn write_atomic(dest: &Path, data: &[u8], perm: Perm, replace: Replace) -> Result<WriteOutcome> {
    let dir = dest.parent().expect("dest is inside a directory");
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;
    apply(file.as_file(), perm)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    let persisted = match replace {
        Replace::Always => file.persist(dest),
        Replace::Never => file.persist_noclobber(dest),
    };
    match persisted {
        Err(err) if replace == Replace::Never && err.error.kind() == ErrorKind::AlreadyExists => {
            return Ok(WriteOutcome::Existed);
        }
        Err(err) => return Err(err).with_context(|| format!("writing {}", dest.display())),
        Ok(_) => {}
    }
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok(WriteOutcome::Written)
}
