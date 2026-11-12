//! Files and directories are created the way an installation needs them: the final mode and owner are set on the open
//! handle before any content exists, whatever the umask.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use anyhow::{Context, Result, ensure};

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

    pub const fn uid(self, uid: u32) -> Perm {
        Perm { uid: Some(uid), ..self }
    }

    pub const fn gid(self, gid: u32) -> Perm {
        Perm { gid: Some(gid), ..self }
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
        use std::fs::Permissions;
        use std::os::unix::fs::{PermissionsExt, fchown};
        // Before the mode: a chown can clear setuid and setgid bits.
        fchown(file, perm.uid, perm.gid)?;
        file.set_permissions(Permissions::from_mode(perm.mode))?;
    }
    #[cfg(windows)]
    let _ = (file, perm);
    Ok(())
}

/// Creates `path` if it is missing (not its parents), then gives it `perm`, whatever it had. A new directory is
/// owner-only until then, so it is never wider than its final mode, whatever the umask. Fails if something else is
/// there, a link to a directory included.
pub fn make_dir(path: &Path, perm: Perm) -> Result<()> {
    #[cfg(unix)]
    let builder = {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = DirBuilder::new();
    match builder.create(path) {
        Err(err) if err.kind() == ErrorKind::AlreadyExists => ensure_directory(path)?,
        Err(err) => return Err(err).with_context(|| format!("creating {}", path.display())),
        Ok(()) => {}
    }
    let dir = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    apply(&dir, perm).with_context(|| format!("setting the mode and owner of {}", path.display()))
}

/// Fails unless `path` is a directory itself, not a link to one.
fn ensure_directory(path: &Path) -> Result<()> {
    let entry = fs::symlink_metadata(path).with_context(|| format!("looking at {}", path.display()))?;
    ensure!(entry.is_dir(), "{} is not a directory", path.display());
    Ok(())
}

/// Opens `path` for writing and gives it `perm`; a missing file is created owner-only first, like `make_dir`'s. With
/// `exclusive`, anything already at `path`, a symlink included, is an error: it is never followed.
pub fn open_file(path: &Path, perm: Perm, exclusive: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).create_new(exclusive);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    apply(&file, perm).with_context(|| format!("setting the mode and owner of {}", path.display()))?;
    Ok(file)
}

/// Creates `path` and the ancestors it lacks with `perm`. Directories that exist are left as they are; anything else
/// there is an error.
pub fn make_missing_dirs(path: &Path, perm: Perm) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return ensure_directory(path),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("looking at {}", path.display())),
    }
    if let Some(parent) = path.parent() {
        make_missing_dirs(parent, perm)?;
    }
    make_dir(path, perm)
}

/// Removes `path`, a directory with its contents, unless it is already gone. A link is removed, not followed.
pub fn remove_entry(path: &Path) -> Result<()> {
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
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing {}", dir.display()))?;
    Ok(WriteOutcome::Written)
}
