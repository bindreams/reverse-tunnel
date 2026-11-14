//! Files and directories are created the way an installation needs them: the final mode and owner are set on the open
//! handle before any content exists, whatever the umask.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::fs::DirBuilder;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use anyhow::{Context, Result, ensure};

use crate::account::Account;
use crate::output::eprintln_best_effort;
#[cfg(windows)]
use crate::security::{self, Descriptor, OWNED_BY_ADMINISTRATORS};

/// Mode and owner for a file or directory. `None` leaves the creator as owner or group. Windows files take their
/// directory's ACL, and ignore this; a directory there gets a descriptor made from it (see `make_dir`).
#[derive(Debug, Clone, Copy)]
pub struct Perm {
    pub mode: u32,
    pub owner: Option<Account>,
    pub group: Option<Account>,
}

impl Perm {
    pub const fn new(mode: u32) -> Perm {
        Perm {
            mode,
            owner: None,
            group: None,
        }
    }

    pub const fn owner(self, account: Account) -> Perm {
        Perm {
            owner: Some(account),
            ..self
        }
    }

    pub const fn group(self, account: Account) -> Perm {
        Perm {
            group: Some(account),
            ..self
        }
    }

    /// A binary the installation puts in place. On Unix it is owned by this process's user and group, named explicitly
    /// because a new file's group comes from its directory on macOS.
    pub fn executable() -> Perm {
        let perm = Perm::new(0o755);
        #[cfg(unix)]
        {
            let this_process = Account {
                uid: uzers::get_effective_uid(),
                gid: uzers::get_effective_gid(),
            };
            perm.owner(this_process).group(this_process)
        }
        #[cfg(windows)]
        perm
    }
}

/// What a directory's contents give an account on Windows, for the bits of the mode that are the account's: modify if
/// it may write, else read and execute if it may read.
#[cfg(windows)]
fn rights(bits: u32) -> Option<&'static str> {
    match bits & 0o7 {
        bits if bits & 0o2 != 0 => Some("0x1301bf"),
        bits if bits & 0o4 != 0 => Some("0x1200a9"),
        _ => None,
    }
}

#[cfg(windows)]
impl Perm {
    /// The whole descriptor of a Windows directory with this mode: owned by Administrators, with a protected DACL that
    /// the contents inherit. SYSTEM and Administrators have full control; Everyone reads if the mode lets others; the
    /// owner and the group, accounts here, have what the mode's owner and group bits say (an account that is both has
    /// the owner's).
    pub fn sddl(&self) -> String {
        let mut sddl = format!("{OWNED_BY_ADMINISTRATORS}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let others = rights(self.mode & 0o4).map(|rights| (rights, "WD".to_string()));
        // An account that is both owner and group is the owner, whose bits alone say what it has, as on Unix.
        let mut accounts: Vec<(Account, u32)> = Vec::new();
        for (account, bits) in [(self.owner, self.mode >> 6), (self.group, self.mode >> 3)] {
            let Some(account) = account else { continue };
            if !accounts.iter().any(|(known, _)| *known == account) {
                accounts.push((account, bits));
            }
        }
        let accounts = accounts
            .into_iter()
            .filter_map(|(account, bits)| Some((rights(bits)?, account.sid())));
        for (rights, who) in others.into_iter().chain(accounts) {
            sddl += &format!("(A;OICI;{rights};;;{who})");
        }
        sddl
    }
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
        fchown(
            file,
            perm.owner.map(|account| account.uid),
            perm.group.map(|account| account.gid),
        )?;
        file.set_permissions(Permissions::from_mode(perm.mode))?;
    }
    #[cfg(windows)]
    let _ = (file, perm);
    Ok(())
}

/// Opens `path` and gives it `perm`.
#[cfg(unix)]
fn open_and_apply(path: &Path, perm: Perm) -> Result<()> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    apply(&file, perm).with_context(|| format!("setting the mode and owner of {}", path.display()))
}

/// Gives the existing binary `path` what `write_atomic` with `Perm::executable()` gives a new one. On Unix that is its
/// mode, owner and group. On Windows it is the ACL its directory gives, whatever ACEs it had (its owner stays).
pub fn restore_binary(path: &Path) -> Result<()> {
    #[cfg(unix)]
    return open_and_apply(path, Perm::executable());
    #[cfg(windows)]
    security::inherit_dacl(path).with_context(|| format!("resetting the ACL of {}", path.display()))
}

/// Creates `path` if it is missing (not its parents), then gives it `perm`, whatever it had. A new directory is
/// owner-only until then, so it is never wider than its final mode, whatever the umask. Fails if something else is
/// there, a link to a directory included.
#[cfg(unix)]
pub fn make_dir(path: &Path, perm: Perm) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Err(err) if err.kind() == ErrorKind::AlreadyExists => ensure_directory(path)?,
        Err(err) => return Err(err).with_context(|| format!("creating {}", path.display())),
        Ok(()) => {}
    }
    open_and_apply(path, perm)
}

/// Creates `path` if it is missing (not its parents) with the descriptor `perm.sddl()` makes, so that it is never there
/// with another, then gives it that descriptor, whatever it had: the whole owner and DACL, which replace every ACE
/// there. Fails if something else is there, a link to a directory included, and if a directory that is there is owned
/// by anyone but Administrators or SYSTEM: someone else made it, and could change its ACL.
#[cfg(windows)]
pub fn make_dir(path: &Path, perm: Perm) -> Result<()> {
    let descriptor = Descriptor::parse(&perm.sddl()).with_context(|| format!("describing {}", path.display()))?;
    match descriptor.create_dir(path) {
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            ensure_directory(path)?;
            ensure_trusted_owner(path)?;
        }
        Err(err) => return Err(err).with_context(|| format!("creating {}", path.display())),
        Ok(()) => {}
    }
    descriptor
        .apply(path)
        .with_context(|| format!("setting the owner and ACL of {}", path.display()))
}

/// Windows: makes Administrators the owner of `path`, a file. What an Administrator creates is owned by that user, who
/// could change its ACL, and goetia refuses a host that anyone but Administrators or SYSTEM owns.
#[cfg(windows)]
pub fn own_by_administrators(path: &Path) -> Result<()> {
    Descriptor::parse(OWNED_BY_ADMINISTRATORS)
        .and_then(|descriptor| descriptor.apply(path))
        .with_context(|| format!("making Administrators the owner of {}", path.display()))
}

#[cfg(windows)]
fn ensure_trusted_owner(path: &Path) -> Result<()> {
    let owner = security::owner_of(path).with_context(|| format!("finding the owner of {}", path.display()))?;
    ensure!(
        matches!(owner.as_str(), "S-1-5-32-544" | "S-1-5-18"),
        "refusing to use {}: its owner is {owner}, not Administrators or SYSTEM, so it was not made by an install; \
         delete it and run this again",
        path.display()
    );
    Ok(())
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
///
/// On Windows a process that keeps `path`, or a file in it, open without delete sharing (an antivirus scan, a program
/// that watches files) makes the removal wait until it closes it: the removal is tried again, with no limit, and the
/// first time says on stderr that it waits. Every other failure is an error.
pub fn remove_entry(path: &Path) -> Result<()> {
    let mut said = false;
    loop {
        let removed = match fs::symlink_metadata(path) {
            Ok(entry) if entry.is_dir() => fs::remove_dir_all(path),
            Ok(_) => fs::remove_file(path),
            Err(err) => Err(err),
        };
        match removed {
            Err(err) if is_open_elsewhere(&err) => {
                if !said {
                    eprintln_best_effort(&format!(
                        "{}: another process has it open; waiting until that process closes it",
                        path.display()
                    ));
                    said = true;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) if err.kind() != ErrorKind::NotFound => {
                return Err(err).with_context(|| format!("removing {}", path.display()));
            }
            _ => return Ok(()),
        }
    }
}

/// Whether `err` is Windows refusing to delete a file that another process has open without delete sharing
/// (ERROR_SHARING_VIOLATION). It is no other platform's error: 32 is `EPIPE` on Unix.
fn is_open_elsewhere(err: &std::io::Error) -> bool {
    cfg!(windows) && err.raw_os_error() == Some(32)
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

#[cfg(all(test, windows))]
#[path = "files_tests.rs"]
mod tests;
