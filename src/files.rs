//! Files and directories are created the way an installation needs them: the final mode and owner are set on the open
//! handle before any content exists, whatever the umask.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
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
use crate::schtasks;
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
pub enum Replace<'a> {
    Always,
    Never,
    /// Like `Always`, and on Windows a `dest` that Windows refuses to overwrite (access denied) and lets be renamed is
    /// renamed into this directory as a leftover (see `move_aside`) first. On Unix it is replaced like any other.
    OrMoveAside(&'a Path),
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
/// first time says on stderr that it waits (see `OpenElsewhere`). Every other failure is an error.
pub fn remove_entry(path: &Path) -> Result<()> {
    remove_waiting(path, true)
}

/// Removes the file or link `path`, unless it is already gone, and waits like `remove_entry`. Never a directory: one at
/// `path`, even one that replaced a file a moment ago, is an error and is left as it is.
pub fn remove_file(path: &Path) -> Result<()> {
    remove_waiting(path, false)
}

fn remove_waiting(path: &Path, directories_too: bool) -> Result<()> {
    let mut wait = OpenElsewhere::default();
    loop {
        let removed = if directories_too {
            match fs::symlink_metadata(path) {
                Ok(entry) if entry.is_dir() => fs::remove_dir_all(path),
                Ok(_) => fs::remove_file(path),
                Err(err) => Err(err),
            }
        } else {
            fs::remove_file(path)
        };
        match removed {
            Err(err) if wait.waited_for(path, &err) => {}
            Err(err) if err.kind() != ErrorKind::NotFound => {
                return Err(err).with_context(|| format!("removing {}", path.display()));
            }
            _ => return Ok(()),
        }
    }
}

/// Whether `err`, or the `io::Error` it wraps, is the OS refusing an operation for lack of access.
pub fn is_access_denied(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>()
        .is_some_and(|err| err.kind() == ErrorKind::PermissionDenied)
}

/// Windows: `Err` naming `path` unless it is a regular file, not a directory, junction or link (a link is not
/// followed); `otherwise` says what is then not done, in "... is not a regular file, so it is `otherwise`". A `path`
/// that cannot be looked at is an error too.
#[cfg(windows)]
pub fn require_regular_file(path: &Path, otherwise: &str) -> Result<()> {
    let entry = fs::symlink_metadata(path).with_context(|| format!("looking at {}", path.display()))?;
    ensure!(
        entry.is_file(),
        "{} is not a regular file, so it is {otherwise}",
        path.display()
    );
    Ok(())
}

/// What follows the path in the line that says a wait (see `OpenElsewhere`).
pub const OPEN_ELSEWHERE_LINE: &str = ": another process has it open; waiting until that process closes it";

/// The wait that every delete, replace and move of a file shares. Windows refuses to delete, replace or rename a file
/// that another process has open without delete sharing (an antivirus scan, a program that watches files); the
/// operation is tried again, with no limit, until that process closes it. Every other failure is the caller's. The first
/// wait is said on stderr.
#[derive(Default)]
struct OpenElsewhere {
    said: bool,
}

impl OpenElsewhere {
    /// Whether `err`, the failure of an operation on `path`, is that refusal. If it is, this has waited, and the
    /// operation is to be tried again.
    fn waited_for(&mut self, path: &Path, err: &io::Error) -> bool {
        if !is_refused_for_an_open_file(path, err) {
            return false;
        }
        if !self.said {
            eprintln_best_effort(&format!("{}{OPEN_ELSEWHERE_LINE}", path.display()));
            self.said = true;
        }
        thread::sleep(Duration::from_millis(50));
        true
    }
}

/// Whether `err`, the failure of an operation on `path`, is Windows refusing it because another process has `path` open
/// without delete sharing: ERROR_SHARING_VIOLATION (32), which a delete and a rename give. A replace gives "access
/// denied", as it does for a running image, a read-only file and an ACL that forbids it; asking to open `path` with
/// delete access, which only the first of them refuses with 32, says which it is. Nothing else is that refusal, and
/// 32 is `EPIPE` on Unix.
#[cfg(windows)]
fn is_refused_for_an_open_file(path: &Path, err: &io::Error) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x1_0000;
    const SHARE_ALL: u32 = 7;
    const SHARING_VIOLATION: i32 = 32;
    match err.raw_os_error() {
        Some(SHARING_VIOLATION) => true,
        _ if err.kind() == ErrorKind::PermissionDenied => OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(SHARE_ALL)
            .open(path)
            .is_err_and(|opened| opened.raw_os_error() == Some(SHARING_VIOLATION)),
        _ => false,
    }
}

#[cfg(not(windows))]
fn is_refused_for_an_open_file(_path: &Path, _err: &io::Error) -> bool {
    false
}

/// Writes `data` to `dest` through a temp file in the same directory, which has `perm` before it gets any data, so
/// `dest` is never partial and never briefly readable by others. The data and then the directory are synced. A `dest`
/// that another process holds open waits until it is closed (see `OpenElsewhere`).
///
/// With `Replace::OrMoveAside`, a replace that Windows refuses with access denied, and not because another process has
/// `dest` open (that waits, as above), is answered by moving the old `dest` aside (see `persist_over_refused`) once the
/// new one is written and synced; the old one is put back if the new one cannot be put in its place. A refused move is
/// an error that names the refused replace and the refused move.
pub fn write_atomic(dest: &Path, data: &[u8], perm: Perm, replace: Replace) -> Result<WriteOutcome> {
    let dir = dest.parent().expect("dest is inside a directory");
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;
    apply(file.as_file(), perm)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    match (replace, persist_waiting(file, dest, replace == Replace::Never)) {
        (Replace::Never, Err(err)) if err.error.kind() == ErrorKind::AlreadyExists => {
            return Ok(WriteOutcome::Existed);
        }
        #[cfg(windows)]
        (Replace::OrMoveAside(leftovers), Err(err)) if err.error.kind() == ErrorKind::PermissionDenied => {
            persist_over_refused(err.file, dest, leftovers, err.error)?;
            return Ok(WriteOutcome::Written);
        }
        (_, Err(err)) => return Err(err).with_context(|| format!("writing {}", dest.display())),
        (_, Ok(())) => {}
    }
    #[cfg(unix)]
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing {}", dir.display()))?;
    Ok(WriteOutcome::Written)
}

/// Puts `file` at `dest`, replacing what is there unless `keep_existing`, once no other process holds `dest` open (see
/// `OpenElsewhere`).
fn persist_waiting(
    mut file: tempfile::NamedTempFile,
    dest: &Path,
    keep_existing: bool,
) -> Result<(), tempfile::PersistError> {
    let mut wait = OpenElsewhere::default();
    loop {
        let persisted = if keep_existing {
            file.persist_noclobber(dest)
        } else {
            file.persist(dest)
        };
        match persisted {
            Err(err) if wait.waited_for(dest, &err.error) => file = err.file,
            done => return done.map(drop),
        }
    }
}

/// Windows: moves the file `dest`, which Windows refused to replace with `refused`, into `leftovers` and puts `file` in
/// its place. If that fails, `dest` is put back. Between the two renames there is no file at `dest`, so it is only for a
/// file that no service start needs, like the binary on the `PATH`. Two renames, because Windows refuses to replace or
/// delete a running image even with a POSIX-semantics rename (error 5), and allows renaming it. A refused move is an
/// error that has both answers.
#[cfg(windows)]
fn persist_over_refused(
    file: tempfile::NamedTempFile,
    dest: &Path,
    leftovers: &Path,
    refused: io::Error,
) -> Result<()> {
    let writing = || format!("writing {}", dest.display());
    let aside = move_aside(dest, leftovers).map_err(|moving| {
        anyhow::anyhow!(
            "{}: replacing it was refused ({refused}); moving it aside failed too: {moving:#}",
            writing()
        )
    })?;
    let Err(err) = persist_waiting(file, dest, false) else {
        return Ok(());
    };
    let failure = anyhow::anyhow!(err.error).context(writing());
    match fs::rename(&aside, dest) {
        Ok(()) => Err(failure),
        Err(back) => Err(failure.context(format!(
            "putting {} back from {} failed too: {back}",
            dest.display(),
            aside.display()
        ))),
    }
}

/// Windows: renames the file `path` into `leftovers`, keeping its name (see `schtasks::leftover_name`), and returns the
/// new path. Windows refuses to delete a running image, and lets it be renamed. A file there is deleted once it can be:
/// by the next `install` or `upgrade`, or by a removal. Only a regular file is moved aside, since only a file is an
/// image and the leftover sweeps never delete anything else: any other `path` is an error naming it, and nothing is
/// moved. A `path` that another process holds open waits (see `OpenElsewhere`).
#[cfg(windows)]
pub fn move_aside(path: &Path, leftovers: &Path) -> Result<std::path::PathBuf> {
    require_regular_file(path, "not moved aside")?;
    let original = path.file_name().context("the file has no name")?;
    let to = leftovers.join(schtasks::leftover_name(&hex_of_random_bytes::<16>()?, original));
    let mut wait = OpenElsewhere::default();
    while let Err(err) = fs::rename(path, &to) {
        if !wait.waited_for(path, &err) {
            return Err(err).with_context(|| format!("moving it to {}", to.display()));
        }
    }
    Ok(to)
}

/// The hex digits of `N` random bytes from the OS.
pub fn hex_of_random_bytes<const N: usize>() -> Result<String> {
    let mut random = [0u8; N];
    getrandom::fill(&mut random).context("reading random bytes from the OS")?;
    Ok(hex::encode(random))
}

#[cfg(all(test, windows))]
#[path = "files_tests.rs"]
mod tests;
