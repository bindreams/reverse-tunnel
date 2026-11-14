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
#[cfg(windows)]
use crate::leftovers;
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
pub enum Replace<'a> {
    Always,
    Never,
    /// Like `Always`, and on Windows a `dest` that Windows refuses to overwrite (access denied) and lets be renamed is
    /// renamed into this directory as a leftover (see `leftovers`) first. On Unix it is replaced like any other.
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
    remove_waiting(path, |path| match fs::symlink_metadata(path) {
        Ok(entry) if entry.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(err) => Err(err),
    })
}

/// Removes the file or link `path`, unless it is already gone, and waits like `remove_entry`. Never a directory: one at
/// `path`, even one that replaced a file a moment ago, is an error and is left as it is.
pub fn remove_file(path: &Path) -> Result<()> {
    remove_waiting(path, |path| fs::remove_file(path))
}

fn remove_waiting(path: &Path, remove: impl Fn(&Path) -> io::Result<()>) -> Result<()> {
    let mut wait = OpenElsewhere::default();
    loop {
        match remove(path) {
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
    has_kind(err, ErrorKind::PermissionDenied)
}

/// Whether `err`, or the `io::Error` it wraps, is the OS saying that the path is not there.
#[cfg(windows)]
pub fn is_not_found(err: &anyhow::Error) -> bool {
    has_kind(err, ErrorKind::NotFound)
}

fn has_kind(err: &anyhow::Error, kind: ErrorKind) -> bool {
    err.downcast_ref::<io::Error>().is_some_and(|err| err.kind() == kind)
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
pub(crate) struct OpenElsewhere {
    said: bool,
}

impl OpenElsewhere {
    /// Whether `err`, the failure of an operation on `path`, is that refusal. If it is, this has waited, and the
    /// operation is to be tried again.
    pub(crate) fn waited_for(&mut self, path: &Path, err: &io::Error) -> bool {
        if !is_sharing_violation(err) {
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

/// Whether `err` is ERROR_SHARING_VIOLATION (32): another process has the file open without delete sharing, which a
/// delete, a rename and a replace (see `rename_over`) all give. Not `EPIPE`, which is 32 on Unix.
fn is_sharing_violation(err: &io::Error) -> bool {
    cfg!(windows) && err.raw_os_error() == Some(32)
}

/// Writes `data` to `dest` through a temp file in the same directory, which has `perm` before it gets any data, so
/// `dest` is never partial and never briefly readable by others. A `dest` that another process holds open waits until
/// it is closed (see `OpenElsewhere`).
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
        (Replace::OrMoveAside(leftovers_dir), Err(err)) if err.error.kind() == ErrorKind::PermissionDenied => {
            persist_over_refused(err.file, dest, leftovers_dir, err.error)?;
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
            file.persist_noclobber(dest).map(drop)
        } else {
            persist_over(file, dest)
        };
        match persisted {
            Err(err) if wait.waited_for(dest, &err.error) => file = err.file,
            done => return done,
        }
    }
}

/// Puts `file` at `dest`, replacing what is there.
#[cfg(not(windows))]
fn persist_over(file: tempfile::NamedTempFile, dest: &Path) -> Result<(), tempfile::PersistError> {
    file.persist(dest).map(drop)
}

/// Puts `file` at `dest`, replacing what is there, by `rename_over`.
#[cfg(windows)]
fn persist_over(mut file: tempfile::NamedTempFile, dest: &Path) -> Result<(), tempfile::PersistError> {
    match rename_over(file.as_file(), file.path(), dest) {
        Ok(()) => {
            // The temp file's name is gone: `file` must not delete whatever is at it later.
            file.disable_cleanup(true);
            Ok(())
        }
        Err(error) => Err(tempfile::PersistError { error, file }),
    }
}

/// Windows: renames `from`, which `file` has open, to `to`, replacing `to` as a POSIX rename does: a `to` that another
/// process has open with delete sharing (an indexer, a scanner) does not stop it, where `MoveFileExW` would be refused.
/// A `to` that is open without delete sharing gives ERROR_SHARING_VIOLATION (see `OpenElsewhere`), and one that is a
/// running image, or that the ACL or the read-only attribute protects, gives access denied.
#[cfg(windows)]
fn rename_over(file: &File, from: &Path, to: &Path) -> io::Result<()> {
    use std::ffi::c_void;
    use std::mem::offset_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FileRenameInfoEx, ReOpenFile, SYNCHRONIZE, SetFileAttributesW, SetFileInformationByHandle,
    };
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;

    // Like `tempfile`'s own persist: the file is no longer a temporary one.
    let wide_from = security::wide(from);
    // SAFETY: `wide_from` is NUL-terminated and outlives the call.
    if unsafe { SetFileAttributesW(wide_from.as_ptr(), FILE_ATTRIBUTE_NORMAL) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // A rename needs DELETE access, which the temp file's handle does not have, and the handle's sharing allows.
    // SAFETY: `file` is an open handle.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle() as HANDLE,
            DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `handle` is a handle this call owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as _) };

    // The system reads the name up to a terminator that `FileNameLength` does not count.
    let to = security::wide(&std::path::absolute(to)?);
    let name_bytes = (to.len() - 1) * size_of::<u16>();
    let size = offset_of!(FILE_RENAME_INFO, FileName) + to.len() * size_of::<u16>();
    // The struct ends in the name; a `u64` buffer is aligned for it.
    let mut buffer = vec![
        0u64;
        size.div_ceil(size_of::<u64>())
            .max(size_of::<FILE_RENAME_INFO>().div_ceil(size_of::<u64>()))
    ];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` holds a `FILE_RENAME_INFO` and, after `FileName`, the name and its terminator.
    unsafe {
        (*info).Anonymous.Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*info).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(to.as_ptr(), (*info).FileName.as_mut_ptr(), to.len());
    }
    // SAFETY: `info` points to `size` bytes that `FileRenameInfoEx` takes, and `handle` is open.
    let renamed = unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle() as HANDLE,
            FileRenameInfoEx,
            info as *const c_void,
            size as u32,
        )
    };
    if renamed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Windows: moves the file `dest`, which Windows refused to replace with `refused`, into `leftovers_dir` (see
/// `leftovers`) and puts `file` in its place. If that fails, `dest` is put back. Between the two renames there is no
/// file at `dest`, so it is only for a file that no service start needs, like the binary on the `PATH`. Two renames,
/// because Windows refuses to replace or delete a running image even with a POSIX-semantics rename (error 5), and
/// allows renaming it.
#[cfg(windows)]
fn persist_over_refused(
    file: tempfile::NamedTempFile,
    dest: &Path,
    leftovers_dir: &Path,
    refused: io::Error,
) -> Result<()> {
    let writing = || format!("writing {}", dest.display());
    let aside = leftovers::move_aside(dest, leftovers_dir)
        .map_err(|moving| leftovers::refused_and_not_moved(anyhow::Error::new(refused).context(writing()), &moving))?;
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

/// The hex digits of `N` random bytes from the OS.
pub fn hex_of_random_bytes<const N: usize>() -> Result<String> {
    let mut random = [0u8; N];
    getrandom::fill(&mut random).context("reading random bytes from the OS")?;
    Ok(hex::encode(random))
}

#[cfg(test)]
#[path = "files_replace_tests.rs"]
mod replace_tests;

#[cfg(all(test, windows))]
#[path = "files_tests.rs"]
mod tests;
