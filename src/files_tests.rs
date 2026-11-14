use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use super::*;
use crate::security::Descriptor;

fn service() -> Account {
    Account::of_service("reverse-tunnel")
}

const ADMINS: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[test]
fn a_directory_others_may_read_is_read_by_everyone() {
    assert_eq!(Perm::new(0o755).sddl(), format!("{ADMINS}(A;OICI;0x1200a9;;;WD)"));
}

#[test]
fn a_directory_closed_to_others_is_read_only_by_its_group() {
    let sid = service().sid();
    assert_eq!(
        Perm::new(0o750).group(service()).sddl(),
        format!("{ADMINS}(A;OICI;0x1200a9;;;{sid})")
    );
}

#[test]
fn a_directory_its_owner_may_write_is_written_by_that_account() {
    let sid = service().sid();
    assert_eq!(
        Perm::new(0o755).owner(service()).group(service()).sddl(),
        format!("{ADMINS}(A;OICI;0x1200a9;;;WD)(A;OICI;0x1301bf;;;{sid})")
    );
}

#[test]
fn a_directory_no_one_else_may_enter_has_only_administrators() {
    assert_eq!(Perm::new(0o700).sddl(), ADMINS);
}

#[test]
fn every_descriptor_is_one_windows_accepts() {
    for perm in [Perm::new(0o755), Perm::new(0o700), Perm::new(0o750).group(service())] {
        Descriptor::parse(&perm.sddl()).unwrap_or_else(|err| panic!("{}: {err}", perm.sddl()));
    }
    Descriptor::parse(OWNED_BY_ADMINISTRATORS).unwrap();
}

#[test]
fn one_account_as_owner_and_group_has_what_the_owner_bits_give_it() {
    let sid = service().sid();
    // The owner may read; the group may also write, but an owner is judged by the owner bits alone, as on Unix.
    assert_eq!(
        Perm::new(0o460).owner(service()).group(service()).sddl(),
        format!("{ADMINS}(A;OICI;0x1200a9;;;{sid})")
    );
}

use crate::held;

/// A `bin` directory in a temp directory that is also the leftover directory.
fn bin() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    (dir, bin)
}

fn leftovers_in(dir: &Path) -> Vec<String> {
    let names = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name());
    names
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| schtasks::is_leftover(name))
        .collect()
}

#[test]
fn a_running_file_is_moved_aside_once_the_new_one_is_written() {
    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    let running = held::running(&dest);
    let old = fs::read(&dest).unwrap();

    let written = write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(dir.path())).unwrap();

    assert_eq!(written, WriteOutcome::Written);
    assert_eq!(fs::read(&dest).unwrap(), b"new");
    let aside = leftovers_in(dir.path());
    assert!(
        aside.len() == 1 && schtasks::is_leftover_of(&aside[0], "x.exe"),
        "{aside:?}"
    );
    assert_eq!(fs::read(dir.path().join(&aside[0])).unwrap(), old);
    drop(running);
}

#[test]
fn a_file_that_does_not_run_is_replaced_in_place() {
    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    fs::write(&dest, "old").unwrap();

    write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(dir.path())).unwrap();

    assert_eq!(fs::read(&dest).unwrap(), b"new");
    assert_eq!(leftovers_in(dir.path()), Vec::<String>::new());
}

#[test]
fn a_running_file_is_not_moved_aside_unless_the_write_says_so() {
    let (_dir, bin) = bin();
    let dest = bin.join("x.exe");
    let _running = held::running(&dest);
    let old = fs::read(&dest).unwrap();

    write_atomic(&dest, b"new", Perm::executable(), Replace::Always).unwrap_err();

    assert_eq!(fs::read(&dest).unwrap(), old);
}

#[test]
fn a_running_file_stays_where_it_is_when_it_cannot_be_moved_aside() {
    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    let _running = held::running(&dest);
    let old = fs::read(&dest).unwrap();

    let err = write_atomic(
        &dest,
        b"new",
        Perm::executable(),
        Replace::OrMoveAside(&dir.path().join("missing")),
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("moving it to"), "{err:#}");
    assert_eq!(fs::read(&dest).unwrap(), old);
    // No temp file is left beside it.
    assert_eq!(fs::read_dir(&bin).unwrap().count(), 1);
}

#[test]
fn a_directory_is_refused_and_not_moved_aside() {
    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("inside"), "").unwrap();

    write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(dir.path())).unwrap_err();

    assert!(dest.join("inside").exists());
    assert_eq!(leftovers_in(dir.path()), Vec::<String>::new());
}

#[test]
fn a_file_that_is_refused_for_another_reason_is_not_moved_aside() {
    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    fs::write(&dest, "old").unwrap();
    let mut readonly = fs::metadata(&dest).unwrap().permissions();
    readonly.set_readonly(true);
    fs::set_permissions(&dest, readonly).unwrap();

    let err = write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(dir.path())).unwrap_err();

    assert!(format!("{err:#}").contains(&dest.display().to_string()), "{err:#}");
    assert_eq!(fs::read(&dest).unwrap(), b"old");
    assert_eq!(leftovers_in(dir.path()), Vec::<String>::new());
}

/// Renames `from` over `to` with POSIX semantics (`FileRenameInfoEx` with `FILE_RENAME_FLAG_REPLACE_IF_EXISTS |
/// FILE_RENAME_FLAG_POSIX_SEMANTICS`), which lets a file that is open elsewhere be replaced and go on being used.
fn posix_rename_over(from: &Path, to: &Path) -> io::Result<()> {
    use std::mem::offset_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{FILE_RENAME_INFO, FileRenameInfoEx, SetFileInformationByHandle};

    const DELETE: u32 = 0x1_0000;
    const SHARE_ALL: u32 = 7;
    const REPLACE_IF_EXISTS_AND_POSIX_SEMANTICS: u32 = 1 | 2;

    let file = OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(SHARE_ALL)
        .open(from)?;
    let name: Vec<u16> = std::path::absolute(to)?.as_os_str().encode_wide().collect();
    let name_at = offset_of!(FILE_RENAME_INFO, FileName);
    let bytes = name_at + name.len() * 2;
    // Eight bytes to a word keeps the header aligned.
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` is aligned for FILE_RENAME_INFO and holds the header and the name after it.
    let renamed = unsafe {
        (*info).Anonymous.Flags = REPLACE_IF_EXISTS_AND_POSIX_SEMANTICS;
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), info.cast::<u8>().add(name_at).cast(), name.len());
        SetFileInformationByHandle(file.as_raw_handle(), FileRenameInfoEx, info.cast(), bytes as u32)
    };
    if renamed == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Measured on 2026-11-14 (build 26100): replacing a running image takes two renames (see `write_atomic`), as even a
/// rename with POSIX semantics is refused. Fails if Windows starts to allow it, when one rename will do and the moment
/// without a file at `dest` can go.
#[test]
fn a_running_image_cannot_be_replaced_in_one_step_even_with_posix_semantics() {
    let (_dir, bin) = bin();
    let dest = bin.join("x.exe");
    let _running = held::running(&dest);
    let new = bin.join("new.exe");
    fs::write(&new, "new").unwrap();
    let plain = bin.join("plain.exe");
    fs::write(&plain, "old").unwrap();
    posix_rename_over(&new, &plain).expect("the same call replaces a file that does not run");
    fs::write(&new, "new").unwrap();

    let err = posix_rename_over(&new, &dest).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err:?}");
}

#[test]
fn only_a_file_held_open_without_delete_sharing_is_refused_for_an_open_file() {
    let (_dir, bin) = bin();
    let denied = || io::Error::from(ErrorKind::PermissionDenied);
    let held = bin.join("held.txt");
    fs::write(&held, "").unwrap();
    let open = held::open_held(&held);
    assert!(is_refused_for_an_open_file(&held, &denied()));
    drop(open);
    assert!(!is_refused_for_an_open_file(&held, &denied()), "closed");

    let running = bin.join("running.exe");
    let _running = held::running(&running);
    assert!(!is_refused_for_an_open_file(&running, &denied()), "a running image");

    let readonly = bin.join("readonly.txt");
    fs::write(&readonly, "").unwrap();
    let mut permissions = fs::metadata(&readonly).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&readonly, permissions).unwrap();
    assert!(!is_refused_for_an_open_file(&readonly, &denied()), "a read-only file");
    assert!(
        !is_refused_for_an_open_file(&held, &io::Error::from_raw_os_error(2)),
        "not found"
    );
}
