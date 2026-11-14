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
        .filter(|name| leftovers::is_leftover(name))
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
        aside.len() == 1 && leftovers::is_leftover_of(&aside[0], "x.exe"),
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

    let err = write_atomic(&dest, b"new", Perm::executable(), Replace::Always).unwrap_err();

    assert!(format!("{err:#}").contains("(os error 5)"), "{err:#}");
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

    assert!(is_access_denied(&err), "{err:#}");
    let err = format!("{err:#}");
    assert!(err.contains("moving it to"), "{err}");
    // The replace's answer (access denied) and the rename's (no such path).
    assert!(err.contains("(os error 5)") && err.contains("(os error 3)"), "{err}");
    assert_eq!(fs::read(&dest).unwrap(), old);
    assert_eq!(fs::read_dir(&bin).unwrap().count(), 1);
}

#[test]
fn a_read_only_file_that_windows_refuses_to_replace_is_moved_aside_and_the_leftover_can_be_deleted() {
    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    fs::write(&dest, "old").unwrap();
    let mut readonly = fs::metadata(&dest).unwrap().permissions();
    readonly.set_readonly(true);
    fs::set_permissions(&dest, readonly).unwrap();

    write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(dir.path())).unwrap();

    assert_eq!(fs::read(&dest).unwrap(), b"new");
    let aside = leftovers_in(dir.path());
    assert_eq!(aside.len(), 1, "{aside:?}");
    remove_entry(&dir.path().join(&aside[0])).unwrap();
}

#[test]
fn removing_a_file_leaves_a_directory_at_its_path_alone() {
    let (_dir, bin) = bin();
    let dir = bin.join("x.exe");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("inside"), "").unwrap();

    remove_file(&dir).unwrap_err();

    assert!(dir.join("inside").exists());
}

#[test]
fn a_file_held_open_with_delete_sharing_is_replaced_in_place_and_not_moved_aside() {
    use std::os::windows::fs::OpenOptionsExt;

    let (dir, bin) = bin();
    let dest = bin.join("x.exe");
    fs::write(&dest, "old").unwrap();
    // As an indexer or a scanner opens it.
    let _held = fs::OpenOptions::new().read(true).share_mode(7).open(&dest).unwrap();

    write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(dir.path())).unwrap();

    assert_eq!(fs::read(&dest).unwrap(), b"new");
    assert_eq!(leftovers_in(dir.path()), Vec::<String>::new());
}

#[test]
fn a_file_held_open_without_delete_sharing_is_refused_with_a_sharing_violation() {
    let (_dir, bin) = bin();
    let dest = bin.join("x.txt");
    fs::write(&dest, "old").unwrap();
    let held = held::open_held(&dest);
    let temp = tempfile::NamedTempFile::new_in(&bin).unwrap();

    let refused = persist_over(temp, &dest).unwrap_err();

    assert!(is_sharing_violation(&refused.error), "{}", refused.error);
    drop(held);
    persist_over(refused.file, &dest).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"");
}
