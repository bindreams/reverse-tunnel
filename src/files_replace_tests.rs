//! What `write_atomic` does on every platform; the Windows-only cases are in `files_tests.rs`.

use super::*;

#[test]
fn replacing_a_file_with_an_or_move_aside_write_leaves_nothing_aside() {
    let root = tempfile::tempdir().unwrap();
    let (bin, aside) = (root.path().join("bin"), root.path().join("aside"));
    fs::create_dir(&bin).unwrap();
    fs::create_dir(&aside).unwrap();
    let dest = bin.join("x");
    fs::write(&dest, "old").unwrap();

    let written = write_atomic(&dest, b"new", Perm::executable(), Replace::OrMoveAside(&aside)).unwrap();

    assert_eq!(written, WriteOutcome::Written);
    assert_eq!(fs::read(&dest).unwrap(), b"new");
    assert_eq!(fs::read_dir(&bin).unwrap().count(), 1);
    assert_eq!(fs::read_dir(&aside).unwrap().count(), 0);
}
