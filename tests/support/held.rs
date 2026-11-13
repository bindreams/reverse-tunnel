//! Windows: a file that nothing can delete while a handle to it is open.

use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

/// Opens the existing `path` without delete sharing, as an antivirus scan does, so that deleting it fails until the
/// returned file drops.
pub fn open_held(path: &Path) -> fs::File {
    const FILE_SHARE_READ: u32 = 1;
    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .unwrap()
}
