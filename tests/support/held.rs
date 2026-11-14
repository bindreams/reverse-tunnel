//! Windows: files that nothing can delete.

use std::env;
use std::fs;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

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

/// A process that runs the image `path`, a copy of `cmd.exe`, until it drops: Windows will not delete a running image
/// (access denied), and will rename it.
pub struct Running(Child);

pub fn running(path: &Path) -> Running {
    let cmd = Path::new(&env::var("SystemRoot").unwrap())
        .join("System32")
        .join("cmd.exe");
    fs::copy(cmd, path).unwrap();
    // Waits for input, which the pipe gives it when it is killed.
    let child = Command::new(path)
        .args(["/c", "set /p x="])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    Running(child)
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
