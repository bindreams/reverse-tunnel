//! Fixtures shared by unit tests of several modules.

use std::fs;

use tempfile::TempDir;

use crate::paths::Paths;

pub const CODE: &str = include_str!("../server/testdata/join-code.txt");

/// `code` as a chat client wraps it: lines of 40 characters, indented, with Windows line ends.
pub fn wrapped(code: &str) -> String {
    let lines: Vec<&str> = code
        .as_bytes()
        .chunks(40)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!("  {}\r\n", lines.join("\r\n  "))
}

/// A host's directories in a temp dir, with the config directory made.
pub fn host_dirs() -> (TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir(&paths.config_dir).unwrap();
    (dir, paths)
}
