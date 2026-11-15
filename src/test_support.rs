//! Fixtures shared by unit tests of several modules.

use std::fs;
use std::io::{self, Write};

use goetia::manager::fake::Fake;
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

/// A writer that notes how many calls the fake manager had received when the first byte was written, to show that
/// something was printed before a call.
pub struct NotesCalls<'a> {
    manager: &'a Fake,
    pub text: Vec<u8>,
    pub calls_at_first_write: Option<usize>,
}

impl<'a> NotesCalls<'a> {
    pub fn new(manager: &'a Fake) -> Self {
        NotesCalls {
            manager,
            text: Vec::new(),
            calls_at_first_write: None,
        }
    }
}

impl Write for NotesCalls<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls_at_first_write
            .get_or_insert_with(|| self.manager.calls().len());
        self.text.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
