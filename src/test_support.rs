//! Fixtures shared by unit tests of several modules.

use std::fs;
use std::io::{self, Write};

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

/// A writer that records what `note` returns when its first byte arrives: what had happened by then.
pub struct NotesAtFirstWrite<T, F: Fn() -> T> {
    note: F,
    pub text: Vec<u8>,
    pub at_first_write: Option<T>,
}

impl<T, F: Fn() -> T> NotesAtFirstWrite<T, F> {
    pub fn new(note: F) -> Self {
        NotesAtFirstWrite {
            note,
            text: Vec::new(),
            at_first_write: None,
        }
    }
}

impl<T, F: Fn() -> T> Write for NotesAtFirstWrite<T, F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.at_first_write.get_or_insert_with(&self.note);
        self.text.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A writer whose other end is gone: every write fails with `BrokenPipe`.
pub struct Closed;

impl Write for Closed {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
