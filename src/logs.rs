//! frpc's log, which `logs` prints and follows and `status` ends with. Every local account may read it: nothing secret
//! is in it, because frpc.toml holds the tokens as environment placeholders.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::logfile;

/// How many lines `status` shows.
pub const TAIL: usize = 10;

/// Between two looks at the log, in `follow`.
const POLL: Duration = Duration::from_millis(250);

/// The last `n` lines of `text`, a final line without its newline included.
fn last_lines(text: &[u8], n: usize) -> &[u8] {
    if n == 0 {
        return &[];
    }
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    let mut seen = 0;
    for (at, byte) in body.iter().enumerate().rev() {
        seen += usize::from(*byte == b'\n');
        if seen == n {
            return &text[at + 1..];
        }
    }
    text
}

/// The log at `path` opened; `None` if there is no log yet.
pub fn open(path: &Path) -> Result<Option<File>> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("opening {}", path.display())),
    }
}

/// How much of a log `tail` reads at a time.
const BLOCK: usize = 8 * 1024;

/// The last `n` lines of `file`, a final line without its newline included, read backwards in blocks so that a long
/// log is not read whole. Leaves `file` at the end that the lines were taken to, so lines appended meanwhile are
/// the next read's.
pub fn tail(file: &mut File, n: usize) -> io::Result<Vec<u8>> {
    tail_in_blocks(file, n, BLOCK)
}

fn tail_in_blocks(file: &mut File, n: usize, block: usize) -> io::Result<Vec<u8>> {
    let end = file.metadata()?.len();
    let mut start = end;
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut newlines = 0;
    // The newlines that bound `n` lines: `n`, and the one that ends the file's last line.
    let mut want = n;
    while n > 0 && start > 0 && newlines < want {
        let step = start.min(block as u64);
        start -= step;
        let mut buf = vec![0; step as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buf)?;
        if blocks.is_empty() && buf.last() == Some(&b'\n') {
            want += 1;
        }
        newlines += buf.iter().filter(|byte| **byte == b'\n').count();
        blocks.push(buf);
    }
    file.seek(SeekFrom::Start(end))?;
    let text: Vec<u8> = blocks.into_iter().rev().flatten().collect();
    Ok(last_lines(&text, n).to_vec())
}

/// `logs`: prints the log, or its last `lines` lines, then with `follow` every line appended after, until interrupted.
/// With `follow` and no `lines` it starts with the last `TAIL`, as `tail -f` does, and waits for a log that is not
/// there yet. A closed output ends it quietly.
pub fn show(path: &Path, lines: Option<usize>, follow: bool, out: &mut impl Write) -> Result<()> {
    let ended = stream(path, lines, follow, out);
    match ended {
        Err(err)
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::BrokenPipe) =>
        {
            Ok(())
        }
        ended => ended,
    }
}

fn stream(path: &Path, lines: Option<usize>, follow: bool, out: &mut impl Write) -> Result<()> {
    let mut following = Follower { path, file: None };
    match open(path)? {
        Some(mut file) => {
            match lines.or(follow.then_some(TAIL)) {
                Some(n) => out.write_all(&tail(&mut file, n)?)?,
                None => {
                    io::copy(&mut file, out)?;
                }
            }
            out.flush()?;
            following.file = Some(file);
        }
        None if follow => {}
        None => bail!("no log yet: {} does not exist", path.display()),
    }
    if follow {
        loop {
            thread::sleep(POLL);
            following.poll(out)?;
        }
    }
    Ok(())
}

/// Prints what is appended to a log, across the rotation (`logfile`) that renames the log and starts another.
struct Follower<'a> {
    path: &'a Path,
    /// What has been printed of this file is everything before its position. `None` until the log exists.
    file: Option<File>,
}

impl Follower<'_> {
    /// Prints what has been appended since the last call.
    fn poll(&mut self, out: &mut impl Write) -> Result<()> {
        if self.file.is_none() {
            self.file = open(self.path)?;
        }
        let Some(held) = self.file.as_mut() else {
            return Ok(());
        };
        io::copy(held, out)?;
        // Between the rename and the new file there is none: the next call looks again.
        let Some(mut current) = open(self.path)? else {
            return Ok(());
        };
        if identity(&current)? != identity(held)? {
            // Nothing is written to the old file once the new one exists, so this last read is all of it.
            io::copy(held, out)?;
            // After two rotations since the last call the old file is gone, and `<log>.1` is the file between.
            if let Some(mut between) = open(&logfile::rotated(self.path))?
                && identity(&between)? != identity(held)?
                && identity(&between)? != identity(&current)?
            {
                io::copy(&mut between, out)?;
            }
            io::copy(&mut current, out)?;
            self.file = Some(current);
        }
        out.flush()?;
        Ok(())
    }
}

/// What tells one file from another, whatever its name: the device and the file's number on it.
#[cfg(unix)]
fn identity(file: &File) -> Result<(u64, u128)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), u128::from(meta.ino())))
}

/// What tells one file from another, whatever its name: the volume and the file's 128-bit ID on it (`FileIdInfo`, which
/// ReFS needs: its IDs do not fit the 64 bits of `GetFileInformationByHandle`).
#[cfg(windows)]
fn identity(file: &File) -> Result<(u64, u128)> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx};

    // SAFETY: `info` is plain data that the call fills, of the size passed, and the handle is open as long as `file` is.
    let info = unsafe {
        let mut info = std::mem::zeroed::<FILE_ID_INFO>();
        let size = std::mem::size_of::<FILE_ID_INFO>() as u32;
        if GetFileInformationByHandleEx(file.as_raw_handle(), FileIdInfo, (&raw mut info).cast::<c_void>(), size) == 0 {
            return Err(io::Error::last_os_error()).context("reading a file's identity");
        }
        info
    };
    Ok((info.VolumeSerialNumber, u128::from_le_bytes(info.FileId.Identifier)))
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
