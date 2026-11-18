//! frpc's log, which `logs` prints and follows and `status` ends with. Every local account may read it: nothing secret
//! is in it, because frpc.toml holds the tokens as environment placeholders.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, BufRead, BufReader, ErrorKind, Seek, SeekFrom, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

pub const TAIL: usize = 10;

const POLL: Duration = Duration::from_millis(250);

/// The log at `path` opened; `None` if there is no log yet.
pub fn open(path: &Path) -> Result<Option<File>> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("opening {}", path.display())),
    }
}

/// Copies the last `n` lines of `file`, a final line without its newline included, to `out`, and leaves `file` at its
/// end, so `follow` continues from there. One pass over the file keeps the offsets of the last `n` line starts, so a long
/// log is not held in memory.
pub fn tail(file: &mut File, n: usize, out: &mut impl Write) -> io::Result<()> {
    file.seek(SeekFrom::End(0))?;
    if n == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(0))?;
    // Not preallocated by `n`, which may be `usize::MAX`.
    let mut starts = VecDeque::new();
    let mut reader = BufReader::new(&mut *file);
    let (mut at, mut line_starts_here) = (0u64, true);
    loop {
        let block = reader.fill_buf()?;
        if block.is_empty() {
            break;
        }
        for byte in block {
            if line_starts_here {
                if starts.len() == n {
                    starts.pop_front();
                }
                starts.push_back(at);
            }
            line_starts_here = *byte == b'\n';
            at += 1;
        }
        let read = block.len();
        reader.consume(read);
    }
    drop(reader);
    if let Some(first) = starts.front() {
        file.seek(SeekFrom::Start(*first))?;
        io::copy(file, out)?;
    }
    Ok(())
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
                Some(n) => tail(&mut file, n, out)?,
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
    /// Prints what has been appended since the last call, and when the log has been replaced, the rest of the file it
    /// replaced and then the new one. A file that a second rotation moved on meanwhile is not recovered.
    fn poll(&mut self, out: &mut impl Write) -> Result<()> {
        if self.file.is_none() {
            self.file = open(self.path)?;
        }
        let Some(held) = self.file.as_mut() else {
            return Ok(());
        };
        io::copy(held, out)?;
        // Mid-rotation: no log yet; look again next call.
        let Some(mut current) = open(self.path)? else {
            return Ok(());
        };
        if identity(&current)? != identity(held)? {
            // Nothing is written to the old file once the new one exists, so this last read is all of it.
            io::copy(held, out)?;
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
