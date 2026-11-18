//! frpc's log, which `logs` prints and follows and `status` ends with. Every local account may read it: nothing secret
//! is in it, because frpc.toml holds the tokens as environment placeholders.

use std::fs::File;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
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

/// Copies the last `n` lines of `file`, a final line without its newline included, to `out`, and leaves `file` where
/// they end, so `follow` continues from there with what was appended meanwhile. Two passes keep memory constant: the
/// first counts the lines and fixes the end; the second, which reads no further than that end, finds where the last `n`
/// start.
pub fn tail(file: &mut File, n: usize, out: &mut impl Write) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(&mut *file);
    let (mut newlines, mut end, mut last) = (0usize, 0u64, b'\n');
    loop {
        let block = reader.fill_buf()?;
        let Some(&final_byte) = block.last() else { break };
        newlines += block.iter().filter(|byte| **byte == b'\n').count();
        (last, end) = (final_byte, end + block.len() as u64);
        let len = block.len();
        reader.consume(len);
    }
    let mut skip = (newlines + usize::from(last != b'\n')).saturating_sub(n);
    drop(reader);
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(Read::by_ref(file).take(end));
    let mut start = 0u64;
    while skip > 0 {
        let block = reader.fill_buf()?;
        // At `end`, or before it if the log was truncated meanwhile.
        if block.is_empty() {
            break;
        }
        let mut taken = block.len();
        for (at, _) in block.iter().enumerate().filter(|(_, byte)| **byte == b'\n') {
            skip -= 1;
            if skip == 0 {
                taken = at + 1;
                break;
            }
        }
        start += taken as u64;
        reader.consume(taken);
    }
    drop(reader);
    file.seek(SeekFrom::Start(start))?;
    io::copy(&mut Read::by_ref(file).take(end - start), out)?;
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
    /// Prints what has been appended since the last call; after a replacement, the rest of the old file, then the new one.
    /// Lines that reached only a file it never held are not shown, as with `tail -F`.
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
