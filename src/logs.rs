//! frpc's log, which `logs` prints and follows and `status` ends with. Every local account may read it: nothing secret
//! is in it, because frpc.toml holds the tokens as environment placeholders.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// How many lines `status` shows.
pub const TAIL: usize = 10;

/// Between two looks at the log, in `follow`.
const POLL: Duration = Duration::from_millis(250);

/// The last `n` lines of `text`, a final line without its newline included.
pub fn last_lines(text: &[u8], n: usize) -> &[u8] {
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

/// The log at `path` opened, and everything in it; `None` if there is no log yet.
pub fn read(path: &Path) -> Result<Option<(File, Vec<u8>)>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("opening {}", path.display())),
    };
    let mut text = Vec::new();
    file.read_to_end(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(Some((file, text)))
}

/// `logs`: prints the log, or its last `lines` lines, then with `follow` every line appended after, until interrupted.
/// A closed output ends it quietly.
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
    let Some((file, text)) = read(path)? else {
        bail!("no log yet: {} does not exist", path.display());
    };
    out.write_all(lines.map_or(&text[..], |n| last_lines(&text, n)))?;
    out.flush()?;
    let mut following = Follower { path, file };
    loop {
        if !follow {
            return Ok(());
        }
        thread::sleep(POLL);
        following.poll(out)?;
    }
}

/// Prints what is appended to a log, across the rotation (`logfile`) that renames the log and starts another.
struct Follower<'a> {
    path: &'a Path,
    /// What has been printed of this file is everything before its position.
    file: File,
}

impl Follower<'_> {
    /// Prints what has been appended since the last call.
    fn poll(&mut self, out: &mut impl Write) -> Result<()> {
        self.drain(out)?;
        // Between the rename and the new file there is none: the next call looks again.
        let current = match File::open(self.path) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => return Err(err).with_context(|| format!("opening {}", self.path.display())),
        };
        if let Some(current) = current
            && identity(&current)? != identity(&self.file)?
        {
            // Nothing is written to the old file once the new one exists, so this last read is all of it.
            self.drain(out)?;
            self.file = current;
            self.drain(out)?;
        }
        out.flush()?;
        Ok(())
    }

    fn drain(&mut self, out: &mut impl Write) -> Result<()> {
        io::copy(&mut self.file, out)?;
        Ok(())
    }
}

/// What tells one file from another, whatever its name: the device and the file's number on it.
#[cfg(unix)]
fn identity(file: &File) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// What tells one file from another, whatever its name: the volume and the file's index on it.
#[cfg(windows)]
fn identity(file: &File) -> Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};

    // SAFETY: `info` is plain data that the call fills, and the handle is open for as long as `file` is.
    let info = unsafe {
        let mut info = std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>();
        if GetFileInformationByHandle(file.as_raw_handle(), &mut info) == 0 {
            return Err(io::Error::last_os_error()).context("reading a file's identity");
        }
        info
    };
    let index = u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow);
    Ok((u64::from(info.dwVolumeSerialNumber), index))
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
