//! Windows: the processes of a service, which `install`'s removal waits for.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use anyhow::{Context, Result, anyhow};
use windows::core::PCWSTR;
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_EXW, WTS_TYPE_CLASS, WTSEnumerateProcessesExW, WTSFreeMemoryExW,
    WTSTypeProcessInfoLevel0, WTSTypeProcessInfoLevel1,
};
use windows_sys::Win32::System::Threading::{
    INFINITE, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};

use crate::account::Account;
use crate::security::Sid;
use crate::service::ACCOUNT;

/// `WTSEnumerateProcessesExW`'s session id for every session.
const WTS_ANY_SESSION: u32 = 0xFFFF_FFFE;

/// The level of `WTSEnumerateProcessesExW` that lists `WTS_PROCESS_INFO_EXW`.
const LEVEL: u32 = 1;

/// A process of the system's listing.
#[derive(Debug, Clone)]
struct Listed {
    pid: u32,
    /// The name of the image, without its directory.
    image: String,
}

/// Waits, with no cap, until no process runs as `account`, the virtual account of the service: the system lists the
/// processes with their users, and each one of the account is waited for, until a listing finds none. Each round that waits says for which. Only the processes of the account are
/// opened: one that has ended since the listing is gone, one whose id another process took is not ours, and one that
/// cannot be opened or read for any other reason is not ours if a new listing no longer has it, and fails the wait if
/// it does.
///
/// goetia's `uninstall` returns while the service's processes are still ending (goetia#241), and Windows will not
/// delete the image of a process that runs, or a file that it holds open. Delete this when goetia#241 is fixed.
pub fn wait_until_none_runs_as(account: &Account) -> Result<()> {
    let sid = Sid::parse(&account.sid()).context("the service account's SID")?;
    loop {
        let running = running_as(&sid).context("listing the processes of the service's account")?;
        if running.is_empty() {
            return Ok(());
        }
        let (waited_on, handles): (Vec<Listed>, Vec<OwnedHandle>) = open_all(&running, &sid)?.into_iter().unzip();
        if handles.is_empty() {
            continue;
        }
        println!("{}", waiting_line(&waited_on));
        wait_for_exit(&handles).context("waiting for the service's processes to end")?;
    }
}

/// Each of `running` that is `sid`'s, opened to wait for it.
fn open_all(running: &[Listed], sid: &Sid) -> Result<Vec<(Listed, OwnedHandle)>> {
    let mut opened = Vec::new();
    for process in running {
        match open(process, sid) {
            Ok(handle) => opened.extend(handle.map(|handle| (process.clone(), handle))),
            Err(failure) => {
                let listing = running_as(sid).context("listing the processes again after one could not be opened")?;
                println!("{}", skip_if_unlisted(failure, process, &listing)?);
            }
        }
    }
    Ok(opened)
}

/// Whether to go on without `process`, which could not be opened or read (`failure`): its id may be a stranger's that
/// took it since the first listing, so it is skipped if the `listing` made after the failure no longer has it under
/// the service's SID, and the failure stands if it does. A skip is returned as the line that says it.
fn skip_if_unlisted(failure: anyhow::Error, process: &Listed, listing: &[Listed]) -> Result<String> {
    if listing.iter().any(|listed| listed.pid == process.pid) {
        return Err(failure);
    }
    Ok(format!(
        "not waiting for process {} ({}), which is no longer one of the account's: {failure:#}",
        process.pid, process.image
    ))
}

/// What is said before waiting for `processes` of the service's account.
fn waiting_line(processes: &[Listed]) -> String {
    let each: Vec<String> = processes
        .iter()
        .map(|process| format!("{} {}", process.pid, process.image))
        .collect();
    let noun = if processes.len() == 1 { "process" } else { "processes" };
    format!(
        "waiting for {} {noun} of {ACCOUNT} to end: {}",
        processes.len(),
        each.join(", ")
    )
}

/// The processes that run as the user `sid`. The system lists each process's user in one call, and only the
/// processes of `sid` are read further.
fn running_as(sid: &Sid) -> io::Result<Vec<Listed>> {
    let buffer = Buffer::list()?;
    Ok(buffer
        .entries()
        .iter()
        // SAFETY: the user is null or a SID that Windows wrote, which `buffer` keeps.
        .filter(|entry| unsafe { sid.is(entry.pUserSid) })
        .map(|entry| Listed {
            pid: entry.ProcessId,
            // SAFETY: Windows wrote a NUL-terminated name, which `buffer` keeps.
            image: unsafe { image_name(PCWSTR(entry.pProcessName)) },
        })
        .collect())
}

/// The image name `name`. It is for the log line only, so what is not UTF-16 is replaced, not an error.
///
/// # Safety
/// `name` is null or NUL-terminated.
unsafe fn image_name(name: PCWSTR) -> String {
    if name.is_null() {
        return String::new();
    }
    // SAFETY: the caller's promise.
    String::from_utf16_lossy(unsafe { name.as_wide() })
}

/// The class that frees a buffer of `level`; none for a level whose layout is not known.
fn class_of(level: u32) -> Option<WTS_TYPE_CLASS> {
    match level {
        0 => Some(WTSTypeProcessInfoLevel0),
        1 => Some(WTSTypeProcessInfoLevel1),
        _ => None,
    }
}

/// The buffer of `WTSEnumerateProcessesExW`, freed when it drops.
struct Buffer {
    first: *mut u16,
    count: u32,
    /// The class to free it as.
    class: WTS_TYPE_CLASS,
}

impl Buffer {
    fn list() -> io::Result<Buffer> {
        let mut level = LEVEL;
        let mut first = null_mut();
        let mut count = 0;
        // SAFETY: the out pointers are live.
        let listed = unsafe {
            WTSEnumerateProcessesExW(
                WTS_CURRENT_SERVER_HANDLE,
                &mut level,
                WTS_ANY_SESSION,
                &mut first,
                &mut count,
            )
        };
        if listed == 0 {
            return Err(io::Error::last_os_error());
        }
        Buffer::new(first, count, level)
    }

    /// What the enumeration returned. A level that is not the one asked for is an error, and the buffer is freed as the
    /// class of its level, except for a level whose layout is not known: that buffer is leaked, because freeing it as
    /// a layout it does not have risks the heap.
    fn new(first: *mut u16, count: u32, level: u32) -> io::Result<Buffer> {
        let Some(class) = class_of(level) else {
            return Err(io::Error::other(format!(
                "listing the processes gave level {level}, not level {LEVEL}"
            )));
        };
        let buffer = Buffer { first, count, class };
        if level != LEVEL {
            return Err(io::Error::other(format!(
                "listing the processes gave level {level}, not level {LEVEL}"
            )));
        }
        Ok(buffer)
    }

    /// The entries; none if the enumeration returned no buffer or no entries.
    fn entries(&self) -> &[WTS_PROCESS_INFO_EXW] {
        if self.first.is_null() || self.count == 0 {
            return &[];
        }
        // SAFETY: Windows wrote `count` entries at `first`, which `self` keeps until it drops.
        unsafe { std::slice::from_raw_parts(self.first.cast(), self.count as usize) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.first.is_null() {
            // SAFETY: the buffer, its entry count and its class are what the enumeration returned, and it is freed
            // once.
            unsafe { WTSFreeMemoryExW(self.class, self.first.cast(), self.count) };
        }
    }
}

/// `process`, opened to wait for it. None if it has ended since the listing, which Windows answers with "invalid
/// parameter" for an id that no process has, or if it is not `sid`'s: the id is another process's now. Any other
/// failure of the open or of reading its user is an error.
fn open(process: &Listed, sid: &Sid) -> Result<Option<OwnedHandle>> {
    // SAFETY: a plain call.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, process.pid) };
    if handle.is_null() {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(None);
        }
        return Err(anyhow!(
            "opening process {} ({}) to wait for it: {err}",
            process.pid,
            process.image
        ));
    }
    // SAFETY: a handle that this function owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let user = user_of(handle.as_raw_handle())
        .map_err(|err| anyhow!("reading the user of process {} ({}): {err}", process.pid, process.image))?;
    Ok((user == *sid).then_some(handle))
}

/// The user of `process`'s token. `process` is opened with `PROCESS_QUERY_LIMITED_INFORMATION`.
fn user_of(process: HANDLE) -> io::Result<Sid> {
    let mut token = null_mut();
    // SAFETY: the out pointer is live.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle that this function owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    // SAFETY: with no buffer, it only says how large one must be.
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    // Eight bytes to a word keeps `TOKEN_USER` aligned.
    let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
    // SAFETY: `buffer` has room for `size` bytes.
    let read = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Windows wrote a `TOKEN_USER` whose SID points into `buffer`.
    Ok(unsafe { Sid::copy_of((*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid) })
}

/// Waits, with no cap, until every one of `processes` has ended.
fn wait_for_exit(processes: &[OwnedHandle]) -> io::Result<()> {
    for process in processes {
        // SAFETY: a live handle, opened with `SYNCHRONIZE`.
        if unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "processes_tests.rs"]
mod tests;
