//! Windows: the processes that run as an account, which `install`'s removal waits for.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use anyhow::{Context, Result};
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    INFINITE, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

use crate::account::Account;
use crate::security::string_of_sid;

/// Waits, with no cap, until no process has `account`'s SID as its token's user: a snapshot of the processes, then a
/// wait on each one that matches, repeated until a snapshot finds none. A process that cannot be opened, or whose token
/// cannot be read, is not waited for: a service's processes are ordinary ones that an administrator can open, and
/// waiting on one that cannot be opened is not possible.
///
/// goetia's `uninstall` returns while the service's processes are still ending (goetia#241), and Windows will not
/// delete the image of a process that runs, or a file that it holds open. Delete this when goetia#241 is fixed.
pub fn wait_until_none_runs_as(account: &Account) -> Result<()> {
    let sid = account.sid();
    loop {
        let running = running_as(&sid).context("listing the processes that run as the service's account")?;
        if running.is_empty() {
            return Ok(());
        }
        wait_for_exit(&running).context("waiting for the service's processes to end")?;
    }
}

/// The processes that run as the user `sid`, as handles that can be waited on.
fn running_as(sid: &str) -> io::Result<Vec<OwnedHandle>> {
    let mut found = Vec::new();
    for pid in process_ids()? {
        // A process that has ended since the snapshot, or one that cannot be opened, is skipped.
        let Some(process) = open(pid) else { continue };
        if user_of(process.as_raw_handle()).is_ok_and(|user| user == sid) {
            found.push(process);
        }
    }
    Ok(found)
}

/// The ids of the processes that run now.
fn process_ids() -> io::Result<Vec<u32>> {
    // SAFETY: a plain call; the handle it returns is closed by `OwnedHandle`.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle that this function owns.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut ids = Vec::new();
    // SAFETY: the handle is live, and `entry` has its size set.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    while more != 0 {
        ids.push(entry.th32ProcessID);
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    let end = io::Error::last_os_error();
    if end.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
        return Err(end);
    }
    Ok(ids)
}

/// The process `pid`, opened to read its token and to wait for it.
fn open(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: a plain call.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
    // SAFETY: a handle that this function owns, unless the call failed.
    (!process.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(process) })
}

/// The SID of the user of `process`'s token, as `S-1-5-...`.
fn user_of(process: HANDLE) -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: `process` is live, and the out pointer is live.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle that this function owns.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    // SAFETY: a size query: no buffer, which the call answers by failing with the size it needs.
    unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    // Words, so that the `TOKEN_USER` in it is aligned.
    let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    // SAFETY: the buffer is `size` bytes at least, and the out pointer is live.
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
    // SAFETY: the call filled the buffer with a `TOKEN_USER`, whose SID points into the buffer, which is live.
    unsafe { string_of_sid((*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid) }
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

/// Throwaway measurement.
pub fn pids_running_as(sid: &str) -> Vec<u32> {
    use windows_sys::Win32::System::Threading::GetProcessId;
    running_as(sid)
        .unwrap()
        .iter()
        .map(|process| unsafe { GetProcessId(process.as_raw_handle()) })
        .collect()
}
