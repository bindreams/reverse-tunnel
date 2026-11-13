//! Windows: the processes of a service, which `install`'s removal waits for.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use anyhow::{Context, Result, anyhow};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_OBJECT_0};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_PROCESS_INFO_EXW, WTSEnumerateProcessesExW, WTSFreeMemoryExW,
    WTSTypeProcessInfoLevel1,
};
use windows_sys::Win32::System::Threading::{INFINITE, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};

use crate::account::Account;
use crate::security::string_of_sid;

/// `WTSEnumerateProcessesExW`'s session id for every session.
const WTS_ANY_SESSION: u32 = 0xFFFF_FFFE;

/// A process of the system's listing.
#[derive(Debug, Clone)]
struct Listed {
    pid: u32,
    /// The name of the image, without its directory.
    image: String,
    /// The SID of its token's user, as `S-1-5-...`; none for the few processes that have no user.
    sid: Option<String>,
}

/// Waits, with no cap, until no process runs as the virtual account of the service `service` (`NT SERVICE\<service>`):
/// the system lists the processes with their users, and each one of the account is waited for, until a listing finds
/// none. Each round that finds some says which. Nothing is opened but the processes of the account: one that has ended
/// since the listing is gone, and one that cannot be opened for any other reason fails the wait.
///
/// goetia's `uninstall` returns while the service's processes are still ending (goetia#241), and Windows will not
/// delete the image of a process that runs, or a file that it holds open. Delete this when goetia#241 is fixed.
pub fn wait_until_none_runs_as_service(service: &str) -> Result<()> {
    let sid = Account::of_service(service).sid();
    let name = format!(r"NT SERVICE\{service}");
    loop {
        let running = running_as(&sid).context("listing the processes of the service's account")?;
        if running.is_empty() {
            return Ok(());
        }
        println!("{}", waiting_line(&name, &running));
        let mut handles = Vec::new();
        for process in &running {
            handles.extend(open(process)?);
        }
        wait_for_exit(&handles).context("waiting for the service's processes to end")?;
    }
}

/// What is said before waiting for `processes` of the account `name`.
fn waiting_line(name: &str, processes: &[Listed]) -> String {
    let each: Vec<String> = processes
        .iter()
        .map(|process| format!("{} {}", process.pid, process.image))
        .collect();
    format!(
        "waiting for {} processes of {name} to end: {}",
        processes.len(),
        each.join(", ")
    )
}

/// The processes that run as the user `sid`.
fn running_as(sid: &str) -> io::Result<Vec<Listed>> {
    let mut processes = list()?;
    processes.retain(|process| process.sid.as_deref() == Some(sid));
    Ok(processes)
}

/// Every process of the system, with its user, in one call: no process is opened to read it.
fn list() -> io::Result<Vec<Listed>> {
    let mut level = 1;
    let mut first = null_mut();
    let mut count = 0;
    // SAFETY: the out pointers are live; level 1 makes the buffer `WTS_PROCESS_INFO_EXW` entries.
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
    let buffer = Buffer { first, count };
    // SAFETY: Windows wrote `count` entries at `first`, which `buffer` keeps until it drops.
    let entries = unsafe { std::slice::from_raw_parts(buffer.first.cast::<WTS_PROCESS_INFO_EXW>(), count as usize) };
    entries
        .iter()
        .map(|entry| {
            // SAFETY: Windows wrote a NUL-terminated name, and a user SID or none.
            let (image, sid) = unsafe {
                let len = (0..).take_while(|&at| *entry.pProcessName.add(at) != 0).count();
                let image = String::from_utf16_lossy(std::slice::from_raw_parts(entry.pProcessName, len));
                let sid = (!entry.pUserSid.is_null())
                    .then(|| string_of_sid(entry.pUserSid))
                    .transpose()?;
                (image, sid)
            };
            Ok(Listed {
                pid: entry.ProcessId,
                image,
                sid,
            })
        })
        .collect()
}

/// The buffer of `WTSEnumerateProcessesExW`'s level 1, freed when it drops.
struct Buffer {
    first: *mut u16,
    count: u32,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: the buffer and its entry count are what the enumeration returned, and it is freed once.
        unsafe { WTSFreeMemoryExW(WTSTypeProcessInfoLevel1, self.first.cast(), self.count) };
    }
}

/// `process`, opened to wait for it; none if it has ended since the listing, which Windows answers with "invalid
/// parameter" for an id that no process has. Any other failure is an error.
fn open(process: &Listed) -> Result<Option<OwnedHandle>> {
    // SAFETY: a plain call.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process.pid) };
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
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(handle) }))
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

/// THROWAWAY measurement.
pub fn measure(service: &str) -> String {
    let sid = Account::of_service(service).sid();
    let mut out = format!("service sid {sid}\n");
    for p in list().unwrap() {
        let img = p.image.to_lowercase();
        if p.sid.as_deref() == Some(sid.as_str()) || img.contains("reverse-tunnel") || img.contains("frpc") {
            out += &format!(
                "  pid {} image {} sid {:?} ours={}\n",
                p.pid,
                p.image,
                p.sid,
                p.sid.as_deref() == Some(sid.as_str())
            );
        }
    }
    out
}

/// THROWAWAY: the error OpenProcess gives for an id that ended.
pub fn measure_open(pid: u32) -> String {
    match open(&Listed {
        pid,
        image: "x".into(),
        sid: None,
    }) {
        Ok(Some(_)) => "opened".into(),
        Ok(None) => "gone (invalid parameter)".into(),
        Err(err) => format!("error {err}"),
    }
}
