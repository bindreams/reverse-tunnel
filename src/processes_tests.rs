use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::process::{Child, Command, Stdio};

use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId, WaitForSingleObject};

use super::*;

/// A process of this user that lives until it is killed: `cmd` waits for input, which a pipe nobody writes to never
/// gives it.
fn waiting() -> Child {
    Command::new("cmd.exe")
        .args(["/c", "set /p x="])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap()
}

fn own_user() -> String {
    // SAFETY: the pseudo-handle of this process is always valid.
    user_of(unsafe { GetCurrentProcess() }).unwrap()
}

fn id_of(process: &OwnedHandle) -> u32 {
    // SAFETY: a live handle.
    unsafe { GetProcessId(process.as_raw_handle()) }
}

fn handle_of(pid: u32) -> OwnedHandle {
    let all = running_as(&own_user()).unwrap();
    all.into_iter()
        .find(|process| id_of(process) == pid)
        .unwrap_or_else(|| panic!("no process of this user has the id {pid}"))
}

#[test]
fn a_process_is_found_by_the_user_it_runs_as() {
    let mut child = waiting();

    // Many processes of the system cannot be opened by a user: they are skipped, not an error.
    let process = handle_of(child.id());

    assert_eq!(id_of(&process), child.id());
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn an_account_that_no_process_runs_as_has_no_process_to_wait_for() {
    // The SID of a service that does not exist.
    assert!(running_as("S-1-5-80-1-2-3-4-5").unwrap().is_empty());

    wait_until_none_runs_as(&Account::of_service("reverse-tunnel-no-such-service")).unwrap();
}

#[test]
fn waiting_for_a_process_returns_once_it_has_ended() {
    let mut child = waiting();
    let process = handle_of(child.id());

    std::thread::scope(|scope| {
        scope.spawn(|| {
            child.kill().unwrap();
            child.wait().unwrap();
        });
        wait_for_exit(std::slice::from_ref(&process)).unwrap();
    });

    // SAFETY: a live handle; a zero timeout only reads whether it is signalled.
    let ended = unsafe { WaitForSingleObject(process.as_raw_handle(), 0) };
    assert_eq!(ended, WAIT_OBJECT_0);
}
