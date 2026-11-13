//! The one-time task that finishes an `uninstall` on Windows, through Task Scheduler's COM API.

use std::path::Path;

use anyhow::{Result, anyhow};
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    ITaskFolder, ITaskService, TASK_CREATE, TASK_LOGON_SERVICE_ACCOUNT, TASK_STATE, TASK_STATE_DISABLED,
    TASK_STATE_QUEUED, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, HRESULT};

/// The task's name.
pub const REMOVAL: &str = "reverse-tunnel-uninstall";

/// What a task's last result reads while it has not ended (Task Scheduler's informational `SCHED_S_*` codes): ready,
/// running, never run, and queued. Other informational codes (disabled, no more runs, terminated) mean it will not
/// run, and are results like any other.
const NOT_ENDED: [i32; 4] = [0x41300, 0x41301, 0x41303, 0x41325];

/// The account of SYSTEM, which the task's principal and its registration both name.
const SYSTEM: &str = "S-1-5-18";

/// Registers task `name` as run by SYSTEM, replacing one of the same name, and runs it now. The task runs `script` by
/// `cmd`, with no time limit.
pub fn start(name: &str, script: &str) -> Result<()> {
    let (name, xml) = (name.to_string(), task_xml(script));
    on_scheduler(move |folder| {
        delete_in(folder, &name)?;
        let none = VARIANT::default();
        // SAFETY: the strings and VARIANTs outlive the calls.
        let task = com(
            unsafe {
                folder.RegisterTask(
                    &BSTR::from(name.as_str()),
                    &BSTR::from(xml),
                    TASK_CREATE.0,
                    &VARIANT::from(SYSTEM),
                    &none,
                    TASK_LOGON_SERVICE_ACCOUNT,
                    &none,
                )
            },
            "registering the removal's task",
        )?;
        // SAFETY: as above.
        com(unsafe { task.Run(&none) }, "the removal may not have started")?;
        Ok(())
    })
}

/// Deletes task `name`; a task that is not there is already deleted.
pub fn delete(name: &str) -> Result<()> {
    let name = name.to_string();
    on_scheduler(move |folder| delete_in(folder, &name))
}

/// What a task is doing.
#[derive(Debug, PartialEq, Eq)]
pub enum TaskState {
    /// It runs, or has not run yet.
    Running,
    /// It is disabled, and will not run.
    Disabled,
    /// It ended with this exit code.
    Ended(i32),
    /// There is no such task.
    Gone,
}

/// The state of task `name`. Only "no such task" is `Gone`; any other failure to ask is an error, as it says nothing
/// about the task.
pub fn state(name: &str) -> Result<TaskState> {
    let name = name.to_string();
    on_scheduler(move |folder| {
        // SAFETY: the string outlives the call.
        let task = match unsafe { folder.GetTask(&BSTR::from(name.as_str())) } {
            Err(err) if err.code() == not_found() => return Ok(TaskState::Gone),
            found => com(found, "looking up the removal's task")?,
        };
        // SAFETY: plain reads of a live task.
        let (state, last) = unsafe {
            (
                com(task.State(), "reading the task's state")?,
                com(task.LastTaskResult(), "reading the task's last result")?,
            )
        };
        Ok(task_state(state, last))
    })
}

/// What a task with this state and last result is doing. A disabled task will not run, whatever its last result says.
fn task_state(state: TASK_STATE, last: i32) -> TaskState {
    if state == TASK_STATE_DISABLED {
        TaskState::Disabled
    } else if state == TASK_STATE_RUNNING || state == TASK_STATE_QUEUED || NOT_ENDED.contains(&last) {
        TaskState::Running
    } else {
        TaskState::Ended(last)
    }
}

fn not_found() -> HRESULT {
    HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0)
}

fn com<T>(result: windows::core::Result<T>, what: &str) -> Result<T> {
    result.map_err(|err| anyhow!("{what}: {err}"))
}

fn delete_in(folder: &ITaskFolder, name: &str) -> Result<()> {
    // SAFETY: the string outlives the call.
    match unsafe { folder.DeleteTask(&BSTR::from(name), 0) } {
        Err(err) if err.code() == not_found() => Ok(()),
        deleted => com(deleted, "deleting the task"),
    }
}

/// Runs `work` on a thread of its own, since COM is initialised per thread and the caller's may already hold an
/// apartment of another kind, with the root folder of the local Task Scheduler.
fn on_scheduler<T: Send>(work: impl FnOnce(&ITaskFolder) -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|scope| {
        let ran = scope.spawn(|| {
            // SAFETY: balanced by the `CoUninitialize` below, which runs after every interface is released.
            com(
                unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() },
                "initialising COM",
            )?;
            let outcome = connect().and_then(|folder| work(&folder));
            unsafe { CoUninitialize() };
            outcome
        });
        ran.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

fn connect() -> Result<ITaskFolder> {
    // SAFETY: COM is initialised on this thread.
    unsafe {
        let service: ITaskService = com(
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER),
            "creating the Task Scheduler service",
        )?;
        let none = VARIANT::default();
        com(
            service.Connect(&none, &none, &none, &none),
            "connecting to the Task Scheduler",
        )?;
        com(service.GetFolder(&BSTR::from("\\")), "opening the root task folder")
    }
}

/// What `cmd` runs for the removal task: `uninstall --finish` from `copy`, the copy's deletion, then the directory
/// `dir` that holds the copy and the log `log`, and last the task `name` itself. Each step that fails ends `cmd` with
/// a code of its own, which the task's last result carries (`exit /b` ends `cmd`, and with it the rest): 1 the removal,
/// 2 the copy, 3 the directory, 4 the task. A program is judged by its exit code, a builtin by what it left, since
/// `del` and `rmdir` report a file that something holds only in their message.
pub fn removal_script(copy: &Path, log: &Path, dir: &Path, name: &str) -> String {
    let (copy, log, dir) = (copy.display(), log.display(), dir.display());
    format!(
        r#"("{copy}" uninstall --finish > "{log}" 2>&1 || exit /b 1) & del /q "{copy}" >> "{log}" 2>&1 & (if exist "{copy}" exit /b 2) & rmdir /s /q "{dir}" & (if exist "{dir}" exit /b 3) & (schtasks /Delete /F /TN {name} || exit /b 4)"#
    )
}

/// The definition of a task with no trigger that runs `script` as SYSTEM, however long it takes and whatever the power.
fn task_xml(script: &str) -> String {
    // `cmd /s /c "..."` takes everything between the outer quotes as the command, whatever quotes it holds.
    let arguments = format!(r#"/s /c "{script}""#)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Removal"><UserId>{SYSTEM}</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Removal"><Exec><Command>cmd.exe</Command><Arguments>{arguments}</Arguments></Exec></Actions>
</Task>"#
    )
}

#[cfg(test)]
#[path = "schtasks_tests.rs"]
mod tests;
