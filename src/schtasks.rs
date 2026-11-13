//! The one-time task that finishes an `uninstall` on Windows, through Task Scheduler's COM API.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

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
/// run: they are results like any other, and end the wait.
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

/// The state of task `name`. Only `GetTask` finding no such task is `Gone`; any other `GetTask` failure is an error, as
/// it says nothing about the task.
pub fn state(name: &str) -> Result<TaskState> {
    let name = name.to_string();
    on_scheduler(move |folder| {
        let get = || {
            // SAFETY: the string outlives the call.
            unsafe { folder.GetTask(&BSTR::from(name.as_str())) }
        };
        let task = match get() {
            Err(err) if err.code() == not_found() => return Ok(TaskState::Gone),
            found => com(found, "looking up the removal's task")?,
        };
        // The removal's task deletes itself as its last step, so it can go between `GetTask` and any read of it.
        // SAFETY: plain reads of a live task.
        let read = unsafe {
            task.State().and_then(|state| {
                let instances = task.GetInstances(0)?.Count()?;
                Ok((state, instances, task.LastTaskResult()?))
            })
        };
        match read {
            Ok((state, instances, last)) => Ok(task_state(state, instances, last)),
            Err(err) => after_a_failed_read(get().map(drop), err),
        }
    })
}

/// What a failed read of a task that was found means, given what looking the task up again said (`lookup`): the task is
/// gone if it is not there now, and otherwise the read's own error, since nothing says what the task is doing.
fn after_a_failed_read(lookup: windows::core::Result<()>, read: windows::core::Error) -> Result<TaskState> {
    match lookup {
        Err(err) if err.code() == not_found() => Ok(TaskState::Gone),
        _ => com(Err(read), "reading the removal's task"),
    }
}

/// What a task with this state, number of running instances and last result is doing. An instance that runs makes it
/// running, whatever its state: disabling a task does not stop it. A last result that is not a not-ended one is an exit
/// code, or an informational code that says it will not run: it ended with that. A not-ended result means it has not
/// run: then a disabled task never will.
fn task_state(state: TASK_STATE, instances: i32, last: i32) -> TaskState {
    let ran = !NOT_ENDED.contains(&last);
    if instances > 0 || state == TASK_STATE_RUNNING || state == TASK_STATE_QUEUED {
        TaskState::Running
    } else if ran {
        TaskState::Ended(last)
    } else if state == TASK_STATE_DISABLED {
        TaskState::Disabled
    } else {
        TaskState::Running
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

/// What a leftover's name starts with. A leftover is a file that a removal could not delete, which it renamed (see
/// `install::remove_or_rename`) so that its folder can go: `.reverse-tunnel.<id>.<the name it had>`, in the folder that
/// holds the bin dir. The removal task's last step deletes every such file once it can (see `removal_script`).
const LEFTOVER_PREFIX: &str = ".reverse-tunnel.";

/// The leftover file that renames the file called `original`, called `id`.
pub fn leftover_name(id: &str, original: &OsStr) -> OsString {
    let mut name = OsString::from(format!("{LEFTOVER_PREFIX}{id}."));
    name.push(original);
    name
}

/// The pattern that every leftover file in `dir` matches, for `cmd`.
pub fn leftover_pattern(dir: &Path) -> PathBuf {
    dir.join(format!("{LEFTOVER_PREFIX}*"))
}

/// What follows `LEFTOVER_PREFIX` in `name`, which `cmd` matches whatever the case.
fn after_prefix(name: &str) -> Option<&str> {
    let (prefix, rest) = (name.get(..LEFTOVER_PREFIX.len())?, name.get(LEFTOVER_PREFIX.len()..)?);
    prefix.eq_ignore_ascii_case(LEFTOVER_PREFIX).then_some(rest)
}

/// Whether the file called `name` is a leftover: whether `leftover_pattern` matches it.
pub fn is_leftover(name: &str) -> bool {
    after_prefix(name).is_some()
}

/// Whether the file called `name` is a leftover of a file that was called `original`.
pub fn is_leftover_of(name: &str, original: &str) -> bool {
    // The id is hex, so the first dot ends it.
    after_prefix(name)
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(_id, kept)| kept.eq_ignore_ascii_case(original))
}

/// What `cmd` runs for the removal task: `uninstall --finish` from `copy`, the copy's deletion, then the directory
/// `dir` that holds the copy and the log `log`, and then the task `name` itself. Each step that fails ends `cmd` with
/// a code of its own, which the task's last result carries (`exit /b` ends `cmd`, and with it the rest): 1 the removal,
/// 2 the copy, 3 the directory, 4 the task. A program is judged by its exit code, a builtin by what it left, since
/// `del` and `rmdir` report a file that something holds only in their message.
///
/// A last step deletes the leftover files, read-only ones too, in `leftovers`, the folder that holds the bin dir (see
/// `leftover_pattern`), and checks that none is left, and pauses and tries again until none is. It comes after the
/// task's own deletion: until then `uninstall`'s waiter is alive and may be running a leftover, and the waiter ends
/// once the task is gone.
/// `ping` is the pause between two checks, as `timeout` needs a console, which a task has none of.
pub fn removal_script(copy: &Path, log: &Path, dir: &Path, name: &str, leftovers: &Path) -> String {
    let (copy, log, dir) = (copy.display(), log.display(), dir.display());
    let pattern = leftover_pattern(leftovers);
    let pattern = pattern.display();
    format!(
        r#"("{copy}" uninstall --finish > "{log}" 2>&1 || exit /b 1) & del /q "{copy}" >> "{log}" 2>&1 & (if exist "{copy}" exit /b 2) & rmdir /s /q "{dir}" & (if exist "{dir}" exit /b 3) & (schtasks /Delete /F /TN {name} || exit /b 4) & for /l %i in (1,0,2) do ((del /f /q "{pattern}" >nul 2>&1) & (if not exist "{pattern}" exit /b 0) & ping -n 2 127.0.0.1 >nul)"#
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
    <Principal id="Removal"><UserId>{SYSTEM}</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
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
