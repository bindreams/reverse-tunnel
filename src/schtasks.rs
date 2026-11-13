//! The one-time task that finishes an `uninstall` on Windows, through `schtasks.exe`.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::command::run;

/// The task's name.
pub const REMOVAL: &str = "reverse-tunnel-uninstall";

/// What a task's last result reads while it has not ended (Task Scheduler's informational `SCHED_S_*` codes): ready,
/// running, never run, and queued. Other informational codes (disabled, no more runs, terminated) mean it will not
/// run, and are results like any other.
const NOT_ENDED: [i64; 4] = [0x41300, 0x41301, 0x41303, 0x41325];

/// Registers task `name` as run by SYSTEM, replacing one of the same name, and runs it now. The task runs `script` by
/// `cmd`, with no time limit. `definition` is where the task's definition is written, for `schtasks` to read.
pub fn start(name: &str, definition: &Path, script: &str) -> Result<()> {
    let utf16: Vec<u8> = task_xml(script).encode_utf16().flat_map(u16::to_le_bytes).collect();
    let text = [&[0xff, 0xfe][..], &utf16].concat();
    std::fs::write(definition, text).with_context(|| format!("writing {}", definition.display()))?;
    let definition = definition.as_os_str();
    run(&[
        "schtasks".as_ref(),
        "/Create".as_ref(),
        "/F".as_ref(),
        "/TN".as_ref(),
        name.as_ref(),
        "/XML".as_ref(),
        definition,
    ])
    .context("registering the removal's task")?;
    run(&["schtasks", "/Run", "/TN", name]).context("the removal may not have started")?;
    Ok(())
}

/// What a task is doing.
#[derive(Debug, PartialEq, Eq)]
pub enum TaskState {
    /// It runs, or has not run yet.
    Running,
    /// It ended with this exit code.
    Ended(i64),
    /// There is no such task.
    Gone,
}

/// The state of task `name`. An error means unknown: `schtasks` did not run, or said what this cannot read, or refused
/// the task while another query lists it. Only a task that is not in the list of tasks is `Gone` (the refusal's own
/// text is in the system's language).
pub fn state(name: &str) -> Result<TaskState> {
    match run(&["schtasks", "/Query", "/TN", name, "/V", "/FO", "CSV", "/NH"]) {
        Ok(line) => Ok(last_result(&line)?.map_or(TaskState::Running, TaskState::Ended)),
        Err(refused) => {
            let listing = run(&["schtasks", "/Query", "/FO", "CSV", "/NH"])
                .with_context(|| format!("{refused:#}; and listing the tasks"))?;
            if lists_task(&listing, name) {
                return Err(refused);
            }
            Ok(TaskState::Gone)
        }
    }
}

/// Whether `schtasks /Query /FO CSV /NH` lists the task `name`, which is at the root: the first field is `\name`.
fn lists_task(listing: &str, name: &str) -> bool {
    let wanted = format!("\\{name}");
    listing.lines().any(|line| {
        let first = line.trim().trim_start_matches('"').split("\",\"").next();
        first.is_some_and(|task| task.eq_ignore_ascii_case(&wanted))
    })
}

/// What `cmd` runs for the removal task: `uninstall --finish` from `copy`, then the copy's deletion, all logged to
/// `log`. `del` reports a copy that something holds only in its message, so the group fails if the copy is still there
/// (`exit /b` ends `cmd`, and with it the rest). Then, if the group succeeded, the directory `dir` that holds the copy
/// and the log, and last the task `name` itself. A removal that failed leaves all three.
pub fn removal_script(copy: &Path, log: &Path, dir: &Path, name: &str) -> String {
    let (copy, log, dir) = (copy.display(), log.display(), dir.display());
    format!(
        r#"( "{copy}" uninstall --finish && del /q "{copy}" && if exist "{copy}" exit /b 1 ) > "{log}" 2>&1 && rmdir /s /q "{dir}" && schtasks /Delete /F /TN {name}"#
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
    <Principal id="Removal"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
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

/// The exit code in the one line of `schtasks /Query /V /FO CSV /NH`: its seventh field, a number in every language
/// (the status beside it is a word in the system's).
fn last_result(csv: &str) -> Result<Option<i64>> {
    let line = csv.trim();
    let Some(field) = line.trim_matches('"').split("\",\"").nth(6) else {
        bail!("`schtasks /Query` printed no last result: {line}");
    };
    let code: i64 = field
        .parse()
        .with_context(|| format!("`schtasks /Query` printed {field:?} as the last result"))?;
    Ok((!NOT_ENDED.contains(&code)).then_some(code))
}

#[cfg(test)]
#[path = "schtasks_tests.rs"]
mod tests;
