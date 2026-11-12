//! The one-time task that finishes an `uninstall` on Windows, through `schtasks.exe`.

use anyhow::{Context, Result, bail};

use crate::command::run;

/// The task's name.
pub const REMOVAL: &str = "reverse-tunnel-uninstall";

/// What a task's last result reads while it has not ended: running, or created and never run.
const RUNNING: i64 = 0x41301;
const NOT_YET_RUN: i64 = 0x41303;

/// Registers task `name` as run by SYSTEM, replacing one of the same name, and runs it now. The task runs `script` by
/// `cmd`, with no time limit. `definition` is where the task's definition is written, for `schtasks` to read.
pub fn start(name: &str, definition: &std::path::Path, script: &str) -> Result<()> {
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

/// How task `name` ended: its exit code, or none while it has not run or runs.
pub fn exit_code(name: &str) -> Result<Option<i64>> {
    last_result(&run(&["schtasks", "/Query", "/TN", name, "/V", "/FO", "CSV", "/NH"])?)
}

pub fn delete(name: &str) -> Result<()> {
    run(&["schtasks", "/Delete", "/F", "/TN", name])?;
    Ok(())
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
    Ok((code != RUNNING && code != NOT_YET_RUN).then_some(code))
}

#[cfg(test)]
#[path = "schtasks_tests.rs"]
mod tests;
