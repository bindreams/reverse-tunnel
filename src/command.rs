//! Running a command to completion.

use std::ffi::OsStr;
use std::process::{self, ExitStatus};

use anyhow::{Context, Result, ensure};

/// Runs `args[0]` with the rest and returns its output; it fails, with its status and what it printed, unless the
/// command succeeds.
pub fn run(args: &[impl AsRef<OsStr>]) -> Result<String> {
    let shown = args
        .iter()
        .map(|arg| arg.as_ref().to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let out = cosca::run(args)
        .output()
        .with_context(|| format!("running `{shown}`"))?;
    finish(&shown, out.status, &out.stdout, &out.stderr)
}

/// `run` for a command that is already built, because cosca's does not set a user or group.
pub fn run_built(command: &mut process::Command) -> Result<String> {
    let shown = format!("{command:?}");
    let out = command.output().with_context(|| format!("running `{shown}`"))?;
    finish(&shown, out.status, &out.stdout, &out.stderr)
}

fn finish(shown: &str, status: ExitStatus, stdout: &[u8], stderr: &[u8]) -> Result<String> {
    let stdout = String::from_utf8_lossy(stdout);
    let printed = format!("{}\n{}", stdout.trim(), String::from_utf8_lossy(stderr).trim());
    let printed = printed.trim();
    ensure!(
        status.success(),
        "`{shown}` ended with {status}{}{printed}",
        if printed.is_empty() { "" } else { ": " }
    );
    Ok(stdout.into_owned())
}
