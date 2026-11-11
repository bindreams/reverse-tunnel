//! Running a command to completion.

use std::ffi::OsStr;

use anyhow::{Context, Result, ensure};

/// Runs `args[0]` with the rest and returns its output; it fails, with its status and stderr, unless the command
/// succeeds.
pub fn run(args: &[impl AsRef<OsStr>]) -> Result<String> {
    let shown = args
        .iter()
        .map(|arg| arg.as_ref().to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let out = cosca::run(args)
        .output()
        .with_context(|| format!("running `{shown}`"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr = stderr.trim();
    ensure!(
        out.status.success(),
        "`{shown}` ended with {}{}{stderr}",
        out.status,
        if stderr.is_empty() { "" } else { ": " }
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
