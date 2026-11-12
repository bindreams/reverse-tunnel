//! Running a command to completion.

use std::ffi::OsStr;
use std::io::ErrorKind;
use std::process::{self, ExitStatus};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, ensure};

/// Runs `args[0]` with the rest and returns its output; it fails, with its status and what it printed to stderr, unless
/// the command succeeds.
pub fn run(args: &[impl AsRef<OsStr>]) -> Result<String> {
    let shown = args
        .iter()
        .map(|arg| arg.as_ref().to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let what = format!("`{shown}`");
    let out = cosca::run(args).output().with_context(|| format!("running {what}"))?;
    finish(&what, out.status, &out.stdout, &out.stderr, false)
}

/// `run` for a command the caller built (cosca's cannot set a user or group), described as `what` because the command's
/// debug form lists its environment. A failure includes stdout as well as stderr.
pub fn run_built(what: &str, command: &mut process::Command) -> Result<String> {
    let mut said = false;
    let out = loop {
        match command.output() {
            // Refused while anything holds the binary open for writing: in the unit tests, a child that another
            // thread forked while this process wrote the binary, until it execs or exits.
            Err(err) if err.kind() == ErrorKind::ExecutableFileBusy => {
                if !said {
                    said = true;
                    eprintln!("waiting to start {what}: its binary is still open for writing");
                }
                thread::sleep(Duration::from_millis(10));
            }
            out => break out.with_context(|| format!("running {what}"))?,
        }
    };
    finish(what, out.status, &out.stdout, &out.stderr, true)
}

fn finish(what: &str, status: ExitStatus, stdout: &[u8], stderr: &[u8], with_stdout: bool) -> Result<String> {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    let printed = if with_stdout {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    } else {
        stderr.to_string()
    };
    let printed = printed.trim();
    ensure!(
        status.success(),
        "{what} ended with {}{}{printed}",
        status,
        if printed.is_empty() { "" } else { ": " }
    );
    Ok(stdout.into_owned())
}
