use std::process::ExitStatus;

use anyhow::Context;

use super::*;

fn failed_tool(stderr: &str) -> goetia::Error {
    #[cfg(unix)]
    let status = <ExitStatus as std::os::unix::process::ExitStatusExt>::from_raw(1 << 8);
    #[cfg(windows)]
    let status = <ExitStatus as std::os::windows::process::ExitStatusExt>::from_raw(1);
    goetia::Error::Command {
        command: "systemctl start x".into(),
        status,
        stderr: stderr.into(),
    }
}

#[test]
fn a_goetia_error_is_reported_with_its_stderr_under_our_context() {
    let err = Err::<(), _>(failed_tool("boom"))
        .context("starting the service")
        .unwrap_err();

    let text = report(&err);

    assert!(
        text.starts_with("starting the service: `systemctl start x` failed"),
        "{text}"
    );
    assert!(text.contains("boom"), "{text}");
}

#[test]
fn an_error_without_goetia_in_its_chain_prints_as_anyhow_does() {
    let err = anyhow::anyhow!("inner").context("middle").context("outer");

    assert_eq!(report(&err), format!("{err:#}"));
}
