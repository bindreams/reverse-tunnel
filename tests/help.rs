//! `--help` lists what a person runs; the service's entry point, `run`, is not one of those and stays out of it.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_reverse-tunnel");

fn help(args: &[&str]) -> String {
    let out = Command::new(BIN).args(args).output().unwrap();
    assert!(out.status.success(), "{args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn help_does_not_list_run_but_run_still_has_its_own_help() {
    let listed = help(&["--help"]);
    assert!(listed.contains("install"), "the command list is missing: {listed}");
    assert!(
        !listed.lines().any(|line| line.trim_start().starts_with("run ")),
        "`run` is listed: {listed}"
    );
    assert!(help(&["run", "--help"]).contains("--check"));
}
