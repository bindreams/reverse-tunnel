use std::fs;
use std::process::Command;
use std::thread;

use super::*;

#[test]
fn a_binary_open_for_writing_runs_once_it_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("true");
    fs::copy("/bin/true", &path).unwrap();
    let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let run = thread::spawn(move || run_built("the copy", &mut Command::new(&path)));

    drop(writer);

    run.join().unwrap().unwrap();
}
