use std::fs;
use std::io::{self, Write};

use super::*;
use crate::logfile::LogFile;

fn shown(path: &Path, lines: Option<usize>) -> String {
    let mut out = Vec::new();
    show(path, lines, false, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn last_lines_keeps_whole_lines_from_the_end() {
    for (text, n, expected) in [
        ("a\nb\nc\n", 2, "b\nc\n"),
        ("a\nb\nc", 2, "b\nc"),
        ("a\nb\n", 5, "a\nb\n"),
        ("a\nb\n", 0, ""),
        ("", 3, ""),
        ("\n\nx\n", 2, "\nx\n"),
    ] {
        assert_eq!(last_lines(text.as_bytes(), n), expected.as_bytes(), "{n} of {text:?}");
    }
}

#[test]
fn show_prints_the_whole_log_or_its_last_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    fs::write(&log, "one\ntwo\nthree\n").unwrap();

    assert_eq!(shown(&log, None), "one\ntwo\nthree\n");
    assert_eq!(shown(&log, Some(2)), "two\nthree\n");
}

#[test]
fn show_without_a_log_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let mut out = Vec::new();

    let err = show(&dir.path().join("frpc.log"), None, true, &mut out).unwrap_err();

    assert!(err.to_string().contains("no log yet"), "{err:#}");
    assert!(out.is_empty());
}

/// `logs | head` closes its input while `logs -f` runs on; that is the reader leaving, not a failure.
#[test]
fn show_ends_quietly_when_the_output_is_closed() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    fs::write(&log, "one\n").unwrap();

    show(&log, None, true, &mut Closed).unwrap();
}

fn follower_of(path: &Path) -> Follower<'_> {
    let (file, _) = read(path).unwrap().unwrap();
    Follower { path, file }
}

#[test]
fn a_follower_prints_each_appended_line_once() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    fs::write(&log, "old\n").unwrap();
    let mut follower = follower_of(&log);
    let mut out = Vec::new();

    follower.poll(&mut out).unwrap();
    assert!(out.is_empty(), "printed what was already shown: {out:?}");
    let mut file = fs::OpenOptions::new().append(true).open(&log).unwrap();
    file.write_all(b"new\n").unwrap();
    follower.poll(&mut out).unwrap();
    follower.poll(&mut out).unwrap();

    assert_eq!(out, b"new\n");
}

/// The lines the old file got before the rotation that this follower had not read yet, and those of the files after
/// it, come in order and once, over two rotations between polls.
#[test]
fn a_follower_goes_on_in_the_file_a_rotation_starts() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("frpc.log");
    let log = LogFile::open(log_path.clone(), 10).unwrap();
    let mut follower = follower_of(&log_path);
    let mut out = Vec::new();

    log.write(
        b"first, before the rotation
",
    );
    log.write(
        b"second, after it
",
    );
    follower.poll(&mut out).unwrap();
    log.write(
        b"third, after another
",
    );
    follower.poll(&mut out).unwrap();

    let all = "first, before the rotation
second, after it
third, after another
";
    assert_eq!(String::from_utf8(out).unwrap(), all);
}

/// Between a rotation's rename and its new file there is no log: that is not an error, and the next poll finds it.
#[test]
fn a_follower_waits_for_a_log_that_is_not_there() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    fs::write(
        &log, "old
",
    )
    .unwrap();
    let mut follower = follower_of(&log);
    let mut out = Vec::new();

    fs::rename(&log, dir.path().join("frpc.log.1")).unwrap();
    follower.poll(&mut out).unwrap();
    fs::write(
        &log, "new
",
    )
    .unwrap();
    follower.poll(&mut out).unwrap();

    assert_eq!(
        out,
        b"new
"
    );
}
