use std::fs;
use std::io::{self, Write};
use std::thread;

use super::*;
use crate::logfile::LogFile;

fn shown(path: &Path, lines: Option<usize>) -> String {
    let mut out = Vec::new();
    show(path, lines, false, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

/// A reader that has what it came for: `flush`, which `logs -f` calls after each print, ends the follow as a closed
/// output does.
#[derive(Default)]
struct UntilFlushed(Vec<u8>);

impl Write for UntilFlushed {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

const INPUTS: [(&str, usize, &str); 6] = [
    ("a\nb\nc\n", 2, "b\nc\n"),
    ("a\nb\nc", 2, "b\nc"),
    ("a\nb\n", 5, "a\nb\n"),
    ("a\nb\n", 0, ""),
    ("", 3, ""),
    ("\n\nx\n", 2, "\nx\n"),
];

#[test]
fn last_lines_keeps_whole_lines_from_the_end() {
    for (text, n, expected) in INPUTS {
        assert_eq!(last_lines(text.as_bytes(), n), expected.as_bytes(), "{n} of {text:?}");
    }
}

/// Block sizes below the length of a line put a block's edge on every kind of line boundary.
#[test]
fn tail_is_the_same_whatever_the_block_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.log");
    for (text, n, expected) in INPUTS {
        fs::write(&path, text).unwrap();
        for block in 1..=7 {
            let mut file = File::open(&path).unwrap();
            let got = tail_in_blocks(&mut file, n, block).unwrap();
            assert_eq!(got, expected.as_bytes(), "{n} of {text:?} in blocks of {block}");
        }
    }
}

/// The tail of a log longer than a few blocks, and the file left at the end it read to.
#[test]
fn tail_of_a_long_log_leaves_the_file_at_its_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("frpc.log");
    let lines: String = (1..=5000).map(|n| format!("line {n}\n")).collect();
    assert!(lines.len() > 3 * BLOCK);
    fs::write(&path, &lines).unwrap();
    let mut file = File::open(&path).unwrap();

    let got = tail(&mut file, 3).unwrap();

    assert_eq!(got, b"line 4998\nline 4999\nline 5000\n");
    let mut rest = Vec::new();
    file.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty(), "{} bytes after the tail", rest.len());
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

    let err = show(&dir.path().join("frpc.log"), None, false, &mut out).unwrap_err();

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

/// Like `tail -f`: the last ten lines, unless `-n` says otherwise.
#[test]
fn following_starts_with_the_last_ten_lines_or_those_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    let lines: String = (1..=12).map(|n| format!("line {n}\n")).collect();
    fs::write(&log, &lines).unwrap();

    for (asked, first) in [(None, 3), (Some(2), 11)] {
        let mut out = UntilFlushed::default();
        show(&log, asked, true, &mut out).unwrap();
        let expected: String = (first..=12).map(|n| format!("line {n}\n")).collect();
        assert_eq!(String::from_utf8(out.0).unwrap(), expected, "{asked:?}");
    }
}

/// `logs -f` on a host whose service has not made the log yet waits for it. The log is put there from another thread,
/// whole, so that whenever `show` looks it sees nothing or all of it.
#[test]
fn following_waits_for_a_log_that_is_not_there_yet() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    let (made, log_to_make) = (dir.path().join("made"), log.clone());
    let maker = thread::spawn(move || {
        fs::write(&made, "late\n").unwrap();
        fs::rename(&made, &log_to_make).unwrap();
    });

    let mut out = UntilFlushed::default();
    show(&log, None, true, &mut out).unwrap();

    maker.join().unwrap();
    assert_eq!(out.0, b"late\n");
}

/// A follower that has printed what is in the log at `path`.
fn follower_of(path: &Path) -> Follower<'_> {
    let mut file = open(path).unwrap().unwrap();
    file.seek(SeekFrom::End(0)).unwrap();
    Follower { path, file: Some(file) }
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

/// A follower that began before the log existed prints all of it once it is there.
#[test]
fn a_follower_without_a_log_prints_it_from_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    let mut follower = Follower { path: &log, file: None };
    let mut out = Vec::new();

    follower.poll(&mut out).unwrap();
    assert!(out.is_empty());
    fs::write(&log, "first\nsecond\n").unwrap();
    follower.poll(&mut out).unwrap();
    follower.poll(&mut out).unwrap();

    assert_eq!(out, b"first\nsecond\n");
}

/// What the old file got that the follower had not read, then the new file's lines, in order and once.
#[test]
fn a_follower_goes_on_in_the_file_a_rotation_starts() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("frpc.log");
    let log = LogFile::open(log_path.clone(), 10).unwrap();
    let mut follower = follower_of(&log_path);
    let mut out = Vec::new();

    log.write(b"first, before the rotation\n");
    log.write(b"second, after it\n");
    follower.poll(&mut out).unwrap();
    log.write(b"third, appended\n");
    follower.poll(&mut out).unwrap();

    let all = "first, before the rotation\nsecond, after it\nthird, appended\n";
    assert_eq!(String::from_utf8(out).unwrap(), all);
}

/// After a second rotation the file the follower holds is no longer `frpc.log.1`, which the second replaced: the file
/// between is, and its lines are not lost.
#[test]
fn a_follower_loses_no_line_to_two_rotations_between_polls() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("frpc.log");
    let log = LogFile::open(log_path.clone(), 10).unwrap();
    let mut follower = follower_of(&log_path);
    let mut out = Vec::new();

    log.write(b"first, in the file the follower holds\n");
    log.write(b"second, in the file between\n");
    log.write(b"third, in the file now\n");
    follower.poll(&mut out).unwrap();

    let all = "first, in the file the follower holds\nsecond, in the file between\nthird, in the file now\n";
    assert_eq!(String::from_utf8(out).unwrap(), all);
}

/// Between a rotation's rename and its new file there is no log: that is not an error, and the next poll finds it.
#[test]
fn a_follower_waits_for_a_log_that_is_not_there() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    fs::write(&log, "old\n").unwrap();
    let mut follower = follower_of(&log);
    let mut out = Vec::new();

    fs::rename(&log, dir.path().join("frpc.log.1")).unwrap();
    follower.poll(&mut out).unwrap();
    fs::write(&log, "new\n").unwrap();
    follower.poll(&mut out).unwrap();

    assert_eq!(out, b"new\n");
}
