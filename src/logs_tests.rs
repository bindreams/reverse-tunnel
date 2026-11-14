use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
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

const INPUTS: [(&str, usize, &str); 8] = [
    ("a\nb\nc\n", 2, "b\nc\n"),
    ("a\nb\nc", 2, "b\nc"),
    ("a\nb\n", 5, "a\nb\n"),
    ("a\nb\n", 0, ""),
    ("", 3, ""),
    ("\n\nx\n", 2, "\nx\n"),
    ("a\nb\n", usize::MAX, "a\nb\n"),
    ("a\nb", usize::MAX, "a\nb"),
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

/// A reader that, on its first flush (the end of what `show` prints at the start), has a line appended to the log, and
/// ends the follow at the next, which is the follower's after it has printed that line.
struct AppendsAfterTheStart {
    log: PathBuf,
    shown: Vec<u8>,
    flushes: usize,
}

impl Write for AppendsAfterTheStart {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.shown.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flushes > 1 {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut file = fs::OpenOptions::new().append(true).open(&self.log)?;
        file.write_all(
            b"appended
",
        )
    }
}

/// `show` hands the file it printed from to the follower at the end of what it printed: a line appended after that is
/// shown once, and nothing before it is shown again.
#[test]
fn following_goes_on_from_the_end_of_what_was_shown() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    let lines: String = (1..=12)
        .map(|n| {
            format!(
                "line {n}
"
            )
        })
        .collect();
    fs::write(&log, &lines).unwrap();
    let mut out = AppendsAfterTheStart {
        log: log.clone(),
        shown: Vec::new(),
        flushes: 0,
    };

    show(&log, None, true, &mut out).unwrap();

    let expected: String = (3..=12)
        .map(|n| {
            format!(
                "line {n}
"
            )
        })
        .collect::<String>()
        + "appended
";
    assert_eq!(String::from_utf8(out.shown).unwrap(), expected);
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
    fs::write(
        &log, "old
",
    )
    .unwrap();
    let mut follower = follower_of(&log);
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    follower.poll(&mut out, &mut notes).unwrap();
    assert!(out.is_empty(), "printed what was already shown: {out:?}");
    let mut file = fs::OpenOptions::new().append(true).open(&log).unwrap();
    file.write_all(
        b"new
",
    )
    .unwrap();
    follower.poll(&mut out, &mut notes).unwrap();
    follower.poll(&mut out, &mut notes).unwrap();

    assert_eq!(
        out,
        b"new
"
    );
    assert!(notes.is_empty());
}

/// A follower that began before the log existed prints all of it once it is there.
#[test]
fn a_follower_without_a_log_prints_it_from_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    let mut follower = Follower { path: &log, file: None };
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    follower.poll(&mut out, &mut notes).unwrap();
    assert!(out.is_empty());
    fs::write(
        &log,
        "first
second
",
    )
    .unwrap();
    follower.poll(&mut out, &mut notes).unwrap();
    follower.poll(&mut out, &mut notes).unwrap();

    assert_eq!(
        out,
        b"first
second
"
    );
}

/// A follower that began before the log existed and finds it rotated already prints `<log>.1` before it.
#[test]
fn a_follower_without_a_log_prints_the_rotated_log_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("frpc.log");
    let mut follower = Follower { path: &log, file: None };
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    fs::write(
        dir.path().join("frpc.log.1"),
        "rotated
",
    )
    .unwrap();
    fs::write(
        &log, "current
",
    )
    .unwrap();
    follower.poll(&mut out, &mut notes).unwrap();
    follower.poll(&mut out, &mut notes).unwrap();

    assert_eq!(
        out,
        b"rotated
current
"
    );
}

/// What the old file got that the follower had not read, then the new file's lines, in order and once.
#[test]
fn a_follower_goes_on_in_the_file_a_rotation_starts() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("frpc.log");
    let log = LogFile::open(log_path.clone(), 10).unwrap();
    let mut follower = follower_of(&log_path);
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    log.write(
        b"first, before the rotation
",
    );
    log.write(
        b"second, after it
",
    );
    follower.poll(&mut out, &mut notes).unwrap();
    log.write(
        b"third, appended
",
    );
    follower.poll(&mut out, &mut notes).unwrap();

    let all = "first, before the rotation
second, after it
third, appended
";
    assert_eq!(String::from_utf8(out).unwrap(), all);
}

/// After a second rotation the file the follower holds is no longer `frpc.log.1`, which the second replaced: the file
/// between is, and its lines are not lost. With rotations past that the lines of the files before it are, and the
/// follower says so; it cannot tell two rotations from more, so it says so for two as well.
#[test]
fn a_follower_recovers_two_rotations_and_says_when_it_may_have_missed_lines() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("frpc.log");
    let log = LogFile::open(log_path.clone(), 10).unwrap();
    let mut follower = follower_of(&log_path);
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    log.write(
        b"first, in the file the follower holds
",
    );
    log.write(
        b"second, in the file between
",
    );
    log.write(
        b"third, in the file now
",
    );
    follower.poll(&mut out, &mut notes).unwrap();

    let all = "first, in the file the follower holds
second, in the file between
third, in the file now
";
    assert_eq!(String::from_utf8(out).unwrap(), all);

    let (mut out, mut notes) = (Vec::new(), Vec::new());
    log.write(
        b"fourth, in a file that the next rotation unlinks
",
    );
    log.write(
        b"fifth, in the file between
",
    );
    log.write(
        b"sixth, in the file now
",
    );
    follower.poll(&mut out, &mut notes).unwrap();

    let kept = "fifth, in the file between
sixth, in the file now
";
    assert_eq!(String::from_utf8(out).unwrap(), kept);
    assert!(String::from_utf8(notes).unwrap().contains("rotated away"));
}

/// One rotation loses nothing and says nothing.
#[test]
fn a_follower_says_nothing_of_one_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("frpc.log");
    let log = LogFile::open(log_path.clone(), 10).unwrap();
    let mut follower = follower_of(&log_path);
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    log.write(
        b"first, in the file the follower holds
",
    );
    log.write(
        b"second, in the file now
",
    );
    follower.poll(&mut out, &mut notes).unwrap();

    assert!(notes.is_empty(), "{:?}", String::from_utf8_lossy(&notes));
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
    let (mut out, mut notes) = (Vec::new(), Vec::new());

    fs::rename(&log, dir.path().join("frpc.log.1")).unwrap();
    follower.poll(&mut out, &mut notes).unwrap();
    fs::write(
        &log, "new
",
    )
    .unwrap();
    follower.poll(&mut out, &mut notes).unwrap();

    assert_eq!(
        out,
        b"new
"
    );
}
