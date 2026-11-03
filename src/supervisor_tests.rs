use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::oneshot;

use super::*;

const LOGIN_SUCCESS: &str = include_str!("../server/testdata/frpc-login-success.log");
const HOST_NOT_REGISTERED: &str = include_str!("../server/testdata/frpc-host-not-registered.log");
const TOKEN_MISMATCH: &str = include_str!("../server/testdata/frpc-token-mismatch.log");
/// A login, then the server stopped: the lines after the login are frpc's reconnect attempts.
const CONNECTION_LOST: &str = include_str!("../server/testdata/frpc-connection-lost.log");
const SUCCESS_LINE: &str = "2026-11-01 17:02:16.481 [I] [client/service.go:355] [53f902f3aee8283d] login to server success, get run id [53f902f3aee8283d]\n";

struct BrokenPipe;

impl AsyncRead for BrokenPipe {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("the pipe broke")))
    }
}

/// Gives each chunk in a read of its own.
struct Chunks(VecDeque<&'static str>);

impl Chunks {
    fn of(chunks: &[&'static str]) -> Chunks {
        Chunks(chunks.iter().copied().collect())
    }
}

impl AsyncRead for Chunks {
    fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if let Some(chunk) = self.0.pop_front() {
            buf.put_slice(chunk.as_bytes());
        }
        Poll::Ready(Ok(()))
    }
}

/// Runs `pump` over `output` with `connection`, and returns frpc's log and the supervisor's.
async fn pumped(dir: &Path, output: impl AsyncRead + Unpin, connection: Connection) -> (String, String) {
    let (frpc_log, supervisor_log) = (dir.join("frpc.log"), dir.join("supervisor.log"));
    let (broken, failed) = oneshot::channel();
    drop(failed);
    let logs = (
        LogFile::open(frpc_log.clone(), ROTATE_AT).unwrap(),
        LogFile::open(supervisor_log.clone(), ROTATE_AT).unwrap(),
    );
    pump(output, logs.0, logs.1, broken, connection).await;
    (
        std::fs::read_to_string(frpc_log).unwrap(),
        std::fs::read_to_string(supervisor_log).unwrap(),
    )
}

/// A run that began at "start".
fn connection(path: PathBuf) -> Connection {
    Connection::new(path, "start".into())
}

/// The record after each change that `log` makes to it; each line's own time is its stamp.
fn records(log: &str) -> Vec<String> {
    let mut connection = connection(PathBuf::new());
    let mut changed = Vec::new();
    for line in log.lines() {
        if let Some(event) = classify(line)
            && connection.apply(event, &line[..23])
        {
            changed.push(connection.text());
        }
    }
    changed
}

#[tokio::test]
async fn pump_read_error_is_logged_even_when_nobody_listens() {
    let dir = tempfile::tempdir().unwrap();
    let connection = connection(dir.path().join(CONNECTION_RECORD));
    let (_, supervisor_log) = pumped(dir.path(), BrokenPipe, connection).await;
    assert!(supervisor_log.contains("the pipe broke"));
}

#[test]
fn each_frpc_event_gives_its_own_record() {
    assert_eq!(records(LOGIN_SUCCESS), ["connected since 2026-11-01 17:02:16.481"]);
    // Before a login, the first "try to connect" is not a loss, and a repeated error is not a new record.
    assert_eq!(
        records(HOST_NOT_REGISTERED),
        ["not connected since start: host not registered"]
    );
    assert_eq!(records(TOKEN_MISMATCH), ["not connected since start: token mismatch"]);
    assert_eq!(
        records(CONNECTION_LOST),
        [
            "connected since 2026-11-03 15:53:28.539",
            "not connected since 2026-11-03 15:53:57.718",
            "not connected since 2026-11-03 15:53:57.718: timeout: no recent network activity",
        ]
    );
}

#[test]
fn an_outage_keeps_the_time_it_began_through_retries() {
    let more = "\
2026-11-03 15:54:07.721 [I] [client/service.go:335] [470d7b95e00f5b55] try to connect to server...
2026-11-03 15:54:12.722 [W] [client/service.go:346] [470d7b95e00f5b55] connect to server error: timeout: no recent network activity
2026-11-03 15:54:17.723 [I] [client/service.go:335] [470d7b95e00f5b55] try to connect to server...
2026-11-03 15:54:22.724 [W] [client/service.go:346] [470d7b95e00f5b55] connect to server error: connection refused
";
    let after_retries = records(&format!("{CONNECTION_LOST}{more}"));

    assert_eq!(
        after_retries[3..],
        ["not connected since 2026-11-03 15:53:57.718: connection refused"]
    );
}

#[test]
fn a_line_longer_than_a_log_file_is_dropped_whole() {
    let mut lines = Lines::default();
    let mut seen = Vec::new();

    let garbage = vec![b'x'; ROTATE_AT as usize / 2 + 1];
    for _ in 0..3 {
        lines.feed(&garbage, |line| seen.push(line.to_string()));
        assert!(lines.partial.len() as u64 <= ROTATE_AT);
    }
    // The rest of the long line, which must not be read as a line, and then a line.
    lines.feed(b"login to server success\nsecond\n", |line| seen.push(line.to_string()));

    assert_eq!(seen, ["second"]);
}

#[tokio::test]
async fn a_line_split_across_reads_is_still_recognised() {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join(CONNECTION_RECORD);
    let (head, tail) = SUCCESS_LINE.split_at(SUCCESS_LINE.len() - 20);

    let (frpc_log, _) = pumped(dir.path(), Chunks::of(&[head, tail]), connection(record.clone())).await;

    assert_eq!(frpc_log, SUCCESS_LINE);
    assert!(std::fs::read_to_string(record).unwrap().starts_with("connected since "));
}

#[tokio::test]
async fn a_record_that_cannot_be_written_does_not_stop_the_pump() {
    let dir = tempfile::tempdir().unwrap();
    let connection = connection(dir.path().join("missing/connection"));

    let (frpc_log, supervisor_log) = pumped(dir.path(), Chunks::of(&[SUCCESS_LINE, SUCCESS_LINE]), connection).await;

    assert_eq!(frpc_log, SUCCESS_LINE.repeat(2));
    assert_eq!(
        supervisor_log.matches("recording frpc's connection").count(),
        2,
        "{supervisor_log}"
    );
}
