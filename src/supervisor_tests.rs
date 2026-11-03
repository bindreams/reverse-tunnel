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

/// Runs `pump` over `output` with the record at `connection`, and returns frpc's log and the supervisor's.
async fn pumped(dir: &Path, output: impl AsyncRead + Unpin, connection: PathBuf) -> (String, String) {
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

/// What `classify` makes of each line of `log`, in order.
fn events(log: &str) -> Vec<String> {
    log.lines().filter_map(|line| classify(line, "T")).collect()
}

#[tokio::test]
async fn pump_read_error_is_logged_even_when_nobody_listens() {
    let dir = tempfile::tempdir().unwrap();
    let (_, supervisor_log) = pumped(dir.path(), BrokenPipe, dir.path().join(CONNECTION_RECORD)).await;
    assert!(supervisor_log.contains("the pipe broke"));
}

#[test]
fn each_frpc_event_gives_its_own_record() {
    assert_eq!(events(LOGIN_SUCCESS), ["connected since T"]);
    assert_eq!(
        events(HOST_NOT_REGISTERED),
        vec!["refused at T: host not registered"; 2]
    );
    assert_eq!(events(TOKEN_MISMATCH), vec!["refused at T: token mismatch"; 2]);
    // The first attempt's "try to connect" (every fixture above has one) is not a loss; the same line after a login is.
    let lost: Vec<_> = CONNECTION_LOST.lines().collect();
    assert_eq!(events(&lost[..6].join("\n")), ["connected since T", "lost at T"]);
    assert_eq!(
        events(CONNECTION_LOST).last().unwrap(),
        "refused at T: timeout: no recent network activity"
    );
}

#[tokio::test]
async fn a_line_split_across_reads_is_still_recognised() {
    let dir = tempfile::tempdir().unwrap();
    let connection = dir.path().join(CONNECTION_RECORD);
    let (head, tail) = SUCCESS_LINE.split_at(SUCCESS_LINE.len() - 20);

    let (frpc_log, _) = pumped(dir.path(), Chunks::of(&[head, tail]), connection.clone()).await;

    assert_eq!(frpc_log, SUCCESS_LINE);
    assert!(
        std::fs::read_to_string(connection)
            .unwrap()
            .starts_with("connected since ")
    );
}

#[tokio::test]
async fn a_record_that_cannot_be_written_does_not_stop_the_pump() {
    let dir = tempfile::tempdir().unwrap();
    let connection = dir.path().join("missing/connection");

    let (frpc_log, supervisor_log) = pumped(dir.path(), Chunks::of(&[SUCCESS_LINE, SUCCESS_LINE]), connection).await;

    assert_eq!(frpc_log, SUCCESS_LINE.repeat(2));
    assert_eq!(
        supervisor_log.matches("recording frpc's connection").count(),
        2,
        "{supervisor_log}"
    );
}
