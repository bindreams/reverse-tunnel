use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::oneshot;

use super::*;

struct BrokenPipe;

impl AsyncRead for BrokenPipe {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("the pipe broke")))
    }
}

#[tokio::test]
async fn pump_read_error_is_logged_even_when_nobody_listens() {
    let dir = tempfile::tempdir().unwrap();
    let (frpc_log, supervisor_log) = (dir.path().join("frpc.log"), dir.path().join("supervisor.log"));
    let (broken, failed) = oneshot::channel();
    drop(failed);
    let logs = (
        LogFile::open(frpc_log, ROTATE_AT).unwrap(),
        LogFile::open(supervisor_log.clone(), ROTATE_AT).unwrap(),
    );
    pump(BrokenPipe, logs.0, logs.1, broken).await;
    assert!(
        std::fs::read_to_string(supervisor_log)
            .unwrap()
            .contains("the pipe broke")
    );
}
