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
async fn pump_read_error_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let log = LogFile::open(dir.path().join("frpc.log"), ROTATE_AT).unwrap();
    let (broken, failed) = oneshot::channel();
    pump(BrokenPipe, log, broken).await;
    assert!(format!("{:#}", failed.await.unwrap()).contains("the pipe broke"));
}
