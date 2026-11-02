//! A burst of connections that exhausts the file descriptors must not take every tunnel down. This is its own test
//! binary because it lowers the descriptor limit of the whole process.
#![cfg(unix)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::thread;

use reverse_tunnel::paths::LOG_SUPERVISOR;
use rustix::process::{Resource, Rlimit, setrlimit};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio_tungstenite::client_async;

#[path = "support/host.rs"]
mod host;
use host::{Live, tcp_services};

#[tokio::test]
async fn descriptor_exhaustion_does_not_end_run() {
    // supervisor.log is a FIFO, so the test can wait for a line instead of polling a file.
    let mut log = None;
    let mut live = Live::start_with(&tcp_services(22, 5900), |host| {
        let fifo = host.paths.log_dir.join(LOG_SUPERVISOR);
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        log = Some(thread::spawn(move || BufReader::new(File::open(fifo).unwrap())));
    })
    .await;
    let mut log = log.unwrap().join().unwrap();

    // Holds the descriptor of the connection the test makes at the end, when the flood may still hold the others.
    let client = TcpSocket::new_v4().unwrap();
    // Descriptors are handed out lowest first, so this leaves room for 16 more, but not for the stub's flood.
    let next = File::open("/dev/null").unwrap().as_raw_fd() as u64;
    let limit = Some(next + 16);
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: limit,
            maximum: limit,
        },
    )
    .unwrap();

    live.stub.get_mut().write_all(b"f").await.unwrap();
    live.stub.read_line(&mut String::new()).await.unwrap();
    let mut line = String::new();
    while !line.contains("Too many open files") {
        line.clear();
        assert_ne!(log.read_line(&mut line).unwrap(), 0, "supervisor.log ended");
    }

    // The flood ends, and run is still serving.
    live.stub.get_mut().write_all(b"r").await.unwrap();
    let tcp = client
        .connect((Ipv4Addr::LOCALHOST, live.ws_port).into())
        .await
        .unwrap();
    client_async("ws://ssh.testhost.tunnel.example/", tcp).await.unwrap();
    let (_, err) = live.stop().await;
    assert!(err.contains("frpc exited"), "{err}");
}
