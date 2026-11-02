//! A burst of connections that exhausts the file descriptors must not take every tunnel down. This is its own test
//! binary because it lowers the descriptor limit of the whole process.
#![cfg(unix)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use reverse_tunnel::paths::LOG_SUPERVISOR;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio_tungstenite::client_async;

#[path = "support/host.rs"]
mod host;
use host::{Live, refused_port, tcp_services};

#[tokio::test]
async fn descriptor_exhaustion_does_not_end_run() {
    // supervisor.log is a FIFO, so the test can wait for a line instead of polling a file. A thread keeps reading it:
    // a FIFO holds little, and a write to a full one would block `run`.
    let (send, log) = mpsc::channel();
    let (_held, dead) = refused_port();
    let mut live = Live::start_with(&tcp_services(dead, dead), move |host| {
        let fifo = host.paths.log_dir.join(LOG_SUPERVISOR);
        assert!(Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        thread::spawn(move || {
            for line in BufReader::new(File::open(fifo).unwrap()).lines() {
                let _ = send.send(line.unwrap());
            }
        });
    })
    .await;

    // Descriptors are handed out lowest first, so this leaves room for 16 more, but not for the stub's flood. The hard
    // limit stays, so the soft limit can be raised again.
    let original = getrlimit(Resource::Nofile);
    let next = File::open("/dev/null").unwrap().as_raw_fd() as u64;
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(next + 16),
            maximum: original.maximum,
        },
    )
    .unwrap();

    live.stub.get_mut().write_all(b"f").await.unwrap();
    live.stub.read_line(&mut String::new()).await.unwrap();
    let found = log.iter().find(|line| line.contains("Too many open files"));
    assert!(found.is_some(), "supervisor.log ended");

    // Restore the limit first: while `accept` fails with EMFILE, an incoming connection can be reset.
    setrlimit(Resource::Nofile, original).unwrap();
    // 'r' ends the flood.
    live.stub.get_mut().write_all(b"r").await.unwrap();
    let tcp = TcpSocket::new_v4()
        .unwrap()
        .connect((Ipv4Addr::LOCALHOST, live.ws_port).into())
        .await
        .unwrap();
    client_async("ws://ssh.testhost.tunnel.example/", tcp).await.unwrap();
    let (_, err) = live.stop().await;
    assert!(err.contains("frpc exited"), "{err}");
}
