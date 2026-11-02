//! A host directory and a supervisor to run against it, for the tests that start `run`.

#![allow(dead_code, reason = "each test binary uses part of this")]

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;

use anyhow::Result;
use reverse_tunnel::download::Tools;
use reverse_tunnel::paths::Paths;
use reverse_tunnel::supervisor::{run, run_with};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Error;
use tokio_tungstenite::{WebSocketStream, client_async};

/// A host directory whose frpc is `testbin/stub_frpc.rs`, doing what `mode` says.
pub struct Host {
    dir: TempDir,
    pub paths: Paths,
    pub frpc: PathBuf,
}

impl Host {
    pub fn new(mode: &str, services: &str) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let paths = Paths {
            bin_dir: root.join("bin"),
            config_dir: root.join("config"),
            secrets_dir: root.join("config/secrets"),
            log_dir: root.join("logs"),
            lock: root.join("lock"),
            link: None,
        };
        for dir in [&paths.bin_dir, &paths.secrets_dir, &paths.log_dir] {
            fs::create_dir_all(dir).unwrap();
        }
        let config = format!("host: testhost\nbridge: tunnel.example\ndefault: ssh\nservices:\n{services}");
        fs::write(paths.config_dir.join("config.yaml"), config).unwrap();
        fs::write(paths.secrets_dir.join("bridge.token"), "bridge-secret\n").unwrap();
        fs::write(paths.secrets_dir.join("host.token"), "host-secret\r\n").unwrap();
        let frpc = paths.bin_dir.join(format!("frpc{EXE_SUFFIX}"));
        copy_stub(&frpc);
        let record = root.join("record");
        fs::write(
            frpc.with_extension("mode"),
            mode.replace("{record}", record.to_str().unwrap()),
        )
        .unwrap();
        Host { dir, paths, frpc }
    }

    /// Where a stub in `record` mode writes.
    pub fn record(&self) -> PathBuf {
        self.dir.path().join("record")
    }

    pub fn tools(&self) -> Tools {
        Tools {
            frpc: self.frpc.clone(),
        }
    }

    pub fn run(&self, check_only: bool) -> Result<ExitCode> {
        run(&self.paths, &self.tools(), check_only)
    }

    /// `run` with the WebSocket listener on `listen`.
    pub fn run_listening(&self, listen: SocketAddr) -> Result<ExitCode> {
        run_with(&self.paths, &self.tools(), false, listen)
    }

    pub fn log(&self, name: &str) -> String {
        fs::read_to_string(self.paths.log_dir.join(name)).unwrap()
    }

    /// Fails `run` with `expected` in its error before the stub starts.
    pub fn assert_refused(&self, expected: &str) {
        let err = format!("{:#}", self.run(false).unwrap_err());
        assert!(err.contains(expected), "{err}");
        assert!(!self.record().exists(), "frpc started");
    }
}

/// Copies the stub to `to`. On Unix a `cp` child writes it: a writable descriptor in this process would leak into the
/// children that other test threads fork, and executing the copy would fail with ETXTBSY while one lives.
fn copy_stub(to: &Path) {
    let stub = env!("CARGO_BIN_EXE_stub-frpc");
    if cfg!(unix) {
        assert!(Command::new("cp").arg(stub).arg(to).status().unwrap().success());
    } else {
        fs::copy(stub, to).unwrap();
    }
}

/// A supervisor running against a stub frpc that stays up until `stop`.
pub struct Live {
    pub host: Host,
    /// What `run` returned.
    done: oneshot::Receiver<Result<ExitCode>>,
    /// The stub's connection; the stub exits when this closes. It sends the port frpc.toml gives the `tcp` services,
    /// then answers commands (`testbin/stub_frpc.rs`).
    pub stub: BufReader<TcpStream>,
    /// The port frpc.toml gives the `tcp` services.
    pub ws_port: u16,
}

impl Live {
    pub async fn start(services: &str) -> Live {
        Live::start_with(services, |_| ()).await
    }

    /// `prepare` runs on the host before `run` starts.
    pub async fn start_with(services: &str, prepare: impl FnOnce(&Host)) -> Live {
        let notify = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let host = Host::new(&format!("hold {}", notify.local_addr().unwrap()), services);
        prepare(&host);
        let (paths, tools) = (host.paths.clone(), host.tools());
        let (send, mut done) = oneshot::channel();
        thread::spawn(move || send.send(run(&paths, &tools, false)));
        let mut stub = tokio::select! {
            accepted = notify.accept() => BufReader::new(accepted.unwrap().0),
            result = &mut done => panic!("run ended before the stub started: {:#}", result.unwrap().unwrap_err()),
        };
        let mut port = String::new();
        stub.read_line(&mut port).await.unwrap();
        Live {
            host,
            done,
            stub,
            ws_port: port.trim().parse().unwrap(),
        }
    }

    /// Opens a WebSocket whose `Host` is `authority`.
    pub async fn connect(&self, authority: &str) -> Result<WebSocketStream<TcpStream>, Error> {
        let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, self.ws_port)).await.unwrap();
        Ok(client_async(format!("ws://{authority}/"), tcp).await?.0)
    }

    /// Stops the stub, then returns the host and why `run` ended.
    pub async fn stop(self) -> (Host, String) {
        drop(self.stub);
        (self.host, format!("{:#}", self.done.await.unwrap().unwrap_err()))
    }
}

pub fn tcp_services(ssh: u16, vnc: u16) -> String {
    format!("  ssh: {{port: {ssh}, type: tcp}}\n  vnc: {{port: {vnc}, type: tcp}}\n")
}

/// A port whose connects are refused: bound but not listening, so no other process can take it while the socket lives.
pub fn refused_port() -> (TcpSocket, u16) {
    let held = TcpSocket::new_v4().unwrap();
    held.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let port = held.local_addr().unwrap().port();
    (held, port)
}
