//! `reverse-tunnel run`: frpc as a child, and the WebSocket listener its `tcp` services point at.
//!
//! The service manager owns the process tree: `run` neither contains frpc nor lets it start anything, so stopping the
//! service stops frpc with it.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Error, Result, anyhow, bail, ensure};
use cosca::{Fd, Stdio};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{StatusCode, header::HOST};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::config::Config;
use crate::download::Tools;
use crate::frpc::{render, ws_routes};
use crate::logfile::{LogFile, ROTATE_AT};
use crate::paths::{LOG_FRPC, LOG_SUPERVISOR, Paths};

/// Any valid port: `frpc verify` reads the port but does not connect to it.
const CHECK_PORT: u16 = 1;

/// How long a client has to finish the WebSocket handshake.
const HANDSHAKE_WITHIN: Duration = Duration::from_secs(60);

/// The largest WebSocket message or frame accepted; SSH over `websocat --binary` sends small ones.
const MAX_MESSAGE: usize = 1 << 20;

/// What `run` and `run --check` share.
struct Setup<'a> {
    cfg: Config,
    paths: &'a Paths,
    tools: &'a Tools,
    /// The environment frpc reads its tokens from.
    tokens: [(&'static str, String); 2],
}

impl Setup<'_> {
    /// `frpc <subcommand> -c <config>`; the tokens are in this child's environment and no other.
    fn frpc(&self, subcommand: &[&str], config: &Path) -> cosca::tokio::Command {
        let mut frpc = cosca::tokio::run([&self.tools.frpc]);
        frpc.args(subcommand).arg("-c").arg(config).envs(self.tokens.clone());
        frpc
    }
}

/// Runs frpc and the listener until one fails, which is always an error. With `check_only`, verifies the configuration
/// and returns.
pub fn run(paths: &Paths, tools: &Tools, check_only: bool) -> Result<ExitCode> {
    run_with(paths, tools, check_only, (Ipv4Addr::LOCALHOST, 0).into())
}

/// `run` with the WebSocket listener bound to `listen`.
pub fn run_with(paths: &Paths, tools: &Tools, check_only: bool, listen: SocketAddr) -> Result<ExitCode> {
    let config = paths.config_dir.join("config.yaml");
    let setup = Setup {
        cfg: Config::load(&config)?,
        paths,
        tools,
        tokens: [
            ("RT_BRIDGE_TOKEN", token(&paths.secrets_dir.join("bridge.token"))?),
            ("RT_HOST_TOKEN", token(&paths.secrets_dir.join("host.token"))?),
        ],
    };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    if check_only {
        return runtime.block_on(check(&setup));
    }
    let log = LogFile::open(paths.log_dir.join(LOG_SUPERVISOR), ROTATE_AT)?;
    let frpc_log = LogFile::open(paths.log_dir.join(LOG_FRPC), ROTATE_AT)?;
    let Err(err) = runtime.block_on(supervise(&setup, listen, &log, frpc_log));
    log.line(format_args!("{err:#}"));
    Err(err)
}

/// A token file's text without surrounding whitespace, which must not be empty.
fn token(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(!text.trim().is_empty(), "{} is empty", path.display());
    Ok(text.trim().to_string())
}

/// Renders frpc.toml for `port` into `dir` and returns its path. It holds no secret: frpc reads the tokens from its
/// environment.
fn render_config(setup: &Setup<'_>, port: u16, dir: &Path) -> Result<PathBuf> {
    let config = dir.join("frpc.toml");
    fs::write(&config, render(&setup.cfg, port, setup.paths))
        .with_context(|| format!("writing {}", config.display()))?;
    Ok(config)
}

/// Has frpc verify the rendered configuration.
async fn check(setup: &Setup<'_>) -> Result<ExitCode> {
    // `--check` runs as the caller, who may not write the log dir.
    let dir = tempfile::tempdir()?;
    let config = render_config(setup, CHECK_PORT, dir.path())?;
    let status = setup.frpc(&["verify"], &config).status().await;
    let status = status.with_context(|| format!("starting {}", setup.tools.frpc.display()))?;
    ensure!(status.success(), "frpc verify rejected the configuration: {status}");
    Ok(ExitCode::SUCCESS)
}

/// Starts the listener and frpc, and returns why the first of them stopped, after stopping the other.
async fn supervise(setup: &Setup<'_>, listen: SocketAddr, log: &LogFile, frpc_log: LogFile) -> Result<Infallible> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the WebSocket listener on {listen}"))?;
    // The log dir is the one directory the service account may write. A stopped `run` cannot clean up after itself
    // (the service manager kills it), so every start overwrites the same file.
    let config = render_config(setup, listener.local_addr()?.port(), &setup.paths.log_dir)?;

    let mut frpc = setup.frpc(&[], &config);
    frpc.stdin(Stdio::null())?
        .stdout(Stdio::pipe())?
        .stderr(Stdio::merge(Fd::STDOUT))?;
    let mut child = frpc
        .spawn()
        .with_context(|| format!("starting {}", setup.tools.frpc.display()))?;
    let output = child.stdout().context("frpc's output is not piped")?;
    let (broken, read_failed) = oneshot::channel();
    let pump = tokio::spawn(pump(output, frpc_log, log.clone(), broken));

    let routes = Arc::new(ws_routes(&setup.cfg));
    let mut exited = false;
    let failure = tokio::select! {
        status = child.wait() => match status {
            Ok(status) => {
                exited = true;
                anyhow!("frpc exited: {status}")
            }
            Err(err) => Error::new(err).context("waiting for frpc"),
        },
        failed = listen_loop(listener, routes, log.clone()) => {
            let Err(err) = failed;
            err
        }
        Ok(()) = read_failed => anyhow!("frpc's output cannot be read"),
    };
    // frpc starts no processes, so ending it ends its output.
    let stopped = async {
        if !exited {
            child.kill()?;
            child.wait().await?;
        }
        pump.await?;
        anyhow::Ok(())
    };
    if let Err(err) = stopped.await {
        log.line(format_args!("stopping frpc: {err:#}"));
    }
    Err(failure)
}

/// Copies frpc's output into its log until it ends. A read error goes to `supervisor_log` and then to `failed`; the log
/// has it even when `supervise` is already stopping and nobody receives.
async fn pump(mut output: impl AsyncRead + Unpin, to: LogFile, supervisor_log: LogFile, failed: oneshot::Sender<()>) {
    let mut buf = [0; 8192];
    loop {
        match output.read(&mut buf).await {
            Ok(0) => return,
            Ok(len) => to.write(&buf[..len]),
            Err(err) => {
                supervisor_log.line(format_args!("reading frpc's output: {err}"));
                let _ = failed.send(());
                return;
            }
        }
    }
}

/// Serves WebSocket connections until the listening socket is broken. One connection's failure is logged and nothing
/// more.
async fn listen_loop(listener: TcpListener, routes: Arc<BTreeMap<String, u16>>, log: LogFile) -> Result<Infallible> {
    let mut open = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            // Collects the finished connections, so that the set only holds open ones.
            Some(ended) = open.join_next() => {
                log_panic(ended, &log);
                continue;
            }
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                log.line(format_args!("accepting a WebSocket connection: {err}"));
                if is_per_connection(&err) {
                    continue;
                }
                // Open connections hold descriptors, and one closing frees one. With none open, the listener is
                // broken.
                if open.is_empty() {
                    return Err(err).context("accepting WebSocket connections");
                }
                if let Some(ended) = open.join_next().await {
                    log_panic(ended, &log);
                }
                continue;
            }
        };
        let (routes, log) = (routes.clone(), log.clone());
        open.spawn(async move {
            if let Err(err) = forward(stream, &routes).await {
                log.line(format_args!("WebSocket connection from {peer}: {err:#}"));
            }
        });
    }
}

/// Whether `err` from `accept` is about the connection being accepted and not about the listener, so that the next
/// `accept` is fine: the client left, or Linux reports a network error pending on the new connection (accept(2)).
fn is_per_connection(err: &io::Error) -> bool {
    use ErrorKind::{ConnectionAborted, ConnectionReset, HostUnreachable, NetworkDown, NetworkUnreachable};
    #[cfg(unix)]
    {
        let pending = [libc::EPROTO, libc::ENOPROTOOPT, libc::EHOSTDOWN, libc::EOPNOTSUPP];
        if err.raw_os_error().is_some_and(|code| pending.contains(&code)) {
            return true;
        }
        #[cfg(target_os = "linux")]
        if err.raw_os_error() == Some(libc::ENONET) {
            return true;
        }
    }
    matches!(
        err.kind(),
        ConnectionAborted | ConnectionReset | NetworkDown | HostUnreachable | NetworkUnreachable
    )
}

fn log_panic(ended: Result<(), JoinError>, log: &LogFile) {
    if let Err(err) = ended {
        log.line(format_args!("a WebSocket connection panicked: {err}"));
    }
}

/// Upgrades `stream` if its `Host` names a service, then copies between it and that service's port. Ends when either
/// side closes: a WebSocket close closes the TCP connection, and the TCP connection ending closes the WebSocket.
async fn forward(stream: TcpStream, routes: &BTreeMap<String, u16>) -> Result<()> {
    let (mut host, mut port) = (String::new(), None);
    let limits = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    #[expect(
        clippy::result_large_err,
        reason = "the handshake callback must return tungstenite's ErrorResponse"
    )]
    let route = |request: &Request, response: Response| {
        let header = request.headers().get(HOST).and_then(|value| value.to_str().ok());
        host = header
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        port = routes.get(&host).copied();
        port.map(|_| response).ok_or_else(|| {
            let mut refusal = ErrorResponse::new(Some(format!("no service at {host:?}\n")));
            *refusal.status_mut() = StatusCode::NOT_FOUND;
            refusal
        })
    };
    let handshake = tokio_tungstenite::accept_hdr_async_with_config(stream, route, Some(limits));
    let ws = timeout(HANDSHAKE_WITHIN, handshake)
        .await
        .with_context(|| format!("no WebSocket handshake within {HANDSHAKE_WITHIN:?}"))?
        .with_context(|| format!("upgrading for host {host:?}"))?;
    let port = port.expect("the upgrade succeeds only for a route");
    let service = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("connecting to 127.0.0.1:{port} for host {host:?}"))?;

    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut tcp_rx, mut tcp_tx) = service.into_split();
    let result = tokio::select! {
        done = async {
            while let Some(message) = ws_rx.next().await {
                match message? {
                    Message::Binary(data) => tcp_tx.write_all(&data).await?,
                    Message::Close(_) => break,
                    Message::Text(_) => bail!("a text message: clients must send binary ones"),
                    _ => {}
                }
            }
            Ok(())
        } => done,
        done = async {
            let mut buf = [0; 16 * 1024];
            loop {
                let len = tcp_rx.read(&mut buf).await?;
                if len == 0 {
                    break;
                }
                ws_tx.send(Message::binary(buf[..len].to_vec())).await?;
            }
            Ok(ws_tx.close().await?)
        } => done,
    };
    // Sends the reply to a close the client began.
    result.and(ws_tx.flush().await.map_err(Error::from))
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;
