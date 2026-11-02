//! `reverse-tunnel run`: frpc as a contained child, and the WebSocket listener its `tcp` services point at.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Error, Result, anyhow, bail, ensure};
use cosca::{Fd, Stdio};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{StatusCode, header::HOST};

use crate::config::Config;
use crate::download::{Tools, write_file};
use crate::frpc::{render, ws_routes};
use crate::logfile::{LogFile, ROTATE_AT};
use crate::paths::{LOG_FRPC, LOG_SUPERVISOR, Paths};

/// Any valid port: `frpc verify` reads the port but does not connect to it.
const CHECK_PORT: u16 = 1;

pub struct Settings {
    /// Where the WebSocket listener binds.
    pub listen: SocketAddr,
    pub rotate_at: u64,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            listen: (Ipv4Addr::LOCALHOST, 0).into(),
            rotate_at: ROTATE_AT,
        }
    }
}

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
    run_with(paths, tools, check_only, &Settings::default())
}

pub fn run_with(paths: &Paths, tools: &Tools, check_only: bool, settings: &Settings) -> Result<ExitCode> {
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
    let log = LogFile::open(paths.log_dir.join(LOG_SUPERVISOR), settings.rotate_at)?;
    let frpc_log = LogFile::open(paths.log_dir.join(LOG_FRPC), settings.rotate_at)?;
    let Err(err) = runtime.block_on(supervise(&setup, settings.listen, &log, frpc_log));
    log.line(format_args!("{err:#}"));
    Err(err)
}

/// A token file's text without surrounding whitespace, which must not be empty.
fn token(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(!text.trim().is_empty(), "{} is empty", path.display());
    Ok(text.trim().to_string())
}

/// Renders into a private directory, so the config dir is not written, and runs `frpc verify` on it.
async fn check(setup: &Setup<'_>) -> Result<ExitCode> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("frpc.toml");
    fs::write(&config, render(&setup.cfg, CHECK_PORT, setup.paths))?;
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
    let rendered = render(&setup.cfg, listener.local_addr()?.port(), setup.paths);
    let config = setup.paths.config_dir.join("frpc.toml");
    write_file(&config, rendered.as_bytes(), 0o644, true)?;

    let mut frpc = setup.frpc(&[], &config);
    frpc.stdin(Stdio::null())?
        .stdout(Stdio::pipe())?
        .stderr(Stdio::merge(Fd::STDOUT))?;
    let mut child = frpc
        .contain()
        .spawn()
        .with_context(|| format!("starting {}", setup.tools.frpc.display()))?;
    let output = child.stdout().context("frpc's output is not piped")?;
    let pump = tokio::spawn(pump(output, frpc_log, log.clone()));

    let routes = Arc::new(ws_routes(&setup.cfg));
    let failure = tokio::select! {
        status = child.wait() => match status {
            Ok(status) => anyhow!("frpc exited: {status}"),
            Err(err) => Error::new(err).context("waiting for frpc"),
        },
        failed = listen_loop(listener, routes, log.clone()) => {
            let Err(err) = failed;
            err
        }
    };
    // Whatever frpc left running ends with it, and then so does its output.
    if let Err(err) = child.kill_tree() {
        log.line(format_args!("stopping frpc's processes: {err}"));
    }
    pump.await?;
    Err(failure)
}

/// Copies frpc's output into its log until it ends.
async fn pump(mut output: impl AsyncRead + Unpin, to: LogFile, log: LogFile) {
    let mut buf = [0; 8192];
    loop {
        match output.read(&mut buf).await {
            Ok(0) => return,
            Ok(len) => to.write(&buf[..len]),
            Err(err) => return log.line(format_args!("reading frpc's output: {err}")),
        }
    }
}

/// Serves WebSocket connections until the listening socket fails. One connection's failure is logged and nothing more.
async fn listen_loop(listener: TcpListener, routes: Arc<BTreeMap<String, u16>>, log: LogFile) -> Result<Infallible> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // The client left before we accepted: the listener is fine.
            Err(err) if matches!(err.kind(), ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset) => {
                log.line(format_args!("accepting a WebSocket connection: {err}"));
                continue;
            }
            Err(err) => return Err(err).context("accepting WebSocket connections"),
        };
        let (routes, log) = (routes.clone(), log.clone());
        tokio::spawn(async move {
            if let Err(err) = forward(stream, &routes).await {
                log.line(format_args!("WebSocket connection from {peer}: {err:#}"));
            }
        });
    }
}

/// Upgrades `stream` if its `Host` names a service, then copies between it and that service's port. Ends when either
/// side closes: a WebSocket close closes the TCP connection, and the TCP connection ending closes the WebSocket.
async fn forward(stream: TcpStream, routes: &BTreeMap<String, u16>) -> Result<()> {
    let (mut host, mut port) = (String::new(), None);
    #[expect(
        clippy::result_large_err,
        reason = "the handshake callback must return tungstenite's ErrorResponse"
    )]
    let ws = tokio_tungstenite::accept_hdr_async(stream, |request: &Request, response: Response| {
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
    })
    .await
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
