//! `run` against `testbin/stub_frpc.rs`. These bind ports and spawn processes, so they run in a container or on CI.

use std::fs;
use std::net::{Ipv4Addr, TcpListener as StdListener};
use std::path::Path;

use futures_util::{SinkExt, StreamExt};
use reverse_tunnel::logfile::LogFile;
use reverse_tunnel::paths::{LOG_FRPC, LOG_SUPERVISOR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error, Message};

#[path = "support/host.rs"]
mod host;
use host::{Host, Live, tcp_services};

const SSH: &str = "  ssh: {port: 22, type: tcp}\n";

fn recorded(host: &Host, prefix: &str) -> Vec<String> {
    let record = fs::read_to_string(host.record()).unwrap();
    record
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::to_string)
        .collect()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

// check -----

#[test]
fn check_renders_and_verifies_without_starting() {
    let host = Host::new("record 0 {record}", SSH);
    let (config_before, logs_before) = (names(&host.paths.config_dir), names(&host.paths.log_dir));

    host.run(true).unwrap();

    let args = recorded(&host, "ARG ");
    assert_eq!(&args[..2], ["verify", "-c"]);
    let rendered = Path::new(&args[2]);
    assert_eq!(rendered.file_name().unwrap(), "frpc.toml");
    assert!(
        !rendered.starts_with(&host.paths.config_dir),
        "rendered into {}",
        args[2]
    );
    assert!(
        fs::read_to_string(host.record())
            .unwrap()
            .contains("TOML\nserverAddr = \"tunnel.example\"")
    );
    assert_eq!(names(&host.paths.config_dir), config_before);
    assert_eq!(names(&host.paths.log_dir), logs_before);
}

// the child ends -----

#[test]
fn child_exit_stops_others_and_exits_nonzero() {
    let host = Host::new("exit 7", SSH);
    let err = format!("{:#}", host.run(false).unwrap_err());
    assert!(err.contains("frpc exited") && err.contains('7'), "{err}");
    assert_eq!(host.log(LOG_SUPERVISOR).trim_end(), err);
    assert!(host.log(LOG_FRPC).contains("stub frpc: failing"));
}

#[test]
fn tokens_only_in_frpc_env() {
    let host = Host::new("record 3 {record}", SSH);
    host.run(false).unwrap_err();

    let env = recorded(&host, "ENV ");
    assert!(env.contains(&"RT_BRIDGE_TOKEN=bridge-secret".to_string()));
    assert!(env.contains(&"RT_HOST_TOKEN=host-secret".to_string()));
    assert!(std::env::var_os("RT_BRIDGE_TOKEN").is_none());
    let mut seen = vec![recorded(&host, "ARG ").join(" ")];
    for file in [LOG_SUPERVISOR, LOG_FRPC] {
        seen.push(host.log(file));
    }
    let record = fs::read_to_string(host.record()).unwrap();
    seen.push(
        record
            .split_once(
                "TOML
",
            )
            .unwrap()
            .1
            .to_string(),
    );
    for text in seen {
        assert!(
            !text.contains("bridge-secret") && !text.contains("host-secret"),
            "{text}"
        );
    }
}

#[test]
fn run_leaves_the_config_dir_alone() {
    let host = Host::new("record 3 {record}", SSH);
    let config_before = names(&host.paths.config_dir);
    host.run(false).unwrap_err();

    assert_eq!(names(&host.paths.config_dir), config_before);
    let args = recorded(&host, "ARG ");
    assert_eq!(args[0], "-c");
    assert!(!Path::new(&args[1]).exists(), "{} was left behind", args[1]);
}

// refusals before frpc starts -----

#[test]
fn missing_token_file_is_refused() {
    let host = Host::new("exit 0", SSH);
    fs::remove_file(host.paths.secrets_dir.join("host.token")).unwrap();
    host.assert_refused("host.token");
}

#[test]
fn empty_token_is_refused() {
    let host = Host::new("exit 0", SSH);
    fs::write(host.paths.secrets_dir.join("bridge.token"), " \r\n").unwrap();
    host.assert_refused("bridge.token");
}

#[test]
fn unloadable_config_is_refused() {
    let host = Host::new("exit 0", SSH);
    fs::write(host.paths.config_dir.join("config.yaml"), "host: [").unwrap();
    host.assert_refused("config.yaml");
}

#[test]
fn unspawnable_tool_is_refused() {
    let host = Host::new("exit 0", SSH);
    fs::remove_file(&host.frpc).unwrap();
    host.assert_refused("frpc");
    assert!(host.log(LOG_SUPERVISOR).contains("frpc"));
}

#[test]
fn unopenable_log_is_refused() {
    let host = Host::new("exit 0", SSH);
    fs::create_dir(host.paths.log_dir.join(LOG_FRPC)).unwrap();
    host.assert_refused(LOG_FRPC);
}

#[test]
fn listener_bind_failure_is_logged() {
    let host = Host::new("exit 0", SSH);
    let taken = StdListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let err = format!("{:#}", host.run_listening(taken.local_addr().unwrap()).unwrap_err());
    assert!(err.contains(&taken.local_addr().unwrap().to_string()), "{err}");
    assert_eq!(host.log(LOG_SUPERVISOR).trim_end(), err);
}

// rotation -----

#[test]
fn rotation_keeps_two_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.log");
    let log = LogFile::open(path.clone(), 10).unwrap();
    for chunk in ["aaaaaaaaaaaa", "b", "cccccccccc", "d"] {
        log.write(chunk.as_bytes());
    }
    assert_eq!(names(dir.path()), ["x.log", "x.log.1"]);
    assert_eq!(fs::read_to_string(&path).unwrap(), "d");
    assert_eq!(fs::read_to_string(dir.path().join("x.log.1")).unwrap(), "bcccccccccc");
}

#[test]
fn failed_rotation_is_logged_and_retried_at_the_next_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let (path, old) = (dir.path().join("x.log"), dir.path().join("x.log.1"));
    // A rename cannot replace a directory that holds a file.
    fs::create_dir(&old).unwrap();
    fs::write(old.join("blocker"), "").unwrap();
    let log = LogFile::open(path.clone(), 10).unwrap();
    log.write(b"aaaaaaaaaaaa");
    log.write(b"b");
    let kept = fs::read_to_string(&path).unwrap();
    assert!(
        kept.starts_with("aaaaaaaaaaaa") && kept.contains("rotat") && kept.ends_with('b'),
        "{kept}"
    );

    fs::remove_dir_all(&old).unwrap();
    log.write(b"c");
    assert!(!old.exists(), "retried before the next threshold");
    log.write(b"dddddddddd");
    log.write(b"e");
    assert!(old.is_file());
    assert_eq!(fs::read_to_string(&path).unwrap(), "e");
}

// the WebSocket listener -----

/// Accepts one connection, sends `banner`, and returns what it receives until the peer's end.
async fn backend(banner: &'static str) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        conn.write_all(banner.as_bytes()).await.unwrap();
        let mut received = Vec::new();
        conn.read_to_end(&mut received).await.unwrap();
        received
    });
    (port, received)
}

/// Reads the banner, sends `payload`, and closes cleanly.
async fn talk(mut ws: WebSocketStream<TcpStream>, payload: &str) -> Message {
    let banner = ws.next().await.unwrap().unwrap();
    ws.send(Message::binary(payload.as_bytes().to_vec())).await.unwrap();
    ws.close(None).await.unwrap();
    while let Some(message) = ws.next().await {
        message.unwrap();
    }
    banner
}

#[tokio::test]
async fn ws_forwards_by_host() {
    let ((ssh_port, ssh), (vnc_port, vnc)) = (backend("ssh banner").await, backend("vnc banner").await);
    let live = Live::start(&tcp_services(ssh_port, vnc_port)).await;

    // The default service answers at the bare host name, here with a port as a browser or proxy may add.
    let banner = talk(live.connect("testhost.tunnel.example:443").await.unwrap(), "to ssh").await;
    assert_eq!(banner, Message::binary(&b"ssh banner"[..]));
    let banner = talk(live.connect("vnc.testhost.tunnel.example").await.unwrap(), "to vnc").await;
    assert_eq!(banner, Message::binary(&b"vnc banner"[..]));
    // A backend sees the end of its stream only when the WebSocket close reached it.
    assert_eq!(ssh.await.unwrap(), b"to ssh");
    assert_eq!(vnc.await.unwrap(), b"to vnc");
    live.stop().await;
}

#[tokio::test]
async fn ws_unknown_host_refused() {
    let live = Live::start(&tcp_services(22, 5900)).await;
    let Err(Error::Http(response)) = live.connect("nosuch.testhost.tunnel.example").await else {
        panic!("the upgrade was not refused with an HTTP response");
    };
    assert_eq!(response.status(), 404);
    live.stop().await;
}

#[tokio::test]
async fn ws_closes_when_the_backend_closes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { listener.accept().await.unwrap().0.write_all(b"bye").await.unwrap() });
    let live = Live::start(&tcp_services(port, 5900)).await;

    let mut ws = live.connect("ssh.testhost.tunnel.example").await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::binary(&b"bye"[..]));
    assert!(matches!(ws.next().await, None | Some(Ok(Message::Close(_)))));
    live.stop().await;
}

#[tokio::test]
async fn a_failed_connection_is_logged_and_does_not_stop_run() {
    // Bound but not listening: connects are refused, and no other process can take the port.
    let held = TcpSocket::new_v4().unwrap();
    held.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let dead = held.local_addr().unwrap();
    let live = Live::start(&tcp_services(dead.port(), 5900)).await;

    let mut ws = live.connect("ssh.testhost.tunnel.example").await.unwrap();
    assert!(matches!(ws.next().await, Some(Err(_))));
    // That run ended because frpc did, not because of the failed connection.
    let (host, err) = live.stop().await;
    assert!(err.contains("frpc exited"), "{err}");
    assert!(host.log(LOG_SUPERVISOR).contains(&dead.to_string()));
}
