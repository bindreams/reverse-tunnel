//! `run` against `testbin/stub_frpc.rs`. These bind ports and spawn processes, so they run in a container or on CI.

use std::fs;
use std::net::{Ipv4Addr, TcpListener as StdListener};
use std::path::Path;

use futures_util::{SinkExt, StreamExt};
use jiff::Timestamp;
use jiff::fmt::temporal::Pieces;
use jiff::tz::TimeZone;
use reverse_tunnel::logfile::LogFile;
use reverse_tunnel::paths::{LOG_FRPC, LOG_SUPERVISOR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error, Message};

#[path = "support/host.rs"]
mod host;
use host::{Host, Live, refused_port, tcp_services};

const SSH: &str = "  ssh: {port: 22, type: tcp}\n";

fn recorded(host: &Host, prefix: &str) -> Vec<String> {
    let record = fs::read_to_string(host.record()).unwrap();
    record
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(str::to_string)
        .collect()
}

fn stamped(line: &str) -> &str {
    let (stamp, message) = line.trim_end().split_once(' ').expect("a timestamp and a message");
    assert_eq!(stamp.len(), "YYYY-MM-DDTHH:MM:SS+HH:MM".len(), "{stamp:?}");
    let at: Timestamp = stamp
        .parse()
        .unwrap_or_else(|e| panic!("{stamp:?} is not RFC 3339: {e}"));
    let offset = Pieces::parse(stamp).unwrap().to_numeric_offset();
    assert_eq!(
        offset,
        Some(TimeZone::system().to_offset(at)),
        "{stamp:?} is not local time"
    );
    message
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn check_renders_and_verifies_without_starting() {
    let host = Host::new("record 0 {record}", SSH);
    let (config_before, logs_before) = (names(&host.paths.config_dir), names(&host.paths.log_dir));

    assert_eq!(host.run(true).unwrap(), std::process::ExitCode::SUCCESS);

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

#[test]
fn check_fails_when_frpc_rejects_the_config() {
    let host = Host::new("exit 1", SSH);
    let err = format!("{:#}", host.run(true).unwrap_err());
    assert!(err.contains("frpc verify rejected the configuration"), "{err}");
}

#[test]
fn child_exit_stops_others_and_exits_nonzero() {
    let host = Host::new("exit 7", SSH);
    let err = format!("{:#}", host.run(false).unwrap_err());
    assert!(err.contains("frpc exited") && err.contains('7'), "{err}");
    let log = host.log(LOG_SUPERVISOR);
    assert_eq!(stamped(&log), err);
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
    for file in [LOG_SUPERVISOR, LOG_FRPC, "frpc.toml"] {
        seen.push(host.log(file));
    }
    for text in seen {
        assert!(
            !text.contains("bridge-secret") && !text.contains("host-secret"),
            "{text}"
        );
    }
}

#[test]
fn run_renders_into_the_log_dir_and_leaves_the_config_dir_alone() {
    let host = Host::new("record 3 {record}", SSH);
    let config_before = names(&host.paths.config_dir);
    // Longer than the render, so a write that does not truncate leaves its tail behind.
    fs::write(host.paths.log_dir.join("frpc.toml"), "# stale\n".repeat(1000)).unwrap();
    host.run(false).unwrap_err();

    assert_eq!(names(&host.paths.config_dir), config_before);
    let args = recorded(&host, "ARG ");
    assert_eq!(
        args[..2],
        [
            "-c".to_string(),
            host.paths.log_dir.join("frpc.toml").display().to_string()
        ]
    );
    let record = fs::read_to_string(host.record()).unwrap();
    let rendered = record.split_once("TOML\n").unwrap().1;
    assert!(
        rendered.starts_with("serverAddr = ") && !rendered.contains("stale"),
        "{rendered}"
    );
}

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
    let starting = format!("starting {}", host.frpc.display());
    host.assert_refused(&starting);
    assert!(host.log(LOG_SUPERVISOR).contains(&starting));
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
    assert_eq!(stamped(&host.log(LOG_SUPERVISOR)), err);
}

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
    assert!(kept.starts_with("aaaaaaaaaaaa") && kept.ends_with('b'), "{kept}");
    let note = kept["aaaaaaaaaaaa".len()..].lines().next().unwrap();
    assert!(stamped(note).starts_with("log rotation failed"), "{note}");

    fs::remove_dir_all(&old).unwrap();
    log.write(b"c");
    assert!(!old.exists(), "retried before the next threshold");
    log.write(b"dddddddddd");
    log.write(b"e");
    assert!(old.is_file());
    assert_eq!(fs::read_to_string(&path).unwrap(), "e");
}

/// More than one read chunk of the supervisor's, so that a payload cut at a chunk boundary shows.
fn blob(label: &str) -> Vec<u8> {
    (label.bytes().chain((0..100 * 1024).map(|i| (i % 251) as u8))).collect()
}

/// Accepts one connection, sends `banner`, and returns what it receives until the peer's end.
async fn backend(banner: Vec<u8>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        conn.write_all(&banner).await.unwrap();
        let mut received = Vec::new();
        conn.read_to_end(&mut received).await.unwrap();
        received
    });
    (port, received)
}

/// Reads `banner`, sends `payload`, and closes cleanly.
async fn talk(mut ws: WebSocketStream<TcpStream>, banner: &[u8], payload: &[u8]) {
    let mut read = Vec::new();
    while read.len() < banner.len() {
        read.extend(ws.next().await.unwrap().unwrap().into_data());
    }
    assert!(read == banner, "the banner arrived changed");
    ws.send(Message::binary(payload.to_vec())).await.unwrap();
    ws.close(None).await.unwrap();
    while let Some(message) = ws.next().await {
        message.unwrap();
    }
}

#[tokio::test]
async fn ws_forwards_by_host() {
    let (ssh_banner, vnc_banner) = (blob("ssh banner"), blob("vnc banner"));
    let ((ssh_port, ssh), (vnc_port, vnc)) = (backend(ssh_banner.clone()).await, backend(vnc_banner.clone()).await);
    let live = Live::start(&tcp_services(ssh_port, vnc_port)).await;
    let (to_ssh, to_vnc) = (blob("to ssh"), blob("to vnc"));

    // The default service answers at the bare host name, here with a port as a browser or proxy may add.
    talk(
        live.connect("testhost.tunnel.example:443").await.unwrap(),
        &ssh_banner,
        &to_ssh,
    )
    .await;
    // Host names are case-insensitive: Traefik forwards them as typed.
    talk(
        live.connect("VNC.TESTHOST.TUNNEL.EXAMPLE").await.unwrap(),
        &vnc_banner,
        &to_vnc,
    )
    .await;
    // A backend sees the end of its stream only when the WebSocket close reached it.
    assert!(ssh.await.unwrap() == to_ssh, "the payload arrived changed");
    assert!(vnc.await.unwrap() == to_vnc, "the payload arrived changed");
    live.stop().await;
}

#[tokio::test]
async fn ws_unknown_host_refused() {
    let (_held, dead) = refused_port();
    let live = Live::start(&tcp_services(dead, dead)).await;
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
    let (_held, dead) = refused_port();
    let live = Live::start(&tcp_services(port, dead)).await;

    let mut ws = live.connect("ssh.testhost.tunnel.example").await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::binary(&b"bye"[..]));
    assert!(matches!(ws.next().await, None | Some(Ok(Message::Close(_)))));
    live.stop().await;
}

#[tokio::test]
async fn a_failed_connection_is_logged_and_does_not_stop_run() {
    let (_held, dead) = refused_port();
    let live = Live::start(&tcp_services(dead, dead)).await;

    let mut ws = live.connect("ssh.testhost.tunnel.example").await.unwrap();
    assert!(matches!(ws.next().await, Some(Err(_))));
    // That run ended because frpc did, not because of the failed connection.
    let (host, err) = live.stop().await;
    assert!(err.contains("frpc exited"), "{err}");
    assert!(host.log(LOG_SUPERVISOR).contains(&format!("127.0.0.1:{dead}")));
}
