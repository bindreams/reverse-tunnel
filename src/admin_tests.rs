use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::*;

/// What frpc 0.71.1 answers once logged in, for an http and a tcp proxy (its `/api/status` groups by proxy type).
const ANSWER: &str = r#"{"tcp":[{"name":"db","type":"tcp","status":"start error","err":"port in use","local_addr":"127.0.0.1:5432","plugin":"","remote_addr":""}],"http":[{"name":"web","type":"http","status":"running","err":"","local_addr":"127.0.0.1:8001","plugin":"","remote_addr":"web.myhost.example.com:8080"},{"name":"ssh","type":"http","status":"running","err":"","local_addr":"127.0.0.1:8000","plugin":"","remote_addr":"ssh.myhost.example.com:8080"}]}"#;

fn proxy(name: &str, status: &str, err: &str) -> Proxy {
    Proxy {
        name: name.into(),
        status: status.into(),
        err: err.into(),
    }
}

#[test]
fn parse_lists_every_proxy_whatever_its_type_by_name() {
    assert_eq!(
        parse(ANSWER).unwrap(),
        [
            proxy("db", "start error", "port in use"),
            proxy("ssh", "running", ""),
            proxy("web", "running", ""),
        ]
    );
}

/// Before frpc has logged in, and after it has lost the bridge, it answers `{}`.
#[test]
fn parse_of_an_answer_without_proxies_is_empty() {
    assert_eq!(parse("{}").unwrap(), []);
    assert!(parse("<html>").is_err());
}

#[test]
fn describe_says_each_state() {
    let connected = Tunnel::Connected(vec![
        proxy("ssh", "running", ""),
        proxy("db", "start error", "port in use"),
    ]);
    assert_eq!(
        describe("t.example", &connected),
        "bridge: t.example (connected)\npublished ssh: running\npublished db: start error (port in use)\n"
    );
    assert_eq!(
        describe("t.example", &Tunnel::NotConnected),
        "bridge: t.example (not connected)\n"
    );
    let unknown = Tunnel::Unknown("frpc did not answer".into());
    assert_eq!(
        describe("t.example", &unknown),
        "bridge: t.example (not checked: frpc did not answer)\n"
    );
}

/// Listens like frpc's admin API, over TLS with `pair`, answers one request with `status` and `body`, and gives the
/// request it read: nothing, when the client ended the handshake.
fn serve(pair: &KeyPair, status: &'static str, body: &'static str) -> (u16, thread::JoinHandle<String>) {
    let certs = CertificateDer::pem_slice_iter(pair.cert.as_bytes())
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(pair.key.as_bytes()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut stream = StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), stream);
        let mut request = [0; 4096];
        let Ok(len) = stream.read(&mut request) else {
            return String::new();
        };
        let response = format!(
            "HTTP/1.1 {status}
Content-Length: {}

{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.conn.send_close_notify();
        stream.flush().unwrap();
        String::from_utf8_lossy(&request[..len]).into_owned()
    });
    (port, served)
}

/// Listens without TLS, answers one request in plain HTTP, and gives the bytes it read.
fn serve_plain() -> (u16, thread::JoinHandle<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 4096];
        let len = stream.read(&mut request).unwrap_or(0);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK
Content-Length: 2

{}",
        );
        String::from_utf8_lossy(&request[..len]).into_owned()
    });
    (port, served)
}

#[test]
fn get_sends_the_admin_user_and_password_and_returns_the_body() {
    let pair = generate().unwrap();
    let (port, served) = serve(&pair, "200 OK", "{}");
    assert_eq!(get(port, pair.cert.as_bytes(), "pw").unwrap(), "{}");
    let request = served.join().unwrap();
    let basic = STANDARD.encode("reverse-tunnel:pw");
    assert!(request.to_lowercase().contains("authorization: basic "), "{request}");
    assert!(request.contains(&basic), "{request}");
    assert!(request.to_lowercase().starts_with("get /api/status "), "{request}");
}

#[test]
fn get_says_when_the_password_is_refused() {
    let pair = generate().unwrap();
    let (port, _served) = serve(&pair, "401 Unauthorized", "");
    assert!(
        format!("{:#}", get(port, pair.cert.as_bytes(), "pw").unwrap_err()).contains("rejected the admin password")
    );
}

#[test]
fn get_says_when_nothing_answers() {
    let free = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = format!(
        "{:#}",
        get(free, generate().unwrap().cert.as_bytes(), "pw").unwrap_err()
    );
    assert!(err.contains("frpc did not answer"), "{err}");
}

/// Another program on the port, with a certificate of its own, is not frpc, and is never sent the password.
#[test]
fn get_sends_nothing_to_a_listener_with_another_certificate() {
    let (ours, theirs) = (generate().unwrap(), generate().unwrap());
    let (port, served) = serve(&theirs, "200 OK", "{}");
    let err = format!("{:#}", get(port, ours.cert.as_bytes(), "pw").unwrap_err());
    assert!(err.contains("is not this host's frpc"), "{err}");
    assert_eq!(served.join().unwrap(), "", "the listener was sent a request");
}

#[test]
fn get_sends_nothing_to_a_listener_without_tls() {
    let (port, served) = serve_plain();
    let err = format!(
        "{:#}",
        get(port, generate().unwrap().cert.as_bytes(), "pw").unwrap_err()
    );
    assert!(err.contains("is not this host's frpc"), "{err}");
    let seen = served.join().unwrap();
    assert!(!seen.to_lowercase().contains("authorization") && !seen.contains(&STANDARD.encode("reverse-tunnel:pw")));
}

/// A host whose admin certificate is `pair`'s, whose admin password is `password` and whose recorded admin port is
/// `port`, if any.
fn host(
    pair: &KeyPair,
    port: Option<u16>,
    password: Option<&str>,
    services: &str,
) -> (tempfile::TempDir, Config, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir_all(&paths.secrets_dir).unwrap();
    fs::create_dir_all(&paths.log_dir).unwrap();
    if let Some(password) = password {
        fs::write(paths.admin_password(), format!("{password}\n")).unwrap();
    }
    fs::write(paths.admin_cert(), &pair.cert).unwrap();
    if let Some(port) = port {
        fs::write(paths.admin_port_file(), port.to_string()).unwrap();
    }
    let yaml = format!("host: h\nbridge: t.example\nservices:{services}");
    (dir, Config::parse(&yaml).unwrap(), paths)
}

const SSH: &str = "\n  ssh: {port: 22, type: tcp}\n";

#[test]
fn tunnel_is_connected_when_frpc_lists_the_services() {
    let pair = generate().unwrap();
    let (port, served) = serve(&pair, "200 OK", ANSWER);
    let (_dir, config, paths) = host(&pair, Some(port), Some("pw"), SSH);
    assert_eq!(tunnel(&config, &paths), Tunnel::Connected(parse(ANSWER).unwrap()));
    assert!(
        served.join().unwrap().contains(&STANDARD.encode("reverse-tunnel:pw")),
        "the file's newline is not part of the password"
    );
}

#[test]
fn tunnel_is_not_connected_when_frpc_lists_nothing() {
    let pair = generate().unwrap();
    let (port, _served) = serve(&pair, "200 OK", "{}");
    let (_dir, config, paths) = host(&pair, Some(port), Some("pw"), SSH);
    assert_eq!(tunnel(&config, &paths), Tunnel::NotConnected);
}

#[test]
fn tunnel_says_why_it_was_not_checked() {
    let (_dir, config, paths) = host(&generate().unwrap(), Some(1), None, SSH);
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("admin.password"), "{why}");

    let (_dir, config, paths) = host(&generate().unwrap(), Some(1), Some(""), SSH);
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("is empty"), "{why}");

    let (_dir, config, paths) = host(&generate().unwrap(), Some(1), Some("pw"), " {}\n");
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("no service is published"), "{why}");
}

#[test]
fn tunnel_reads_the_port_that_run_recorded() {
    let pair = generate().unwrap();
    let (port, served) = serve(&pair, "200 OK", ANSWER);
    let (_dir, config, paths) = host(&pair, None, Some("pw"), SSH);
    fs::write(paths.admin_port_file(), format!("{port}\r\n")).unwrap();
    assert!(matches!(tunnel(&config, &paths), Tunnel::Connected(_)));
    served.join().unwrap();
}

#[test]
fn tunnel_is_not_checked_when_the_service_has_recorded_no_port() {
    let (_dir, config, paths) = host(&generate().unwrap(), None, Some("pw"), SSH);
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(
        why.contains("has not started frpc, or could not write the file"),
        "{why}"
    );
}

#[test]
fn tunnel_is_not_checked_when_the_recorded_port_is_no_port() {
    for text in ["", "http", "65536", "0"] {
        let (_dir, config, paths) = host(&generate().unwrap(), None, Some("pw"), SSH);
        fs::write(paths.admin_port_file(), text).unwrap();
        let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
            panic!("{text:?}")
        };
        assert!(why.contains("frpc-admin.port"), "{why}");
    }
}

/// A host installed before the certificate existed has none until the next `install`.
#[test]
fn tunnel_is_not_checked_without_the_admin_certificate() {
    let (_dir, config, paths) = host(&generate().unwrap(), Some(1), Some("pw"), SSH);
    fs::remove_file(paths.admin_cert()).unwrap();
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("admin.crt"), "{why}");
}

#[test]
fn tunnel_is_not_checked_when_the_listener_is_not_frpc() {
    let theirs = generate().unwrap();
    let (port, served) = serve(&theirs, "200 OK", ANSWER);
    let (_dir, config, paths) = host(&generate().unwrap(), Some(port), Some("pw"), SSH);
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("not this host's frpc"), "{why}");
    assert_eq!(served.join().unwrap(), "");
}
