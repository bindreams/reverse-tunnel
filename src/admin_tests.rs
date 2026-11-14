use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

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

/// Answers one request with `status` and `body`, and gives the request it got.
fn serve(status: &'static str, body: &'static str) -> (u16, thread::JoinHandle<String>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 4096];
        let len = stream.read(&mut request).unwrap();
        let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        stream.write_all(response.as_bytes()).unwrap();
        String::from_utf8_lossy(&request[..len]).into_owned()
    });
    (port, served)
}

#[test]
fn get_sends_the_admin_user_and_password_and_returns_the_body() {
    let (port, served) = serve("200 OK", "{}");
    assert_eq!(get(port, "pw").unwrap(), "{}");
    let request = served.join().unwrap();
    let basic = STANDARD.encode("reverse-tunnel:pw");
    assert!(request.to_lowercase().contains("authorization: basic "), "{request}");
    assert!(request.contains(&basic), "{request}");
    assert!(request.to_lowercase().starts_with("get /api/status "), "{request}");
}

#[test]
fn get_says_when_the_password_is_refused() {
    let (port, _served) = serve("401 Unauthorized", "");
    assert!(format!("{:#}", get(port, "pw").unwrap_err()).contains("rejected the admin password"));
}

#[test]
fn get_says_when_nothing_answers() {
    let free = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert!(format!("{:#}", get(free, "pw").unwrap_err()).contains("did not answer"));
}

/// A host whose `admin_port` is `port` and whose admin password is `pw`, if any.
fn host(port: u16, password: Option<&str>, services: &str) -> (tempfile::TempDir, Config, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir_all(&paths.secrets_dir).unwrap();
    if let Some(password) = password {
        fs::write(paths.admin_password(), format!("{password}\n")).unwrap();
    }
    let yaml = format!("host: h\nbridge: t.example\nadmin_port: {port}\nservices:{services}");
    (dir, Config::parse(&yaml).unwrap(), paths)
}

const SSH: &str = "\n  ssh: {port: 22, type: tcp}\n";

#[test]
fn tunnel_is_connected_when_frpc_lists_the_services() {
    let (port, served) = serve("200 OK", ANSWER);
    let (_dir, config, paths) = host(port, Some("pw"), SSH);
    assert_eq!(tunnel(&config, &paths), Tunnel::Connected(parse(ANSWER).unwrap()));
    assert!(
        served.join().unwrap().contains(&STANDARD.encode("reverse-tunnel:pw")),
        "the file's newline is not part of the password"
    );
}

#[test]
fn tunnel_is_not_connected_when_frpc_lists_nothing() {
    let (port, _served) = serve("200 OK", "{}");
    let (_dir, config, paths) = host(port, Some("pw"), SSH);
    assert_eq!(tunnel(&config, &paths), Tunnel::NotConnected);
}

#[test]
fn tunnel_says_why_it_was_not_checked() {
    let (_dir, config, paths) = host(1, None, SSH);
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("admin.password"), "{why}");

    let (_dir, config, paths) = host(1, Some(""), SSH);
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("is empty"), "{why}");

    let (_dir, config, paths) = host(1, Some("pw"), " {}\n");
    let Tunnel::Unknown(why) = tunnel(&config, &paths) else {
        panic!()
    };
    assert!(why.contains("no service is published"), "{why}");
}
