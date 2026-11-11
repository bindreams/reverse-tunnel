use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use sha2::{Digest, Sha256};

use super::*;

const ASSET: &str = "reverse-tunnel-x86_64-unknown-linux-gnu";
const BINARY: &[u8] = b"the newer build";

fn sums_line(data: &[u8], separator: &str) -> String {
    format!("{}{separator}{ASSET}\n", hex::encode(Sha256::digest(data)))
}

/// One response per route: its path, status, `Location` and body.
type Route = (&'static str, u16, Option<&'static str>, Vec<u8>);

/// Serves `routes` on a local port, one connection at a time. Returns the releases URL and the requests so far
/// (`METHOD path`).
fn serve(routes: Vec<Route>) -> (String, Arc<Mutex<Vec<String>>>) {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/releases", server.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    thread::spawn(move || {
        for conn in server.incoming() {
            let mut conn = conn.unwrap();
            let mut lines = BufReader::new(&conn).lines();
            let request = lines.next().unwrap().unwrap();
            // The whole request, so that closing after the reply does not reset the connection.
            while !lines.next().unwrap().unwrap().is_empty() {}
            let mut words = request.split(' ');
            let (method, path) = (words.next().unwrap().to_string(), words.next().unwrap().to_string());
            log.lock().unwrap().push(format!("{method} {path}"));
            let (_, status, location, body) = routes.iter().find(|route| route.0 == path).expect("a known path");
            let location = location.map(|to| format!("Location: {to}\r\n")).unwrap_or_default();
            write!(
                conn,
                "HTTP/1.1 {status} X\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            if method == "GET" {
                conn.write_all(body).unwrap();
            }
        }
    });
    (base, seen)
}

#[test]
fn sha256sums_parsing() {
    let digest = hex::encode(Sha256::digest(BINARY));
    let other = "0".repeat(64);
    let rows = [
        (format!("{digest}  {ASSET}\n"), Some(digest.as_str())),
        (format!("{digest} *{ASSET}\n"), Some(digest.as_str())),
        (
            format!("{other}  reverse-tunnel-other\n{digest}  {ASSET}\n{other}  x\n"),
            Some(digest.as_str()),
        ),
        (format!("{other}  {ASSET}.sig\n{other}  reverse-tunnel-other\n"), None),
    ];
    for (text, want) in rows {
        assert_eq!(expected_digest(&text, ASSET).ok(), want, "{text:?}");
    }
}

#[test]
fn fetch_release_resolves_the_tag_once() {
    let download = "/releases/download/v7";
    let (base, seen) = serve(vec![
        ("/releases/latest", 302, Some("/releases/tag/v7"), vec![]),
        ("/releases/tag/v7", 200, None, vec![]),
        (
            "/releases/download/v7/SHA256SUMS",
            200,
            None,
            sums_line(BINARY, "  ").into_bytes(),
        ),
        (
            "/releases/download/v7/reverse-tunnel-x86_64-unknown-linux-gnu",
            200,
            None,
            BINARY.to_vec(),
        ),
    ]);

    let got = fetch_release(&base, ASSET).unwrap();

    assert_eq!(got, BINARY);
    let seen = seen.lock().unwrap();
    assert_eq!(seen[..2], ["HEAD /releases/latest", "HEAD /releases/tag/v7"]);
    assert!(seen[2..].iter().all(|request| request.contains(download)), "{seen:?}");
}

#[test]
fn upgrade_rejects_bad_release_digest() {
    let (base, _) = serve(vec![
        ("/releases/latest", 302, Some("/releases/tag/v7"), vec![]),
        ("/releases/tag/v7", 200, None, vec![]),
        (
            "/releases/download/v7/SHA256SUMS",
            200,
            None,
            sums_line(BINARY, "  ").into_bytes(),
        ),
        (
            "/releases/download/v7/reverse-tunnel-x86_64-unknown-linux-gnu",
            200,
            None,
            b"a tampered build".to_vec(),
        ),
    ]);

    let err = fetch_release(&base, ASSET).unwrap_err();

    assert!(
        err.to_string().contains(&hex::encode(Sha256::digest(BINARY))),
        "{err:#}"
    );
}

#[test]
fn upgrade_http_error() {
    let (base, _) = serve(vec![
        ("/releases/latest", 302, Some("/releases/tag/v7"), vec![]),
        ("/releases/tag/v7", 200, None, vec![]),
        ("/releases/download/v7/SHA256SUMS", 404, None, vec![]),
    ]);

    let err = fetch_release(&base, ASSET).unwrap_err();

    assert!(
        format!("{err:#}").contains(&format!("{base}/download/v7/SHA256SUMS")),
        "{err:#}"
    );
}

#[test]
fn upgrade_needs_a_published_release() {
    // With no release, GitHub sends `releases/latest` to the list of releases.
    let (base, _) = serve(vec![
        ("/releases/latest", 302, Some("/releases"), vec![]),
        ("/releases", 200, None, vec![]),
    ]);

    let err = fetch_release(&base, ASSET).unwrap_err();

    assert!(err.to_string().contains("not a release page"), "{err:#}");
}

#[test]
fn two_upgrades_stage_separate_executables() {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir(&paths.bin_dir).unwrap();

    let (first, second) = (stage(&paths, b"same").unwrap(), stage(&paths, b"same").unwrap());

    assert_ne!(first, second);
    assert_eq!(fs::read(&first).unwrap(), b"same");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(first.metadata().unwrap().permissions().mode() & 0o777, 0o755);
    }
}
