use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use sha2::{Digest, Sha256};

use super::*;
use crate::test_support::Closed;

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
            // Read the whole request first: closing with unread input resets the connection.
            while !lines.next().unwrap().unwrap().is_empty() {}
            let mut words = request.split(' ');
            let (method, path) = (words.next().unwrap().to_string(), words.next().unwrap().to_string());
            log.lock().unwrap().push(format!("{method} {path}"));
            let (_, status, location, body) = routes.iter().find(|route| route.0 == path).expect("a known path");
            let location = location.map(|to| format!("Location: {to}\r\n")).unwrap_or_default();
            let mut response = format!(
                "HTTP/1.1 {status} X\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            if method == "GET" {
                response.extend_from_slice(body);
            }
            // One write: ureq follows a redirect as soon as it has the `Location` line and closes this connection, so
            // a head sent in pieces would meet a closed socket. A failed write means the client has left.
            let _ = conn.write_all(&response);
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

/// The routes of the release `v7` whose `SHA256SUMS` lists `BINARY`, and which serves `served` as the binary.
fn release_serving(served: &[u8]) -> Vec<Route> {
    vec![
        ("/releases/latest", 302, Some("/releases/tag/v7"), vec![]),
        ("/releases/tag/v7", 200, None, b"the release page".to_vec()),
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
            served.to_vec(),
        ),
    ]
}

#[test]
fn fetch_release_resolves_the_tag_once() {
    let download = "/releases/download/v7";
    let (base, seen) = serve(release_serving(BINARY));

    let got = fetch_release(&base, ASSET, &mut io::sink()).unwrap();

    assert_eq!(got, BINARY);
    let seen = seen.lock().unwrap();
    assert_eq!(seen[..2], ["HEAD /releases/latest", "HEAD /releases/tag/v7"]);
    assert!(seen[2..].iter().all(|request| request.contains(download)), "{seen:?}");
}

/// `fetch_release`'s output when it ends in `result`, from a server that has `routes`.
fn said_while_fetching(routes: Vec<Route>) -> (String, Result<Vec<u8>>) {
    let (base, _) = serve(routes);
    let mut out = Vec::new();
    let fetched = fetch_release(&base, ASSET, &mut out);
    (String::from_utf8(out).unwrap(), fetched)
}

#[test]
fn the_check_is_announced_before_it_is_made_and_the_download_before_it_starts() {
    let (said, fetched) = said_while_fetching(vec![("/releases/latest", 404, None, vec![])]);
    fetched.unwrap_err();
    assert_eq!(said, "Checking for a new version...\n");

    let (said, fetched) = said_while_fetching(vec![
        ("/releases/latest", 302, Some("/releases/tag/v7"), vec![]),
        ("/releases/tag/v7", 200, None, b"the release page".to_vec()),
        ("/releases/download/v7/SHA256SUMS", 404, None, vec![]),
    ]);
    fetched.unwrap_err();
    assert_eq!(said, "Checking for a new version...\nDownloading v7...\n");
}

/// The lines are information: a stdout that is closed does not abort an upgrade.
#[test]
fn a_closed_stdout_does_not_stop_the_download() {
    let (base, _) = serve(release_serving(BINARY));

    let got = fetch_release(&base, ASSET, &mut Closed).unwrap();

    assert_eq!(got, BINARY);
}

#[test]
fn upgrade_rejects_bad_release_digest() {
    let (base, _) = serve(release_serving(b"a tampered build"));

    let err = fetch_release(&base, ASSET, &mut io::sink()).unwrap_err();

    let (listed, served) = (
        hex::encode(Sha256::digest(BINARY)),
        hex::encode(Sha256::digest(b"a tampered build")),
    );
    let err = err.to_string();
    assert!(err.contains(&listed) && err.contains(&served), "{err}");
}

#[test]
fn upgrade_http_error() {
    let (base, _) = serve(vec![
        ("/releases/latest", 302, Some("/releases/tag/v7"), vec![]),
        ("/releases/tag/v7", 200, None, b"the release page".to_vec()),
        ("/releases/download/v7/SHA256SUMS", 404, None, vec![]),
    ]);

    let err = fetch_release(&base, ASSET, &mut io::sink()).unwrap_err();

    let err = format!("{err:#}");
    assert!(
        err.contains(&format!("{base}/download/v7/SHA256SUMS")) && err.contains("404"),
        "{err}"
    );
}

#[test]
fn upgrade_needs_a_published_release() {
    // With no release, GitHub sends `releases/latest` to the list of releases. A tag page ends the URL at the tag.
    for ended in ["/releases", "/releases/tag/", "/releases/tag/v7/assets"] {
        let (base, _) = serve(vec![
            ("/releases/latest", 302, Some(ended), vec![]),
            (ended, 200, None, vec![]),
        ]);

        let err = fetch_release(&base, ASSET, &mut io::sink()).unwrap_err();

        assert!(err.to_string().contains("not a release page"), "{ended}: {err:#}");
    }
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
