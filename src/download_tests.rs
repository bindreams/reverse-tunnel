use std::io::{BufRead, BufReader, Cursor, Write};
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};

use super::*;

const BINARY: &[u8] = b"the frpc binary";
const DECOY: &[u8] = b"the frps binary";

fn tar_gz() -> Vec<u8> {
    let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for (path, data) in [("frp/frps", DECOY), ("frp/frpc", BINARY)] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        tar.append_data(&mut header, path, data).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

fn zip() -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, data) in [("frp/frps.exe", DECOY), ("frp/frpc.exe", BINARY)] {
        zip.start_file(path, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn pin_for(url: &'static str, member: &'static str, archive: &[u8]) -> Pin {
    Pin {
        name: "frpc",
        version: VERSION,
        target: "x86_64-unknown-linux-gnu",
        url,
        sha256: hex::encode(Sha256::digest(archive)).leak(),
        member,
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let names = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name());
    names.map(|name| name.into_string().unwrap()).collect()
}

#[test]
fn download_rejects_digest_mismatch() {
    let archive = tar_gz();
    let pin = pin_for("https://example.test/frp.tar.gz", "frp/frpc", &tar_gz());
    let dir = tempfile::tempdir().unwrap();
    let tampered = [archive.as_slice(), b"x"].concat();
    let err = install(&pin, &tampered, dir.path()).unwrap_err();
    assert!(err.to_string().contains(pin.sha256), "{err}");
    assert!(entries(dir.path()).is_empty());
}

#[test]
fn extracts_tar_gz_and_zip() {
    for (url, member, archive) in [
        ("https://example.test/frp.tar.gz", "frp/frpc", tar_gz()),
        ("https://example.test/frp.zip", "frp/frpc.exe", zip()),
    ] {
        let pin = pin_for(url, member, &archive);
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::testing(dir.path());
        std::fs::create_dir(&paths.bin_dir).unwrap();

        let written = install(&pin, &archive, &paths.bin_dir).unwrap();

        assert_eq!(written, tools(&paths).frpc, "{url}");
        assert_eq!(std::fs::read(&written).unwrap(), BINARY, "{url}");
        assert_eq!(entries(&paths.bin_dir).len(), 1, "{url}: only the member is written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(written.metadata().unwrap().permissions().mode() & 0o777, 0o755);
        }
    }
}

#[test]
fn pins_cover_release_targets() {
    let mut targets: Vec<_> = PINS.iter().map(|pin| pin.target).collect();
    targets.sort();
    let mut want = RELEASE_TARGETS.to_vec();
    want.sort();
    assert_eq!(targets, want);
}

#[test]
fn pins_carry_one_version() {
    for pin in PINS {
        for text in [pin.url, pin.member] {
            assert!(text.contains(pin.version), "{} lacks {}", text, pin.version);
        }
        assert_eq!(pin.version, VERSION, "{}", pin.url);
    }
}

#[test]
fn frp_pin_matches_server_dockerfile() {
    let dockerfile = include_str!("../server/Dockerfile");
    for (target, arch) in [
        ("x86_64-unknown-linux-gnu", "amd64"),
        ("aarch64-unknown-linux-gnu", "arm64"),
    ] {
        let pin = PINS.iter().find(|pin| pin.target == target).unwrap();
        let line = format!("{arch}) sha256={}", pin.sha256);
        assert!(dockerfile.contains(&line), "server/Dockerfile lacks `{line}`");
    }
}

#[test]
fn install_error_names_the_missing_directory() {
    let archive = tar_gz();
    let pin = pin_for("https://example.test/frp.tar.gz", "frp/frpc", &archive);
    let dir = tempfile::tempdir().unwrap().path().join("gone");
    let err = install(&pin, &archive, &dir).unwrap_err();
    assert!(format!("{err:#}").contains(dir.to_str().unwrap()), "{err:#}");
}

#[test]
fn fetch_keeps_an_installed_version() {
    let pin = pin_for("https://example.test/unreachable.tar.gz", "frp/frpc", &tar_gz());
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join(file_name(pin.name, pin.version));
    std::fs::write(&installed, b"installed").unwrap();
    assert_eq!(fetch(&pin, dir.path()).unwrap(), installed);
    assert_eq!(std::fs::read(&installed).unwrap(), b"installed");
}

#[test]
fn download_fails_when_the_server_stalls() {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/frp.tar.gz", server.local_addr().unwrap());
    let err = download(&url, Duration::from_millis(200)).unwrap_err();
    assert!(err.to_string().contains(&url), "{err}");
}

#[test]
fn download_keeps_a_slow_body_that_progresses() {
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/frp.tar.gz", server.local_addr().unwrap());
    let body: Vec<u8> = (0..12).collect();
    let sent = body.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = server.accept().unwrap();
        for line in BufReader::new(&conn).lines() {
            if line.unwrap().is_empty() {
                break;
            }
        }
        write!(
            conn,
            "HTTP/1.1 200 OK
Content-Length: {}

",
            sent.len()
        )
        .unwrap();
        for byte in sent {
            conn.write_all(&[byte]).unwrap();
            conn.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    // The gaps are shorter than the stall bound and the whole body is longer than it.
    assert_eq!(download(&url, Duration::from_millis(500)).unwrap(), body);
}

#[test]
fn install_keeps_a_file_that_appeared_first() {
    let archive = tar_gz();
    let pin = pin_for("https://example.test/frp.tar.gz", "frp/frpc", &archive);
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join(file_name(pin.name, pin.version));
    std::fs::write(&first, b"first").unwrap();
    assert_eq!(install(&pin, &archive, dir.path()).unwrap(), first);
    assert_eq!(std::fs::read(&first).unwrap(), b"first");
}

#[test]
fn pins_name_their_target_os_and_arch() {
    for pin in PINS {
        let os = match pin.target {
            t if t.contains("linux") => "linux",
            t if t.contains("apple") => "darwin",
            _ => "windows",
        };
        let arch = if pin.target.starts_with("x86_64") {
            "amd64"
        } else {
            "arm64"
        };
        for text in [pin.url, pin.member] {
            assert!(
                text.contains(&format!("_{os}_{arch}")),
                "{text} is not for {}",
                pin.target
            );
        }
    }
}

#[test]
#[ignore = "downloads from the network"]
fn fetch_every_pin() {
    for pin in PINS {
        let dir = tempfile::tempdir().unwrap();
        let written = fetch(pin, dir.path()).unwrap_or_else(|err| panic!("{}: {err:#}", pin.url));
        assert!(written.is_file(), "{}", pin.url);
    }
}
