use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

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

/// A pin for `archive`, whose format `url` names.
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
        let paths = Paths {
            bin_dir: dir.path().to_path_buf(),
            config_dir: PathBuf::new(),
            secrets_dir: PathBuf::new(),
            log_dir: PathBuf::new(),
            link: None,
        };

        let written = install(&pin, &archive, dir.path()).unwrap();

        assert_eq!(written, tools(&paths).frpc, "{url}");
        assert_eq!(std::fs::read(&written).unwrap(), BINARY, "{url}");
        assert_eq!(entries(dir.path()).len(), 1, "{url}: only the member is written");
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
fn frp_pin_matches_server_dockerfile() {
    let dockerfile = include_str!("../server/Dockerfile");
    for (target, arch) in [
        ("x86_64-unknown-linux-gnu", "amd64"),
        ("aarch64-unknown-linux-gnu", "arm64"),
    ] {
        let pin = PINS.iter().find(|pin| pin.target == target).unwrap();
        for line in [
            format!("{arch}) sha256={}", pin.sha256),
            format!("releases/download/v{}/", pin.version),
            format!("frp_{}_linux_", pin.version),
        ] {
            assert!(dockerfile.contains(&line), "server/Dockerfile lacks `{line}`");
        }
    }
}

/// Downloads every pinned URL; CI runs it with `--include-ignored`.
#[test]
#[ignore = "downloads from the network"]
fn fetch_every_pin() {
    for pin in PINS {
        let dir = tempfile::tempdir().unwrap();
        let written = fetch(pin, dir.path()).unwrap_or_else(|err| panic!("{}: {err:#}", pin.url));
        assert!(written.is_file(), "{}", pin.url);
    }
}
