use std::env::consts::{ARCH, EXE_SUFFIX, OS};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use ureq::ResponseExt;

use crate::files::{Perm, Replace, write_atomic};
use crate::paths::Paths;

/// The targets `reverse-tunnel` is released for.
pub const RELEASE_TARGETS: [&str; 5] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

const VERSION: &str = "0.71.1";

/// How long a download may deliver nothing before `fetch` gives up on it.
pub(crate) const STALL: Duration = Duration::from_secs(60);

/// A tool release archive, and the one file of it that gets installed. `url` ends in `.zip` or `.tar.gz`.
pub struct Pin {
    pub name: &'static str,
    pub version: &'static str,
    pub target: &'static str,
    pub url: &'static str,
    /// Lowercase hex SHA-256 of the archive.
    pub sha256: &'static str,
    pub member: &'static str,
}

pub const PINS: &[Pin] = &[
    Pin {
        name: "frpc",
        version: VERSION,
        target: "x86_64-unknown-linux-gnu",
        url: "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_linux_amd64.tar.gz",
        sha256: "1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803",
        member: "frp_0.71.1_linux_amd64/frpc",
    },
    Pin {
        name: "frpc",
        version: VERSION,
        target: "aarch64-unknown-linux-gnu",
        url: "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_linux_arm64.tar.gz",
        sha256: "8edf590b0c396fa42f9c147121a76af83cfc2002b08f5aef0ea1008c43482019",
        member: "frp_0.71.1_linux_arm64/frpc",
    },
    Pin {
        name: "frpc",
        version: VERSION,
        target: "x86_64-apple-darwin",
        url: "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_darwin_amd64.tar.gz",
        sha256: "8acb59b6fb998cc8d209d1373d90bf70fa5ec3efeb4dfbc7bda6ce3abd78cb45",
        member: "frp_0.71.1_darwin_amd64/frpc",
    },
    Pin {
        name: "frpc",
        version: VERSION,
        target: "aarch64-apple-darwin",
        url: "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_darwin_arm64.tar.gz",
        sha256: "d15d0324b99e14619c9aa46e37f6db588c06a09be4bc6f7948890b6b61077842",
        member: "frp_0.71.1_darwin_arm64/frpc",
    },
    Pin {
        name: "frpc",
        version: VERSION,
        target: "x86_64-pc-windows-msvc",
        url: "https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_windows_amd64.zip",
        sha256: "b90074b2b6a1d792a7a40f085ac6d276bcab2d1bc60201f8a86ca53ce65ce821",
        member: "frp_0.71.1_windows_amd64/frpc.exe",
    },
];

pub struct Tools {
    pub frpc: PathBuf,
}

pub fn tools(paths: &Paths) -> Tools {
    Tools {
        frpc: paths.bin_dir.join(file_name("frpc", VERSION)),
    }
}

/// The versioned name keeps a running tool untouched while a newer one is fetched.
fn file_name(name: &str, version: &str) -> String {
    format!("{name}-{version}{EXE_SUFFIX}")
}

/// The release target for the OS and architecture this binary runs on.
pub fn host_target() -> Result<&'static str> {
    Ok(match (OS, ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => bail!("no release for {OS} on {ARCH}"),
    })
}

/// The pin for the OS and architecture this binary runs on.
pub fn host_pin() -> Result<&'static Pin> {
    let target = host_target()?;
    Ok(PINS
        .iter()
        .find(|pin| pin.target == target)
        .expect("PINS has every release target"))
}

/// Writes the pinned tool into `dest_dir`, which must exist, as `<name>-<version>` (`.exe` on Windows), and returns
/// that path. An existing file of that name is kept, not replaced: only this module writes it, after the digest check,
/// and Windows cannot replace a running one. No archive touches disk.
pub fn fetch(pin: &Pin, dest_dir: &Path) -> Result<PathBuf> {
    let dest = dest_dir.join(file_name(pin.name, pin.version));
    if dest.try_exists()? {
        return Ok(dest);
    }
    install(pin, &download(pin.url, STALL)?, dest_dir)
}

/// What `transfer` got.
struct Transfer {
    /// Where the request ended, after redirects.
    url: String,
    body: Vec<u8>,
}

/// What the reader thread of `transfer` sends: where the request ended, then the body in chunks, the last empty.
enum Piece {
    Url(String),
    Chunk(Vec<u8>),
}

/// The body at `url`. Fails, naming `url`, when nothing arrives for `stall`; see `transfer`.
pub(crate) fn download(url: &str, stall: Duration) -> Result<Vec<u8>> {
    Ok(transfer(url, stall, false)?.body)
}

/// Where `url` ends up after redirects, from a HEAD request. Fails like `download`.
pub(crate) fn resolve(url: &str, stall: Duration) -> Result<String> {
    Ok(transfer(url, stall, true)?.url)
}

/// Fails, naming `url`, when nothing arrives for `stall`; a slow download that keeps progressing is never cut off. A
/// reader thread feeds the pieces, so the wait covers connecting too. `head`: a HEAD request, which has no body.
fn transfer(url: &str, stall: Duration, head: bool) -> Result<Transfer> {
    let (send, recv) = mpsc::channel();
    let owned = url.to_string();
    thread::spawn(move || {
        let read = || -> Result<()> {
            let response = if head { ureq::head(&owned) } else { ureq::get(&owned) }.call()?;
            send.send(Ok(Piece::Url(response.get_uri().to_string()))).ok();
            let mut body = response.into_body().into_reader();
            loop {
                let mut chunk = vec![0; 1 << 16];
                let len = body.read(&mut chunk)?;
                chunk.truncate(len);
                // An empty chunk is the end of the body.
                if send.send(Ok(Piece::Chunk(chunk))).is_err() || len == 0 {
                    return Ok(());
                }
            }
        };
        if let Err(err) = read() {
            let _ = send.send(Err(err));
        }
    });
    let mut got = Transfer {
        url: url.to_string(),
        body: Vec::new(),
    };
    loop {
        match recv.recv_timeout(stall) {
            Ok(piece) => match piece.with_context(|| format!("downloading {url}"))? {
                Piece::Url(ended) => got.url = ended,
                Piece::Chunk(chunk) if chunk.is_empty() => return Ok(got),
                Piece::Chunk(chunk) => got.body.extend(chunk),
            },
            Err(RecvTimeoutError::Disconnected) => bail!("downloading {url}: the reader stopped before the end"),
            Err(RecvTimeoutError::Timeout) => bail!("downloading {url}: no data for {stall:?}"),
        }
    }
}

/// Fails unless `data` has the SHA-256 `want` (hex), which `said_by` gave for `what`.
pub(crate) fn verify_digest(what: &str, data: &[u8], want: &str, said_by: &str) -> Result<()> {
    let digest = hex::encode(Sha256::digest(data));
    ensure!(
        digest.eq_ignore_ascii_case(want),
        "{what} has SHA-256 {digest}, not the {said_by} {want}"
    );
    Ok(())
}

/// Writes only the pinned member, and only if `archive` matches the pinned digest.
fn install(pin: &Pin, archive: &[u8], dest_dir: &Path) -> Result<PathBuf> {
    verify_digest(pin.url, archive, pin.sha256, "pinned")?;
    let mut tool = Vec::new();
    if pin.url.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(Cursor::new(archive))?;
        zip.by_name(pin.member)
            .with_context(|| format!("{} in {}", pin.member, pin.url))?
            .read_to_end(&mut tool)?;
    } else {
        let mut found = false;
        for entry in tar::Archive::new(flate2::read::GzDecoder::new(archive)).entries()? {
            let mut entry = entry?;
            if entry.path()? == Path::new(pin.member) {
                entry.read_to_end(&mut tool)?;
                found = true;
                break;
            }
        }
        ensure!(found, "{} not in {}", pin.member, pin.url);
    }
    let dest = dest_dir.join(file_name(pin.name, pin.version));
    write_atomic(&dest, &tool, Perm::EXECUTABLE, Replace::Never)?;
    Ok(dest)
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod tests;
