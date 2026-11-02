use std::env::consts::{ARCH, EXE_SUFFIX, OS};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use sha2::{Digest, Sha256};

use crate::paths::Paths;

/// The targets `reverse-tunnel` is released for; `PINS` has one pin for each.
pub const RELEASE_TARGETS: [&str; 5] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

const VERSION: &str = "0.71.1";

/// A tool release archive, and the one file of it that gets installed. `url` ends in `.zip` or `.tar.gz`.
pub struct Pin {
    pub name: &'static str,
    pub version: &'static str,
    pub target: &'static str,
    pub url: &'static str,
    /// Lowercase hex SHA-256 of the archive.
    pub sha256: &'static str,
    /// The path of the tool inside the archive.
    pub member: &'static str,
}

/// frpc, one pin per release target.
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

/// Where the pinned tools sit once fetched into `Paths::bin_dir`.
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

/// The pin for the OS and architecture this binary runs on.
pub fn host_pin() -> Result<&'static Pin> {
    let target = match (OS, ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        _ => bail!("no pinned frpc for {OS} on {ARCH}"),
    };
    Ok(PINS
        .iter()
        .find(|pin| pin.target == target)
        .expect("PINS has every release target"))
}

/// Downloads `pin` into memory and writes its tool into `dest_dir` as `<name>-<version>`. No archive touches disk.
pub fn fetch(pin: &Pin, dest_dir: &Path) -> Result<PathBuf> {
    let mut archive = Vec::new();
    let body = ureq::get(pin.url)
        .call()
        .with_context(|| format!("downloading {}", pin.url))?;
    (body.into_body().into_reader().read_to_end(&mut archive)).with_context(|| format!("downloading {}", pin.url))?;
    install(pin, &archive, dest_dir)
}

/// Checks `archive` against the pinned digest, then writes only the pinned member. A mismatch writes nothing.
fn install(pin: &Pin, archive: &[u8], dest_dir: &Path) -> Result<PathBuf> {
    let digest = hex::encode(Sha256::digest(archive));
    ensure!(
        digest == pin.sha256,
        "{} has SHA-256 {digest}, not the pinned {}",
        pin.url,
        pin.sha256
    );
    let mut tool = Vec::new();
    if pin.url.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(Cursor::new(archive))?;
        zip.by_name(pin.member)
            .with_context(|| format!("{} in {}", pin.member, pin.url))?
            .read_to_end(&mut tool)?;
    } else {
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
        let mut entries = tar.entries()?;
        let mut member = entries
            .find(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.path().is_ok_and(|path| path == Path::new(pin.member)))
            })
            .ok_or_else(|| anyhow!("{} not in {}", pin.member, pin.url))??;
        member.read_to_end(&mut tool)?;
    }
    write_executable(&dest_dir.join(file_name(pin.name, pin.version)), &tool)
}

/// Writes `data` to `dest` through a temp file in the same directory, so `dest` is never partial.
fn write_executable(dest: &Path, data: &[u8]) -> Result<PathBuf> {
    let dir = dest.parent().expect("dest is inside a directory");
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file().set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist(dest)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(dest.to_path_buf())
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod tests;
