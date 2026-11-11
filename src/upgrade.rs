//! `reverse-tunnel upgrade`: gets a newer binary, which then installs itself (see `install`).

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::download::{STALL, download, host_target, verify_digest};
use crate::files::{Perm, Replace, write_atomic};
use crate::paths::Paths;

const RELEASES: &str = "https://github.com/bindreams/reverse-tunnel/releases";

/// What the downloaded binary's file name starts with in the bin dir.
const STAGED: &str = "upgrade-";

/// Where an upgrade puts a downloaded binary with SHA-256 `digest` to run it. `clean_bin_dir` leaves it alone, so that
/// an `install` running meanwhile cannot take it away; the `install` it runs removes it (`is_staged`).
pub fn staged(paths: &Paths, digest: &str) -> PathBuf {
    paths.bin_dir.join(format!("{STAGED}{digest}"))
}

/// Whether `exe` is a file `staged` named. `install` removes its own once it has read it: the upgrade that staged it
/// may be gone with its session by the time the service is killed, which is `install`'s last act.
pub fn is_staged(exe: &Path) -> bool {
    exe.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(STAGED))
}

/// Runs `install` of the binary at `from`, or of the latest release's for this platform, checked against the
/// release's `SHA256SUMS`. That `install` checks the new settings, replaces the binary and restarts the service.
pub fn upgrade(paths: &Paths, from: Option<&Path>) -> Result<()> {
    let Some(from) = from else {
        let binary = fetch_release(RELEASES, &format!("reverse-tunnel-{}{EXE_SUFFIX}", host_target()?))?;
        let staged = staged(paths, &hex::encode(Sha256::digest(&binary)));
        write_atomic(&staged, &binary, Perm::EXECUTABLE, Replace::Always)
            .context("staging the download in the bin dir: is reverse-tunnel installed?")?;
        let installed = install_with(&staged);
        // `install` removes it itself, unless it failed before.
        let _ = fs::remove_file(&staged);
        return installed;
    };
    // By path: a bare name would be looked up on `PATH`, and could run the installed binary instead.
    let from = fs::canonicalize(from).with_context(|| format!("finding {}", from.display()))?;
    install_with(&from)
}

/// Runs `exe install` with this terminal: its warnings and the registration line are for the operator.
fn install_with(exe: &Path) -> Result<()> {
    let status = cosca::run([exe.as_os_str(), "install".as_ref()])
        .status()
        .with_context(|| format!("running {} install", exe.display()))?;
    ensure!(status.success(), "{} install ended with {status}", exe.display());
    Ok(())
}

/// The latest release's `asset`. The tag is resolved once, so that the binary and its `SHA256SUMS` are
/// of the same release even if one is published meanwhile.
fn fetch_release(releases: &str, asset: &str) -> Result<Vec<u8>> {
    let latest = format!("{releases}/latest");
    let ended = download(&latest, STALL)?.url;
    // GitHub sends `releases/latest` to the page of the latest release, or to the list of releases when there is none.
    let tag = ended
        .split_once("/releases/tag/")
        .map(|(_, tag)| tag)
        .filter(|tag| !tag.is_empty() && !tag.contains(['/', '?', '#']))
        .with_context(|| format!("no release is published: {latest} led to {ended}"))?;

    let url = |name: &str| format!("{releases}/download/{tag}/{name}");
    let sums = String::from_utf8(download(&url("SHA256SUMS"), STALL)?.body).context("SHA256SUMS is not text")?;
    let want = expected_digest(&sums, asset)?;
    let binary = download(&url(asset), STALL)?.body;
    verify_digest(&url(asset), &binary, want, "SHA256SUMS")?;
    Ok(binary)
}

/// The digest `sums` (`sha256sum` output: `<hex>  <name>`, or `<hex> *<name>`) lists for `asset`.
fn expected_digest<'a>(sums: &'a str, asset: &str) -> Result<&'a str> {
    sums.lines()
        .find_map(|line| {
            let (digest, name) = line.split_once(' ')?;
            (name.trim_start_matches([' ', '*']) == asset).then_some(digest)
        })
        .with_context(|| format!("SHA256SUMS lists no {asset}"))
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
