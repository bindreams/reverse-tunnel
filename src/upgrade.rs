//! `reverse-tunnel upgrade`: gets a newer binary, which then installs itself (see `install`).

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::download::{STALL, download, host_target, resolve, verify_digest};
use crate::files::{Perm, apply, remove_entry};
use crate::paths::Paths;

const RELEASES: &str = "https://github.com/bindreams/reverse-tunnel/releases";

/// What the file name of a downloaded binary starts with in the bin dir.
const STAGED: &str = "upgrade-";

/// Writes `binary` to a new executable file of its own in the bin dir, `upgrade-<random>`, and returns its path, to
/// run it. `clean_bin_dir` leaves such files alone, so that an `install` running meanwhile cannot take one away; the
/// `install` that runs it is told to remove it (`--staged`). What an interrupted upgrade leaves is in `upgrade --help`.
pub fn stage(paths: &Paths, binary: &[u8]) -> Result<PathBuf> {
    let write = || -> Result<PathBuf> {
        let mut file = tempfile::Builder::new().prefix(STAGED).tempfile_in(&paths.bin_dir)?;
        apply(file.as_file(), Perm::EXECUTABLE)?;
        file.write_all(binary)?;
        file.as_file().sync_all()?;
        // Closed before it is kept, which is before it runs.
        Ok(file.into_temp_path().keep()?)
    };
    write().with_context(|| {
        format!(
            "staging the download in {}: is reverse-tunnel installed?",
            paths.bin_dir.display()
        )
    })
}

/// Runs `install` of the binary at `from`, or of the latest release's for this platform, checked against the
/// release's `SHA256SUMS`. That `install` checks the new settings, replaces the binary and restarts the service.
pub fn upgrade(paths: &Paths, from: Option<&Path>) -> Result<()> {
    let Some(from) = from else {
        let binary = fetch_release(RELEASES, &format!("reverse-tunnel-{}{EXE_SUFFIX}", host_target()?))?;
        let staged = stage(paths, &binary)?;
        let installed = install_with(&staged, true);
        // `install` removes it itself, unless it failed before.
        if let Err(err) = remove_entry(&staged) {
            eprintln!("{err:#}; it is safe to delete");
        }
        return installed;
    };
    // By path: a bare name would be looked up on `PATH`, and could run the installed binary instead.
    let from = fs::canonicalize(from).with_context(|| format!("finding {}", from.display()))?;
    install_with(&from, false)
}

/// Runs `exe install` with this terminal: its warnings and the registration line are for the operator.
fn install_with(exe: &Path, staged: bool) -> Result<()> {
    let status = cosca::run([exe.as_os_str(), "install".as_ref()])
        .args(staged.then_some("--staged"))
        .status()
        .with_context(|| format!("running {} install", exe.display()))?;
    ensure!(status.success(), "{} install ended with {status}", exe.display());
    Ok(())
}

/// The latest release's `asset`. The tag is resolved once, so that the binary and its `SHA256SUMS` are
/// of the same release even if one is published meanwhile.
fn fetch_release(releases: &str, asset: &str) -> Result<Vec<u8>> {
    let latest = format!("{releases}/latest");
    let ended = resolve(&latest, STALL)?;
    // GitHub sends `releases/latest` to the page of the latest release, or to the list of releases when there is none.
    let tag = ended
        .split_once("/releases/tag/")
        .map(|(_, tag)| tag)
        .filter(|tag| !tag.is_empty() && !tag.contains(['/', '?', '#']))
        .with_context(|| format!("{latest} led to {ended}, not a release page: is a release published?"))?;

    let url = |name: &str| format!("{releases}/download/{tag}/{name}");
    let sums = String::from_utf8(download(&url("SHA256SUMS"), STALL)?).context("SHA256SUMS is not text")?;
    let want = expected_digest(&sums, asset)?;
    let binary = download(&url(asset), STALL)?;
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
