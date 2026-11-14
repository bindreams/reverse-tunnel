//! `reverse-tunnel upgrade`: gets a newer binary, which then installs itself (see `install`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::download::{STALL, SUMS_FILE, asset_name, download, host_target, resolve, verify_digest};
use crate::files::{Perm, apply, remove_entry};
use crate::paths::Paths;

const RELEASES: &str = "https://github.com/bindreams/reverse-tunnel/releases";

/// What the name of a staged file in the bin dir starts with: a download that `upgrade` runs `install` from, or the copy
/// `install` checks. `install` sweeps the ones left behind.
pub const STAGED: &str = "upgrade-";

/// Writes `binary` to a new executable `upgrade-<random>` in the bin dir and returns its path. The caller removes it
/// (`discard`), or leaves it to the next `install`'s sweep, as a successful `upgrade` does.
pub fn stage(paths: &Paths, binary: &[u8]) -> Result<PathBuf> {
    let mut file = tempfile::Builder::new()
        .prefix(STAGED)
        // Windows runs a file only if its name has an extension.
        .suffix(std::env::consts::EXE_SUFFIX)
        .tempfile_in(&paths.bin_dir)
        .with_context(|| format!("creating a staged copy of the binary in {}", paths.bin_dir.display()))?;
    let path = file.path().to_path_buf();
    let writing = || format!("writing {}", path.display());
    apply(file.as_file(), Perm::executable()).with_context(writing)?;
    file.write_all(binary).with_context(writing)?;
    file.as_file().sync_all().with_context(writing)?;
    // Closed first: an executable open for writing cannot be run (ETXTBSY).
    file.into_temp_path().keep().with_context(writing)
}

/// Removes a staged copy. A failure is a warning: the next `install` sweeps the bin dir.
pub fn discard(staged: &Path) {
    if let Err(err) = remove_entry(staged) {
        eprintln!("{err:#}; it is safe to delete");
    }
}

/// Runs `install` of the binary at `from`, or of the latest release's for this platform, checked against the
/// release's `SHA256SUMS`. That `install` checks the new settings, replaces the binary and restarts the service.
pub fn upgrade(paths: &Paths, from: Option<&Path>) -> Result<()> {
    let Some(from) = from else {
        ensure!(
            paths.bin_dir.try_exists()?,
            "{} does not exist: is reverse-tunnel installed?",
            paths.bin_dir.display()
        );
        let binary = fetch_release(RELEASES, &asset_name(host_target()?))?;
        let staged = stage(paths, &binary).context("staging the release")?;
        let installed = install_with(&staged);
        if installed.is_err() {
            discard(&staged);
        }
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

/// The latest release's `asset`. Resolves the tag once so the binary and `SHA256SUMS` come from the same release.
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
    let sums =
        String::from_utf8(download(&url(SUMS_FILE), STALL)?).with_context(|| format!("{SUMS_FILE} is not text"))?;
    let want = expected_digest(&sums, asset)?;
    let binary = download(&url(asset), STALL)?;
    verify_digest(&url(asset), &binary, want, SUMS_FILE)?;
    Ok(binary)
}

/// The digest `sums` (`sha256sum` output: `<hex>  <name>`, or `<hex> *<name>`) lists for `asset`.
fn expected_digest<'a>(sums: &'a str, asset: &str) -> Result<&'a str> {
    sums.lines()
        .find_map(|line| {
            let (digest, name) = line.split_once(' ')?;
            (name.trim_start_matches([' ', '*']) == asset).then_some(digest)
        })
        .with_context(|| format!("{SUMS_FILE} lists no {asset}"))
}

#[cfg(test)]
#[path = "upgrade_tests.rs"]
mod tests;
