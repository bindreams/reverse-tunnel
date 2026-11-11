//! `reverse-tunnel upgrade`: gets a newer binary, which then installs itself (see `install`).

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::download::{STALL, download, host_target, resolve, verify_digest};
use crate::files::{Perm, apply};
use crate::paths::Paths;

const RELEASES: &str = "https://github.com/bindreams/reverse-tunnel/releases";

/// What the file name of a downloaded binary starts with in the bin dir.
const STAGED: &str = "upgrade-";

/// Writes `binary` to a new executable file of its own in the bin dir, `upgrade-<random>`, and returns its path, to
/// run it. `clean_bin_dir` leaves such files alone, so that an `install` running meanwhile cannot take one away. The
/// `install` that runs it removes it (`is_staged`).
///
/// If `upgrade` is interrupted before it finishes, the downloaded release may remain in reverse-tunnel's bin
/// directory as `upgrade-<...>`; nothing runs it, it is safe to delete, and `uninstall` removes it.
pub fn stage(paths: &Paths, binary: &[u8]) -> Result<PathBuf> {
    let mut file = tempfile::Builder::new()
        .prefix(STAGED)
        .tempfile_in(&paths.bin_dir)
        .with_context(|| {
            format!(
                "staging the download in {}: is reverse-tunnel installed?",
                paths.bin_dir.display()
            )
        })?;
    apply(file.as_file(), Perm::EXECUTABLE)?;
    file.write_all(binary)?;
    file.as_file().sync_all()?;
    // Closed before it is kept, which is before it runs.
    Ok(file.into_temp_path().keep()?)
}

/// Whether `exe` is a file `stage` made: in the bin dir, and named for it. `install` removes its own once it has read
/// it, since the upgrade that staged it may be gone with its session by the time the service is killed, which is
/// `install`'s last act.
pub fn is_staged(paths: &Paths, exe: &Path) -> bool {
    let named = exe.file_name().and_then(|name| name.to_str());
    let in_bin_dir = fs::canonicalize(&paths.bin_dir).ok() == exe.parent().and_then(|dir| fs::canonicalize(dir).ok());
    in_bin_dir && named.is_some_and(|name| name.starts_with(STAGED))
}

/// Runs `install` of the binary at `from`, or of the latest release's for this platform, checked against the
/// release's `SHA256SUMS`. That `install` checks the new settings, replaces the binary and restarts the service.
pub fn upgrade(paths: &Paths, from: Option<&Path>) -> Result<()> {
    let Some(from) = from else {
        let binary = fetch_release(RELEASES, &format!("reverse-tunnel-{}{EXE_SUFFIX}", host_target()?))?;
        let staged = stage(paths, &binary)?;
        let installed = install_with(&staged);
        // `install` removes it itself, unless it failed before.
        let removed = match fs::remove_file(&staged) {
            Err(err) if err.kind() != ErrorKind::NotFound => {
                Err(err).with_context(|| format!("removing {}, which is safe to delete", staged.display()))
            }
            _ => Ok(()),
        };
        if let (Err(_), Err(why)) = (&installed, &removed) {
            eprintln!("{why:#}");
        }
        return installed.and(removed);
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
