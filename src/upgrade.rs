//! `reverse-tunnel upgrade`: gets a newer binary, which then installs itself (see `install`).

use std::env::consts::EXE_SUFFIX;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use ureq::ResponseExt;

use crate::download::{STALL, download, host_target};
use crate::files::{Perm, Replace, write_atomic};
use crate::paths::Paths;

const RELEASES: &str = "https://github.com/bindreams/reverse-tunnel/releases";

/// Runs `install` of the binary at `from`, or of the latest release's for this platform, checked against the
/// release's `SHA256SUMS`. That `install` checks the new settings, replaces the binary and restarts the service.
pub fn upgrade(paths: &Paths, from: Option<&Path>) -> Result<()> {
    let Some(from) = from else {
        let binary = fetch_release(RELEASES, host_target()?)?;
        // A `.tmp` name, which `install` removes (itself too, which Unix allows), so that a killed upgrade leaves nothing.
        let staged = paths
            .bin_dir
            .join(format!(".tmp-upgrade-{}", hex::encode(Sha256::digest(&binary))));
        write_atomic(&staged, &binary, Perm::EXECUTABLE, Replace::Always)
            .context("staging the download in the bin dir: is reverse-tunnel installed?")?;
        let installed = install_with(&staged);
        // `install` removes it itself, unless it failed first.
        let _ = fs::remove_file(&staged);
        return installed;
    };
    install_with(from)
}

/// Runs `exe install` with this terminal: its warnings and the registration line are for the operator.
fn install_with(exe: &Path) -> Result<()> {
    let status = cosca::run([exe.as_os_str(), "install".as_ref()])
        .status()
        .with_context(|| format!("running {} install", exe.display()))?;
    ensure!(status.success(), "{} install ended with {status}", exe.display());
    Ok(())
}

/// The latest release's binary for `target`. The tag is resolved once, so that the binary and its `SHA256SUMS` are
/// of the same release even if one is published meanwhile.
fn fetch_release(releases: &str, target: &str) -> Result<Vec<u8>> {
    let latest = format!("{releases}/latest");
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(STALL))
        .build()
        .new_agent();
    let tag_page = agent
        .head(&latest)
        .call()
        .with_context(|| format!("resolving {latest}"))?;
    let tag = tag_page
        .get_uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_string();
    ensure!(
        !tag.is_empty(),
        "{latest} led to {}, which names no release",
        tag_page.get_uri()
    );

    let asset = format!("reverse-tunnel-{target}{EXE_SUFFIX}");
    let url = |name: &str| format!("{releases}/download/{tag}/{name}");
    let sums = String::from_utf8(download(&url("SHA256SUMS"), STALL)?).context("SHA256SUMS is not text")?;
    let want = expected_digest(&sums, &asset)?;
    let binary = download(&url(&asset), STALL)?;
    let have = hex::encode(Sha256::digest(&binary));
    ensure!(
        have.eq_ignore_ascii_case(want),
        "{} has SHA-256 {have}, but SHA256SUMS says {want}",
        url(&asset)
    );
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
