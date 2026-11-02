use std::path::PathBuf;

use anyhow::{Result, ensure};

pub const LOG_FRPC: &str = "frpc.log";
pub const LOG_SUPERVISOR: &str = "supervisor.log";

/// Where an installation keeps its files on this OS.
#[derive(Debug, Clone)]
pub struct Paths {
    pub bin_dir: PathBuf,
    /// `config.yaml` and `bridge.pem`, readable by everyone.
    pub config_dir: PathBuf,
    /// `bridge.token` and `host.token`, readable by administrators and the service account.
    pub secrets_dir: PathBuf,
    pub log_dir: PathBuf,
    /// The symlink to the binary on `PATH`; none on Windows.
    pub link: Option<PathBuf>,
}

impl Paths {
    /// The system's paths. Fails if one is not valid Unicode, so later code may rely on that.
    pub fn system() -> Result<Paths> {
        let (bin_dir, config_dir, log_dir, link) = layout()?;
        for dir in [&bin_dir, &config_dir, &log_dir] {
            ensure!(dir.to_str().is_some(), "{} is not valid Unicode", dir.display());
        }
        Ok(Paths {
            secrets_dir: config_dir.join("secrets"),
            bin_dir,
            config_dir,
            log_dir,
            link,
        })
    }
}

/// The install, config and log directories and the link, from the system's known folders (not
/// `%ProgramFiles%`, which the installing user's environment can override).
#[cfg(windows)]
fn layout() -> Result<(PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    use anyhow::Context;
    use known_folders::{KnownFolder, get_known_folder_path};

    let folder = |folder| get_known_folder_path(folder).context("the system has no such known folder");
    let config_dir = folder(KnownFolder::ProgramData)?.join("reverse-tunnel");
    let bin_dir = folder(KnownFolder::ProgramFiles)?.join("reverse-tunnel");
    Ok((bin_dir, config_dir.clone(), config_dir.join("logs"), None))
}

#[cfg(target_os = "macos")]
fn layout() -> Result<(PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    Ok((
        "/usr/local/lib/reverse-tunnel".into(),
        "/Library/Application Support/reverse-tunnel".into(),
        "/Library/Logs/reverse-tunnel".into(),
        Some("/usr/local/bin/reverse-tunnel".into()),
    ))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn layout() -> Result<(PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    Ok((
        "/usr/local/lib/reverse-tunnel".into(),
        "/etc/reverse-tunnel".into(),
        "/var/log/reverse-tunnel".into(),
        Some("/usr/local/bin/reverse-tunnel".into()),
    ))
}
