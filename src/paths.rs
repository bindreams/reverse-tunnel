use std::path::{Path, PathBuf};

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
    /// Held by `install` and `uninstall` for their whole run. No removal touches it. On Windows, the name of a mutex,
    /// which named-lock puts in the `Global\` namespace: it has no `\`.
    pub lock: PathBuf,
    /// The symlink to the binary on `PATH`; none on Windows.
    pub link: Option<PathBuf>,
}

impl Paths {
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.yaml")
    }

    /// The bridge's certificate, which frpc trusts.
    pub fn bridge_pem(&self) -> PathBuf {
        self.config_dir.join("bridge.pem")
    }

    pub fn bridge_token(&self) -> PathBuf {
        self.secrets_dir.join("bridge.token")
    }

    pub fn host_token(&self) -> PathBuf {
        self.secrets_dir.join("host.token")
    }

    /// Paths for tests: fixed names under `root`, and no link.
    pub fn testing(root: impl AsRef<Path>) -> Paths {
        let root = root.as_ref();
        Paths {
            bin_dir: root.join("bin"),
            config_dir: root.join("config"),
            secrets_dir: root.join("config/secrets"),
            log_dir: root.join("logs"),
            lock: if cfg!(windows) {
                format!("test-{}", root.file_name().unwrap_or_default().to_string_lossy()).into()
            } else {
                root.join("lock")
            },
            link: None,
        }
    }

    /// The system's paths. Fails if one is not valid Unicode, so later code may rely on that, and on Windows if the
    /// bin dir contains `%`, which `cmd` and the system `PATH` read as a variable.
    pub fn system() -> Result<Paths> {
        let (bin_dir, config_dir, log_dir, lock, link) = layout()?;
        for dir in [&bin_dir, &config_dir, &log_dir] {
            ensure!(dir.to_str().is_some(), "{} is not valid Unicode", dir.display());
        }
        #[cfg(windows)]
        ensure!(
            !bin_dir.to_string_lossy().contains('%'),
            "{} contains `%`. Windows reads `%NAME%` as a variable in the commands that finish `uninstall` and in the \
             system `PATH`, so reverse-tunnel cannot be installed while the system's Program Files folder has `%` in \
             its path.",
            bin_dir.display()
        );
        Ok(Paths {
            secrets_dir: config_dir.join("secrets"),
            bin_dir,
            config_dir,
            log_dir,
            lock,
            link,
        })
    }
}

/// The install, config and log directories and the link, from the system's known folders, not from the environment.
#[cfg(windows)]
fn layout() -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    use anyhow::Context;
    use known_folders::{KnownFolder, get_known_folder_path};

    let folder = |folder| get_known_folder_path(folder).context("the system has no such known folder");
    let config_dir = folder(KnownFolder::ProgramData)?.join("reverse-tunnel");
    let bin_dir = folder(KnownFolder::ProgramFiles)?.join("reverse-tunnel");
    Ok((
        bin_dir,
        config_dir.clone(),
        config_dir.join("logs"),
        "reverse-tunnel".into(),
        None,
    ))
}

#[cfg(target_os = "macos")]
fn layout() -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    Ok((
        "/usr/local/lib/reverse-tunnel".into(),
        "/Library/Application Support/reverse-tunnel".into(),
        "/Library/Logs/reverse-tunnel".into(),
        "/var/run/reverse-tunnel.lock".into(),
        Some("/usr/local/bin/reverse-tunnel".into()),
    ))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn layout() -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, Option<PathBuf>)> {
    Ok((
        "/usr/local/lib/reverse-tunnel".into(),
        "/etc/reverse-tunnel".into(),
        "/var/log/reverse-tunnel".into(),
        "/run/reverse-tunnel.lock".into(),
        Some("/usr/local/bin/reverse-tunnel".into()),
    ))
}
