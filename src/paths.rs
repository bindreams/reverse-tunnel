use std::path::{Path, PathBuf};

pub const LOG_FRPC: &str = "frpc.log";
pub const LOG_SUPERVISOR: &str = "supervisor.log";

/// Where an installation keeps its files on this OS.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The install directory: the binary and frpc.
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
    pub fn system() -> Paths {
        let (bin_dir, config_dir, log_dir, link) = if cfg!(windows) {
            (
                r"C:\Program Files\reverse-tunnel",
                r"C:\ProgramData\reverse-tunnel",
                r"C:\ProgramData\reverse-tunnel\logs",
                None,
            )
        } else if cfg!(target_os = "macos") {
            (
                "/usr/local/lib/reverse-tunnel",
                "/Library/Application Support/reverse-tunnel",
                "/Library/Logs/reverse-tunnel",
                Some("/usr/local/bin/reverse-tunnel"),
            )
        } else {
            (
                "/usr/local/lib/reverse-tunnel",
                "/etc/reverse-tunnel",
                "/var/log/reverse-tunnel",
                Some("/usr/local/bin/reverse-tunnel"),
            )
        };
        Paths {
            bin_dir: bin_dir.into(),
            secrets_dir: Path::new(config_dir).join("secrets"),
            config_dir: config_dir.into(),
            log_dir: log_dir.into(),
            link: link.map(PathBuf::from),
        }
    }
}
