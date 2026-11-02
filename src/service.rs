use std::collections::BTreeMap;
use std::env::consts::EXE_SUFFIX;
use std::path::PathBuf;
use std::time::Duration;

use goetia::spec::{DaemonSpec, Kind, Restart, User};

use crate::paths::Paths;

const ID: &str = "reverse-tunnel";

#[cfg(windows)]
pub const ACCOUNT: &str = r"NT SERVICE\reverse-tunnel";
#[cfg(target_os = "macos")]
pub const ACCOUNT: &str = "_reverse-tunnel";
#[cfg(not(any(windows, target_os = "macos")))]
pub const ACCOUNT: &str = "reverse-tunnel";

/// Where the installed binary is: the one path the service runs.
pub fn exe(paths: &Paths) -> PathBuf {
    paths.bin_dir.join(format!("{ID}{EXE_SUFFIX}"))
}

/// The one daemon this tool installs. It names a fixed path, so an upgrade never changes the spec.
pub fn spec(paths: &Paths) -> DaemonSpec {
    let exe = exe(paths);
    DaemonSpec {
        id: ID.parse().expect("a valid id"),
        name: ID.into(),
        command: vec![
            exe.to_str().expect("Paths::system() guarantees Unicode").into(),
            "run".into(),
        ],
        cwd: None,
        env: BTreeMap::new(),
        user: User::Name(ACCOUNT.into()),
        restart: Restart::OnFailure,
        restart_delay: Some(Duration::from_secs(5)),
        logs: None,
        kind: Kind::Simple,
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
