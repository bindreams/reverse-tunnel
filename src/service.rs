use std::collections::BTreeMap;
use std::env::consts::EXE_SUFFIX;
use std::path::PathBuf;
use std::time::Duration;

use goetia::manager::ServiceManager;
use goetia::spec::{DaemonFields, DaemonSpec, Id, Kind, Restart, User};

use crate::paths::Paths;

/// The name of the service, which `ID` and the accounts' names are spelled from.
macro_rules! name {
    () => {
        "reverse-tunnel"
    };
}

/// The name of the service, and of its virtual account on Windows.
pub const ID: &str = name!();

#[cfg(windows)]
pub const ACCOUNT: &str = concat!(r"NT SERVICE\", name!());
#[cfg(target_os = "macos")]
pub const ACCOUNT: &str = concat!("_", name!());
#[cfg(not(any(windows, target_os = "macos")))]
pub const ACCOUNT: &str = name!();

/// Where the installed binary is: the one path the service runs.
pub fn exe(paths: &Paths) -> PathBuf {
    paths.bin_dir.join(format!("{ID}{EXE_SUFFIX}"))
}

pub fn id() -> Id {
    ID.parse().expect("a valid id")
}

/// The first argument with which SCM starts the installed binary as its service host: `main` then hands over to goetia.
pub const SERVICE_HOST_ARG: &str = "--service-host";

/// The service manager of this platform. On Windows the installed binary is the service host of the daemon: goetia's
/// shim, started with `SERVICE_HOST_ARG`.
pub fn manager(paths: &Paths) -> goetia::Result<Box<dyn ServiceManager>> {
    #[cfg(windows)]
    {
        use goetia::backend::scm::manager::Scm;
        use goetia::shim::{CheckPermissions, StandaloneShim};

        let host = StandaloneShim::new(exe(paths), vec![SERVICE_HOST_ARG.into()]);
        Ok(Box::new(Scm::with_shim(host, CheckPermissions::Enable)))
    }
    #[cfg(not(windows))]
    {
        let _ = paths;
        goetia::manager::native()
    }
}

/// The one daemon this tool installs. It names a fixed path, so an upgrade never changes the spec. Errors when
/// goetia refuses it, e.g. a relative `bin_dir`.
pub fn spec(paths: &Paths) -> Result<DaemonSpec, goetia::Error> {
    let exe = exe(paths);
    DaemonSpec::new(DaemonFields {
        id: id(),
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
    })
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
