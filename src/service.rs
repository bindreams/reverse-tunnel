use std::collections::BTreeMap;
use std::env::consts::EXE_SUFFIX;
use std::path::{Path, PathBuf};
use std::time::Duration;

use goetia::manager::ServiceManager;
use goetia::spec::{DaemonFields, DaemonSpec, Id, Kind, Restart, User};

#[cfg(windows)]
use crate::files::{strip_prefix, strip_suffix};
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

/// Where the installed binary is. On Unix the service runs it from there; on Windows it is the copy on the `PATH`, and
/// the service runs another file (see `image`).
pub fn exe(paths: &Paths) -> PathBuf {
    paths.bin_dir.join(format!("{ID}{EXE_SUFFIX}"))
}

/// What the name of a service image on Windows starts with: the binary's SHA-256 follows, then `EXE_SUFFIX`.
#[cfg(windows)]
const IMAGE_PREFIX: &str = concat!(name!(), "-");

/// The file the service runs `binary` from, once installed.
///
/// On Unix that is `exe`, whatever the binary: the unit never changes, and an upgrade replaces the file and restarts
/// the service. Windows will not replace a running image, so there each build is a file of its own, named by the digest
/// of its content, and the service is moved onto it (`install` registers it before the restart).
pub fn image(paths: &Paths, binary: &[u8]) -> PathBuf {
    #[cfg(windows)]
    {
        use sha2::{Digest, Sha256};
        paths.bin_dir.join(format!(
            "{IMAGE_PREFIX}{}{EXE_SUFFIX}",
            hex::encode(Sha256::digest(binary))
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = binary;
        exe(paths)
    }
}

/// Windows: whether `name` is that of a service image (see `image`) of some build. Names are case-insensitive there.
#[cfg(windows)]
pub fn is_image(name: &str) -> bool {
    let Some(rest) = strip_prefix(name, IMAGE_PREFIX) else {
        return false;
    };
    let Some(digest) = strip_suffix(rest, EXE_SUFFIX) else {
        return false;
    };
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The file that the installed service runs: `exe` on Unix, and on Windows the image that the registered service is
/// started from, which the manager says. Fails if the service is not installed, or cannot be read.
pub fn installed_image(manager: &dyn ServiceManager, paths: &Paths) -> anyhow::Result<PathBuf> {
    #[cfg(windows)]
    {
        use goetia::manager::Installed;

        let _ = paths;
        let mut unread = None;
        for entry in manager.list()? {
            match entry {
                Installed::Ours { spec, .. } if spec.id == id() => return Ok(PathBuf::from(&spec.command[0])),
                Installed::OursUnusable { name, reason } if name == ID => {
                    anyhow::bail!("the service is installed, but cannot be read: {reason}")
                }
                // An entry that names another service is not this one's; one that names none may stand for it.
                Installed::Undetermined { name, reason } if name.as_deref().is_none_or(|name| name == ID) => {
                    unread = Some(reason)
                }
                _ => {}
            }
        }
        match unread {
            Some(reason) => anyhow::bail!("could not tell whether the service is installed: {reason}"),
            None => anyhow::bail!("the service is not installed"),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = manager;
        Ok(exe(paths))
    }
}

pub fn id() -> Id {
    ID.parse().expect("a valid id")
}

/// The first argument with which SCM starts the installed binary as its service host: `main` then hands over to goetia.
pub const SERVICE_HOST_ARG: &str = "--service-host";

/// The service manager of this platform, for everything but registering the service: start, stop, restart, status and
/// uninstall name no host.
pub fn manager(paths: &Paths) -> goetia::Result<Box<dyn ServiceManager>> {
    registering_manager(&exe(paths))
}

/// The service manager of this platform, for `install` to register the service with. On Windows `image` is the service
/// host of a daemon it registers: this binary, which goetia's shim runs when started with `SERVICE_HOST_ARG`.
pub fn registering_manager(image: &Path) -> goetia::Result<Box<dyn ServiceManager>> {
    #[cfg(windows)]
    {
        use goetia::backend::scm::manager::Scm;
        use goetia::shim::{CheckPermissions, StandaloneShim};

        let host = StandaloneShim::new(image.to_path_buf(), vec![SERVICE_HOST_ARG.into()]);
        Ok(Box::new(Scm::with_shim(host, CheckPermissions::Enable)))
    }
    #[cfg(not(windows))]
    {
        let _ = image;
        goetia::manager::native()
    }
}

/// The one daemon this tool installs, running `image` (see `image` for why that stays one path on Unix, and not on
/// Windows). Errors when goetia refuses it, e.g. a relative path.
pub fn spec(image: &Path) -> Result<DaemonSpec, goetia::Error> {
    DaemonSpec::new(DaemonFields {
        id: id(),
        name: ID.into(),
        command: vec![
            image.to_str().expect("Paths::system() guarantees Unicode").into(),
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
