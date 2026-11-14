use std::collections::BTreeMap;
use std::env::consts::EXE_SUFFIX;
use std::path::{Path, PathBuf};
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
/// On Unix that is `exe`, whatever the binary: the unit never changes, and an upgrade replaces the file and restarts the
/// service. Windows will not replace a running image, so there each build is a file of its own, named by the digest of
/// its content, and the service is moved onto it (`install` registers it before the restart). The same content is the
/// same file, which an install that changed nothing else keeps.
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

/// Windows: whether `name` is that of a service image (see `image`) of some build.
#[cfg(windows)]
pub fn is_image(name: &str) -> bool {
    let digest = name
        .strip_prefix(IMAGE_PREFIX)
        .and_then(|rest| rest.strip_suffix(EXE_SUFFIX));
    digest.is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
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
                Installed::Undetermined { reason, .. } => unread = Some(reason),
                _ => {}
            }
        }
        match unread {
            // An entry that could not be read may be this service's.
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

/// The service manager of this platform. On Windows `image` is the service host of a daemon it registers: this binary,
/// which goetia's shim runs when started with `SERVICE_HOST_ARG`. Only `install` registers; everything else may pass
/// any image.
pub fn manager(image: &Path) -> goetia::Result<Box<dyn ServiceManager>> {
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
