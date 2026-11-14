// `TZ=Europe/Berlin` in a unit's environment must not leave every stamp at `+00:00`.
#[cfg(unix)]
#[test]
fn unix_resolves_iana_zone_names() {
    jiff::tz::db()
        .get("Europe/Berlin")
        .expect("Europe/Berlin is not found: is the system's tzdata installed?");
}

/// Logs are 0644 so that anyone on the machine can read them, whatever the service's umask. The umask is
/// process-wide, so the test re-runs itself in a child under `umask 077`.
#[cfg(unix)]
#[test]
fn log_files_are_created_0644() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use super::LogFile;

    const CHILD: &str = "RT_LOGFILE_TEST_DIR";
    if let Some(dir) = std::env::var_os(CHILD) {
        let log = LogFile::open(Path::new(&dir).join("x.log"), 10).unwrap();
        // A rotation creates the next file.
        log.write(b"aaaaaaaaaaaa");
        log.write(b"b");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let status = Command::new("sh")
        .args(["-c", "umask 077; exec \"$0\" log_files_are_created_0644"])
        .arg(std::env::current_exe().unwrap())
        .env(CHILD, dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    for name in ["x.log", "x.log.1"] {
        let mode = fs::metadata(dir.path().join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "{name}");
    }
}

/// Only a file that `open` creates is made 0644: one that exists keeps the mode its owner gave it.
#[cfg(unix)]
#[test]
fn an_existing_log_keeps_its_mode() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::LogFile;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("x.log");
    fs::write(&path, "").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    LogFile::open(path.clone(), 10).unwrap();

    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}
