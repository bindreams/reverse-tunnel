// `TZ=Europe/Berlin` in a unit's environment must not leave every stamp at `+00:00`.
#[cfg(unix)]
#[test]
fn unix_resolves_iana_zone_names() {
    jiff::tz::db()
        .get("Europe/Berlin")
        .expect("Europe/Berlin is not found: is the system's tzdata installed?");
}

/// Logs are 0644 so that, under a service's default umask, anyone on the machine can read them. The umask is
/// process-wide, so the test re-runs itself in a child under `umask 000`.
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
        .args(["-c", "umask 000; exec \"$0\" log_files_are_created_0644"])
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
