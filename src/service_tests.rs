use goetia::blob;
use goetia::spec::{Restart, User};

use super::*;

#[test]
fn spec_runs_the_installed_binary_as_the_service_account() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::testing(root.path());
    let spec = spec(&exe(&paths)).unwrap();

    assert_eq!(spec.id.as_str(), "reverse-tunnel");
    let exe = paths
        .bin_dir
        .join(format!("reverse-tunnel{}", std::env::consts::EXE_SUFFIX));
    assert_eq!(spec.command, [exe.to_str().unwrap(), "run"]);
    assert_eq!(spec.restart, Restart::OnFailure);
    assert!(spec.restart_delay.is_some());
    let account = if cfg!(windows) {
        r"NT SERVICE\reverse-tunnel"
    } else if cfg!(target_os = "macos") {
        "_reverse-tunnel"
    } else {
        "reverse-tunnel"
    };
    assert_eq!(spec.user, User::Name(account.into()));
    // goetia's blob round-trip rejects specs its injection gate refuses.
    assert_eq!(blob::decode(&blob::encode(&spec)).unwrap().spec, spec);
}

/// The SHA-256 of nothing.
#[cfg(windows)]
const EMPTY_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[cfg(windows)]
#[test]
fn each_build_is_an_image_of_its_own_named_by_the_digest_of_its_content() {
    let paths = Paths::testing("C:/root");

    let image = |binary: &[u8]| image(&paths, binary);

    assert_eq!(
        image(b""),
        paths.bin_dir.join(format!("reverse-tunnel-{EMPTY_DIGEST}.exe"))
    );
    assert_eq!(image(b"one"), image(b"one"));
    assert_ne!(image(b"one"), image(b"two"));
}

#[cfg(not(windows))]
#[test]
fn every_build_runs_from_the_installed_binary() {
    let paths = Paths::testing("/root");

    assert_eq!(image(&paths, b"one"), exe(&paths));
    assert_eq!(image(&paths, b"two"), exe(&paths));
}

#[cfg(windows)]
#[test]
fn only_a_file_named_by_a_digest_is_an_image() {
    let named = |digest: &str| format!("reverse-tunnel-{digest}.exe");

    assert!(is_image(&named(EMPTY_DIGEST)));
    for other in [
        "reverse-tunnel.exe".to_string(),
        named(&EMPTY_DIGEST.to_uppercase()),
        named(&EMPTY_DIGEST[1..]),
        named("0.1.0"),
        format!("upgrade-{EMPTY_DIGEST}.exe"),
        format!("reverse-tunnel-{EMPTY_DIGEST}"),
        "frpc-0.71.1.exe".to_string(),
    ] {
        assert!(!is_image(&other), "{other}");
    }
}

#[test]
fn spec_refuses_a_relative_bin_dir() {
    assert!(spec(&exe(&Paths::testing("relative/root"))).is_err());
}

#[cfg(windows)]
#[test]
fn the_installed_image_is_the_registered_one_unless_an_unreadable_entry_may_be_the_service() {
    use goetia::manager::fake::Fake;

    let paths = Paths::testing("C:/root");
    let manager = Fake::default();
    // An unreadable entry that names another service is not this one's.
    manager.seed_opaque("another");
    assert_eq!(
        installed_image(&manager, &paths).unwrap_err().to_string(),
        "the service is not installed"
    );
    // One that names none may be.
    manager.seed_aggregate_undetermined("the scan did not finish.");
    let err = installed_image(&manager, &paths).unwrap_err().to_string();
    assert!(
        err.starts_with("could not tell whether the service is installed"),
        "{err}"
    );
}
