use goetia::blob;
use goetia::spec::{Restart, User};

use super::*;

#[test]
fn spec_runs_the_installed_binary_as_the_service_account() {
    let paths = Paths::testing("/opt/reverse-tunnel");
    let spec = spec(&paths);

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
