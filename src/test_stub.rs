//! `stub-frpc` (`testbin/stub_frpc.rs`) as the binary a unit test checks or installs.

use std::fs;
use std::path::{Path, PathBuf};

/// Where cargo put the stub, which it builds for `cargo test` and not for `cargo test --lib`: the profile directory,
/// taken as the nearest ancestor of the test executable that holds `deps/`.
fn built() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile = exe
        .ancestors()
        .find(|dir| dir.join("deps").is_dir())
        .unwrap_or_else(|| panic!("no cargo profile directory above {exe:?}"));
    let stub = profile.join("stub-frpc");
    assert!(
        stub.is_file(),
        "{stub:?} is missing: run `cargo test`, which builds the `stub-frpc` binary"
    );
    stub
}

/// Copies the stub to `to`.
pub fn copy_to(to: &Path) {
    fs::copy(built(), to).unwrap();
}
