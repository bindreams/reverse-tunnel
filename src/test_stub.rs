//! `stub-frpc` (`testbin/stub_frpc.rs`) as the binary a unit test checks or installs.

use std::fs;
use std::path::{Path, PathBuf};

/// Where cargo put the stub, which it builds for `cargo test` and not for `cargo test --lib`: in the profile directory,
/// the nearest ancestor of the test executable that holds it, whether the executable is in `deps/` or in the build dir.
fn built() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .map(|dir| dir.join("stub-frpc"))
        .find(|stub| stub.is_file())
        .unwrap_or_else(|| panic!("no stub-frpc above {exe:?}: run `cargo test`, which builds the `stub-frpc` binary"))
}

/// Copies the stub to `to`.
pub fn copy_to(to: &Path) {
    fs::copy(built(), to).unwrap();
}
