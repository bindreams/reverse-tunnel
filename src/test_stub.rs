//! `stub-frpc` (`testbin/stub_frpc.rs`) as the binary a unit test checks or installs.

use std::fs;
use std::path::{Path, PathBuf};

/// Where cargo put the stub, which it builds for `cargo test` and not for `cargo test --lib`: the profile directory, an
/// ancestor of the test executable (`deps/`, or the build directory's deeper layout since cargo 1.100).
fn built() -> PathBuf {
    let name = format!("stub-frpc{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe().unwrap();
    exe.ancestors()
        .map(|dir| dir.join(&name))
        .find(|stub| stub.exists())
        .unwrap_or_else(|| panic!("no {name} above {exe:?}: run `cargo test`, which builds the `stub-frpc` binary"))
}

/// Copies the stub to `to`.
pub fn copy_to(to: &Path) {
    fs::copy(built(), to).unwrap();
}
