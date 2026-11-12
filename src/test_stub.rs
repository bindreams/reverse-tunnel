//! `stub-frpc` (`testbin/stub_frpc.rs`) as the binary a unit test checks or installs.

use std::fs;
use std::path::{Path, PathBuf};

/// Where cargo put the stub, which it builds for `cargo test` and not for `cargo test --lib`.
fn built() -> PathBuf {
    let stub = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("stub-frpc");
    assert!(
        stub.exists(),
        "{stub:?} is missing: run `cargo test`, which builds the `stub-frpc` binary"
    );
    stub
}

/// Copies the stub to `to`.
pub fn copy_to(to: &Path) {
    fs::copy(built(), to).unwrap();
}
