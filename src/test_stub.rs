//! `stub-frpc` (`testbin/stub_frpc.rs`) as the binary a unit test checks or installs.

use std::path::{Path, PathBuf};
use std::process;

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

/// Copies the stub to `to`. A `cp` child writes it: a writable descriptor in this process would leak into the children
/// that other test threads fork, and executing the copy would fail with ETXTBSY while one lives.
pub fn copy_to(to: &Path) {
    assert!(
        process::Command::new("cp")
            .arg(built())
            .arg(to)
            .status()
            .unwrap()
            .success()
    );
}
