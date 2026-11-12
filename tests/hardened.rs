//! Fails when `reverse-tunnel`'s imports would be looked up in its own folder or it imports the VC runtime (Windows),
//! or it searches its own folder through `$ORIGIN` or `@rpath` (Linux, macOS). `verify` cannot see the guard that
//! covers `LoadLibrary` calls without flags.

#[test]
fn the_binary_is_hardened() {
    libsearch_guard::verify(env!("CARGO_BIN_EXE_reverse-tunnel")).unwrap();
}
