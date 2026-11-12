//! Fails when `reverse-tunnel` would load a DLL planted beside it (Windows), or searches its own folder through
//! `$ORIGIN` or `@rpath` (Linux, macOS).

#[test]
fn the_binary_is_hardened() {
    libsearch_guard::verify(env!("CARGO_BIN_EXE_reverse-tunnel")).unwrap();
}
