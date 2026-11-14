use std::ffi::OsStr;
use std::fs;

use super::*;

#[test]
fn a_leftover_keeps_the_name_of_the_file_it_was() {
    let name = name("ab12", OsStr::new("frpc-0.1.exe"));

    assert_eq!(name, ".reverse-tunnel.ab12.frpc-0.1.exe");
}

#[test]
fn a_leftover_is_what_the_pattern_matches_whatever_the_case() {
    let name = name("ab12", OsStr::new("frpc-0.1.exe")).to_string_lossy().into_owned();

    assert!(is_leftover(&name));
    assert!(is_leftover(&name.to_uppercase()));
    assert!(!is_leftover("reverse-tunnel.exe"));
    assert!(!is_leftover("x.reverse-tunnel.ab12.exe"));
}

#[test]
fn a_leftover_gives_back_the_name_it_kept() {
    let name = name("ab12", OsStr::new("a.b.exe")).to_string_lossy().into_owned();

    assert_eq!(kept_name(&name), Some("a.b.exe"));
    assert_eq!(kept_name("a.b.exe"), None);
}

#[test]
fn a_leftover_is_of_a_file_by_the_name_it_kept_whatever_the_case() {
    let ours = name("ab12", OsStr::new("reverse-tunnel.exe"))
        .to_string_lossy()
        .into_owned();
    let frpc = name("ab12", OsStr::new("frpc-0.1.exe")).to_string_lossy().into_owned();

    assert!(is_leftover_of(&ours, "reverse-tunnel.exe"));
    assert!(is_leftover_of(&ours.to_uppercase(), "reverse-tunnel.exe"));
    assert!(!is_leftover_of(&frpc, "reverse-tunnel.exe"));
    // A name that only ends like the original is another file.
    let longer = name("ab12", OsStr::new("old-reverse-tunnel.exe"))
        .to_string_lossy()
        .into_owned();
    assert!(!is_leftover_of(&longer, "reverse-tunnel.exe"));
    assert!(!is_leftover_of("reverse-tunnel.exe", "reverse-tunnel.exe"));
}

/// A bin dir in a temp dir, whose parent holds the leftovers, and a leftover of `original` in it.
fn installed() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir_all(&paths.bin_dir).unwrap();
    (dir, paths)
}

fn leftover_in(dir: &Path, id: &str, original: &str) -> PathBuf {
    dir.join(name(id, OsStr::new(original)))
}

#[test]
fn the_leftovers_of_the_binary_are_those_that_kept_its_name_or_a_service_images() {
    let (dir, paths) = installed();
    let image = service::image(&paths, b"an old build");
    let image = image.file_name().unwrap().to_str().unwrap();
    let ours = [
        leftover_in(dir.path(), "a", "reverse-tunnel.exe"),
        leftover_in(dir.path(), "b", "REVERSE-TUNNEL.EXE"),
        leftover_in(dir.path(), "c", image),
    ];
    let others = [
        leftover_in(dir.path(), "d", "frpc-0.1.exe"),
        leftover_in(dir.path(), "e", "old-reverse-tunnel.exe"),
        leftover_in(dir.path(), "f", "reverse-tunnel-0.1.0.exe"),
    ];
    for file in ours.iter().chain(&others) {
        fs::write(file, "").unwrap();
    }

    assert_eq!(images_of_the_binary(&paths).unwrap(), ours);
}

#[test]
fn a_leftover_that_is_not_a_regular_file_is_reported_and_never_deleted() {
    let (dir, paths) = installed();
    let impostor = leftover_in(dir.path(), "a", "frpc-0.1.exe");
    fs::create_dir(&impostor).unwrap();
    fs::write(impostor.join("inside"), "").unwrap();

    let kept = delete_what_can_be(images(&paths).unwrap());

    let [why] = kept.as_slice() else {
        panic!("expected the directory to be reported: {kept:?}")
    };
    let why = format!("{why:#}");
    assert!(
        why.contains(&impostor.display().to_string()) && why.contains("not a regular file"),
        "{why}"
    );
    assert!(impostor.join("inside").exists());
}

#[test]
fn a_leftover_that_is_gone_is_deleted_not_kept() {
    let (dir, _paths) = installed();

    assert!(delete_what_can_be(vec![dir.path().join("gone.exe")]).is_empty());
}
