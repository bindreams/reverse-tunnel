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

/// Paths under a temp dir, which is also the folder that holds the bin dir (see `dir`), with the installed binary in
/// the bin dir.
pub(crate) fn installed() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir_all(&paths.bin_dir).unwrap();
    fs::write(service::exe(&paths), "").unwrap();
    (dir, paths)
}

/// Where the leftover called `id` of the file `original` is in the folder `dir`, which `images` lists: the path only,
/// no file is made.
pub(crate) fn leftover_in(dir: &Path, id: &str, original: &str) -> PathBuf {
    dir.join(name(id, OsStr::new(original)))
}

#[test]
fn the_leftovers_of_the_binary_are_those_that_kept_its_name_or_a_service_images_and_the_binary_comes_first() {
    let (dir, paths) = installed();
    let image = service::image(&paths, b"an old build");
    let image = image.file_name().unwrap().to_str().unwrap();
    // The images have the ids that sort first.
    let binary = [
        leftover_in(dir.path(), "c", "reverse-tunnel.exe"),
        leftover_in(dir.path(), "d", "REVERSE-TUNNEL.EXE"),
    ];
    let images = [
        leftover_in(dir.path(), "a", image),
        leftover_in(dir.path(), "b", &image.to_uppercase()),
    ];
    let others = [
        leftover_in(dir.path(), "e", "frpc-0.1.exe"),
        leftover_in(dir.path(), "f", "old-reverse-tunnel.exe"),
        leftover_in(dir.path(), "g", "reverse-tunnel-0.1.0.exe"),
    ];
    for file in binary.iter().chain(&images).chain(&others) {
        fs::write(file, "").unwrap();
    }

    assert_eq!(
        images_of_the_binary(&paths).unwrap(),
        binary.iter().chain(&images).cloned().collect::<Vec<_>>()
    );
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
