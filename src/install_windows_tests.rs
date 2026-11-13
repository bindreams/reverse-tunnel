use std::fs;
use std::path::{Path, PathBuf};

use super::*;

fn failure_of(state: TaskState, dir_present: bool) -> String {
    match removal_outcome(state, Path::new(r"C:\removal"), dir_present) {
        Some(WaitOutcome::Failed(why)) => why,
        _ => panic!("the removal should have failed"),
    }
}

#[test]
fn a_removal_task_that_runs_is_waited_for() {
    assert!(removal_outcome(TaskState::Running, Path::new(r"C:\removal"), true).is_none());
}

#[test]
fn a_task_that_deleted_itself_after_the_directory_is_a_removal_that_succeeded() {
    assert!(matches!(
        removal_outcome(TaskState::Gone, Path::new(r"C:\removal"), false),
        Some(WaitOutcome::Ended)
    ));
}

#[test]
fn a_task_deleted_before_the_directory_went_is_a_failed_removal() {
    let why = failure_of(TaskState::Gone, true);
    assert!(why.contains("deleted before it finished"), "{why}");
}

#[test]
fn each_failed_step_of_the_removal_has_its_own_message() {
    assert!(failure_of(TaskState::Ended(1), true).contains("`uninstall --finish`"));
    assert!(failure_of(TaskState::Ended(2), true).contains("copy"));
    let by_hand = failure_of(TaskState::Ended(3), true);
    assert!(by_hand.contains(r"delete C:\removal by hand"), "{by_hand}");
    // A task that was ended by something else has no code of the script's.
    assert!(failure_of(TaskState::Ended(0x41306), true).contains("0x41306"));
    assert!(failure_of(TaskState::Ended(-1073741510), true).contains("0xc000013a"));
}

#[test]
fn a_removal_that_left_only_its_task_is_done_and_says_how_to_delete_it() {
    let Some(WaitOutcome::LeftBehind(why)) = removal_outcome(TaskState::Ended(4), Path::new(r"C:\removal"), false)
    else {
        panic!("the removal's task is left, but the removal is not a failure");
    };
    assert!(why.contains("schtasks /Delete /TN reverse-tunnel-uninstall"), "{why}");
    assert!(!why.contains("failed") && !why.contains("log"), "{why}");
}

#[test]
fn a_disabled_removal_task_is_a_failed_removal() {
    assert!(failure_of(TaskState::Disabled, true).contains("disabled"));
}

/// Paths in a temp dir, with an installed binary.
fn installed() -> (tempfile::TempDir, Paths) {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::testing(dir.path());
    fs::create_dir_all(&paths.bin_dir).unwrap();
    fs::write(service::exe(&paths), "").unwrap();
    (dir, paths)
}

#[test]
fn the_rerun_advice_names_the_command_on_the_path_and_any_binary_for_when_it_is_not() {
    let advice = rerun_uninstall(&Paths::testing(r"C:\host"));

    assert_eq!(
        advice,
        "run `reverse-tunnel uninstall` in an elevated prompt (with any `reverse-tunnel` binary, if that is not found)"
    );
}

#[test]
fn a_binary_in_the_bin_dir_runs_from_a_directory_the_removal_deletes() {
    let (_dir, paths) = installed();

    assert!(runs_from_a_deleted_directory(&paths, &service::exe(&paths)).unwrap());
}

#[test]
fn a_binary_in_the_removals_own_directory_does_too() {
    let (_dir, paths) = installed();
    fs::create_dir_all(removal_dir(&paths)).unwrap();
    let copy = removal_dir(&paths).join("reverse-tunnel.exe");
    fs::write(&copy, "").unwrap();

    assert!(runs_from_a_deleted_directory(&paths, &copy).unwrap());
}

#[test]
fn a_binary_inside_a_directory_the_removal_deletes_does_too() {
    let (_dir, paths) = installed();
    let deep = paths.bin_dir.join("old").join("v1");
    fs::create_dir_all(&deep).unwrap();
    fs::create_dir_all(&paths.config_dir).unwrap();
    fs::create_dir_all(&paths.log_dir).unwrap();

    for exe in [
        deep.join("reverse-tunnel.exe"),
        paths.config_dir.join("reverse-tunnel.exe"),
        paths.log_dir.join("reverse-tunnel.exe"),
    ] {
        assert!(runs_from_a_deleted_directory(&paths, &exe).unwrap(), "{exe:?}");
    }
}

#[test]
fn the_directory_is_the_same_by_whatever_case_the_path_names_it() {
    let (_dir, paths) = installed();
    let shouted = PathBuf::from(service::exe(&paths).to_string_lossy().to_uppercase());

    assert!(runs_from_a_deleted_directory(&paths, &shouted).unwrap());
}

#[test]
fn a_binary_elsewhere_does_not_run_from_a_directory_the_removal_deletes() {
    let (dir, paths) = installed();
    let elsewhere = dir.path().join("reverse-tunnel.exe");
    fs::write(&elsewhere, "").unwrap();

    assert!(!runs_from_a_deleted_directory(&paths, &elsewhere).unwrap());
    // A directory that only starts with a deleted one's name is another directory.
    let beside = paths.bin_dir.with_file_name("bin-old");
    fs::create_dir_all(&beside).unwrap();
    assert!(!runs_from_a_deleted_directory(&paths, &beside.join("reverse-tunnel.exe")).unwrap());
}

#[test]
fn with_nothing_installed_no_binary_runs_from_a_deleted_directory() {
    let (dir, paths) = installed();
    let elsewhere = dir.path().join("reverse-tunnel.exe");
    fs::write(&elsewhere, "").unwrap();
    fs::remove_dir_all(&paths.bin_dir).unwrap();

    assert!(!runs_from_a_deleted_directory(&paths, &elsewhere).unwrap());
}

#[test]
fn a_directory_that_cannot_be_resolved_is_named_in_the_error() {
    let (dir, paths) = installed();
    let missing = dir.path().join("gone");

    let err = runs_from_a_deleted_directory(&paths, &missing.join("reverse-tunnel.exe")).unwrap_err();

    let err = format!("{err:#}");
    assert!(err.contains(&missing.display().to_string()), "{err}");
    assert!(err.contains("the removal deletes"), "{err}");
}
