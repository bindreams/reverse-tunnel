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

/// The deleted directory that holds `dir`, by the name `paths` gives it.
fn holder(paths: &Paths, dir: &Path) -> Option<PathBuf> {
    deleted_dir_holding(paths, dir).unwrap()
}

#[test]
fn each_directory_the_removal_deletes_holds_itself_and_what_is_inside() {
    let (_dir, paths) = installed();
    fs::create_dir_all(removal_dir(&paths)).unwrap();
    fs::create_dir_all(&paths.config_dir).unwrap();
    fs::create_dir_all(&paths.log_dir).unwrap();
    let deep = paths.bin_dir.join("old").join("v1");
    fs::create_dir_all(&deep).unwrap();

    for (inside, held) in [
        (paths.bin_dir.clone(), paths.bin_dir.clone()),
        (deep, paths.bin_dir.clone()),
        (paths.config_dir.clone(), paths.config_dir.clone()),
        (paths.log_dir.clone(), paths.log_dir.clone()),
        (removal_dir(&paths), removal_dir(&paths)),
    ] {
        assert_eq!(holder(&paths, &inside), Some(held), "{inside:?}");
    }
}

#[test]
fn the_directory_is_the_same_by_whatever_case_the_path_names_it() {
    let (_dir, paths) = installed();
    let shouted = PathBuf::from(paths.bin_dir.to_string_lossy().to_uppercase());

    assert_eq!(holder(&paths, &shouted), Some(paths.bin_dir.clone()));
}

#[test]
fn a_directory_elsewhere_is_held_by_none() {
    let (dir, paths) = installed();

    assert_eq!(holder(&paths, dir.path()), None);
    // A directory that only starts with a deleted one's name is another directory.
    let beside = paths.bin_dir.with_file_name("bin-old");
    fs::create_dir_all(&beside).unwrap();
    assert_eq!(holder(&paths, &beside), None);
}

#[test]
fn with_nothing_installed_no_directory_is_held() {
    let (dir, paths) = installed();
    fs::remove_dir_all(&paths.bin_dir).unwrap();

    assert_eq!(holder(&paths, dir.path()), None);
}

#[test]
fn a_directory_that_cannot_be_resolved_is_named_in_the_error() {
    let (dir, paths) = installed();
    let missing = dir.path().join("gone");

    let err = deleted_dir_holding(&paths, &missing).unwrap_err();

    let err = format!("{err:#}");
    assert!(err.contains(&missing.display().to_string()), "{err}");
    assert!(err.contains("the removal deletes"), "{err}");
}

#[test]
fn uninstall_refuses_a_working_directory_in_a_directory_the_removal_deletes() {
    let (_dir, paths) = installed();
    fs::create_dir_all(&paths.log_dir).unwrap();
    let inside = paths.bin_dir.join("sub");
    fs::create_dir_all(&inside).unwrap();

    for cwd in [&paths.bin_dir, &paths.log_dir, &inside] {
        let err = refuse_deleted_working_directory(&paths, cwd).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("current directory"), "{err}");
        assert!(err.contains("Change to another directory first"), "{err}");
    }
}

#[test]
fn uninstall_runs_with_its_working_directory_elsewhere() {
    let (dir, paths) = installed();

    refuse_deleted_working_directory(&paths, dir.path()).unwrap();
}
