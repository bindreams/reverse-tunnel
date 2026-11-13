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
    let advice = rerun_uninstall(&Paths::testing(r"C:\host"), None);

    assert_eq!(
        advice,
        "run `reverse-tunnel uninstall` in an elevated prompt (with any `reverse-tunnel` binary, if that is not found)"
    );
}

#[test]
fn the_rerun_advice_of_a_removal_with_a_moved_image_names_it_quoted() {
    let advice = rerun_uninstall(
        &Paths::testing(r"C:\host"),
        Some(Path::new(r"C:\Program Files\.reverse-tunnel.0123.exe")),
    );

    assert_eq!(
        advice,
        r#"run `"C:\Program Files\.reverse-tunnel.0123.exe" uninstall` in an elevated prompt"#
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

/// An image moved aside from the installed binary's place, which exists, as `move_aside` leaves it.
fn moved_aside() -> (tempfile::TempDir, Paths, Aside) {
    let (dir, paths) = installed();
    let aside = Aside {
        from: Some(service::exe(&paths)),
        to: dir.path().join(".reverse-tunnel.0123.exe"),
    };
    fs::rename(service::exe(&paths), &aside.to).unwrap();
    (dir, paths, aside)
}

#[test]
fn an_image_put_back_is_where_it_was_and_the_advice_is_the_name() {
    let (_dir, paths, aside) = moved_aside();

    let advice = aside.put_back(&paths);

    assert!(service::exe(&paths).exists() && !aside.to.exists());
    assert_eq!(advice, rerun_uninstall(&paths, None));
}

#[test]
fn an_image_that_cannot_be_put_back_is_named_as_the_binary_to_run() {
    let (_dir, paths, aside) = moved_aside();
    // Gone, so that the rename back fails.
    fs::remove_file(&aside.to).unwrap();

    let advice = aside.put_back(&paths);

    assert!(
        advice.starts_with(&rerun_uninstall(&paths, Some(&aside.to))),
        "{advice}"
    );
    assert!(advice.contains("could not be moved back"), "{advice}");
}

#[test]
fn an_image_in_the_bin_dir_is_moved_next_to_it_under_a_name_of_its_own() {
    let (dir, paths) = installed();

    let aside = move_aside(&paths, &service::exe(&paths)).unwrap().unwrap();

    assert_eq!(aside.from, Some(service::exe(&paths)));
    assert_eq!(aside.to.parent(), Some(dir.path()));
    let name = aside.to.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with(".reverse-tunnel.") && name.ends_with(".exe"), "{name}");
    assert!(aside.to.exists() && !service::exe(&paths).exists());
}

#[test]
fn an_image_that_is_aside_already_is_the_one_the_removal_deletes_and_is_not_moved() {
    let (_dir, paths, aside) = moved_aside();

    let again = move_aside(&paths, &aside.to).unwrap().unwrap();

    assert_eq!((again.from, again.to.as_path()), (None, aside.to.as_path()));
    assert!(aside.to.exists());
    let advice = Aside {
        from: None,
        to: aside.to.clone(),
    }
    .put_back(&paths);
    assert_eq!(advice, rerun_uninstall(&paths, Some(&aside.to)));
    assert!(aside.to.exists());
}

#[test]
fn a_binary_outside_the_directories_the_removal_deletes_stays_where_it_is() {
    let (dir, paths) = installed();
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    // Named as a moved image, but not in the directory that holds the bin dir.
    let lookalike = elsewhere.join(".reverse-tunnel.0123.exe");
    fs::write(&lookalike, "").unwrap();
    // In the directory that holds the bin dir, but not named as a moved image.
    let beside = dir.path().join("reverse-tunnel.exe");
    fs::write(&beside, "").unwrap();

    for exe in [lookalike, beside] {
        assert!(move_aside(&paths, &exe).unwrap().is_none(), "{exe:?}");
        assert!(exe.exists());
    }
}

#[test]
fn a_removal_that_left_its_task_and_the_image_says_how_to_run_it_again() {
    let task = "the task is still registered";

    let with = left_behind(task, Some("run `\"X\" uninstall`".to_string()));

    assert!(with.starts_with(task), "{with}");
    assert!(with.ends_with("run `\"X\" uninstall`"), "{with}");
    assert_eq!(left_behind(task, None), task);
}

#[path = "../tests/support/held.rs"]
mod held;

/// Writes `path` and opens it so that nothing can delete it until the returned file drops.
fn held(path: &Path) -> fs::File {
    fs::write(path, "x").unwrap();
    held::open_held(path)
}

#[test]
fn a_staged_copy_that_is_held_does_not_fail_the_sweep_of_the_bin_dir() {
    let (_dir, paths) = installed();
    let staged = paths.bin_dir.join(format!("{}x.exe", upgrade::STAGED));
    let _held = held(&staged);

    clean_bin_dir(&paths).unwrap();

    assert!(staged.exists());
}

#[test]
fn a_stale_file_that_is_held_fails_the_sweep_of_the_bin_dir() {
    let (_dir, paths) = installed();
    let stale = paths.bin_dir.join("frpc-0.0.1");
    let _held = held(&stale);

    let err = format!("{:#}", clean_bin_dir(&paths).unwrap_err());

    assert!(err.contains("frpc-0.0.1"), "{err}");
}
