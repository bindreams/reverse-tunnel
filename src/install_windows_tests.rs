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
fn the_installed_binary_is_copied_out_run_and_the_copy_removed_by_one_powershell_line() {
    let paths = Paths::testing(r"C:\host");

    assert_eq!(
        copy_out_commands(&paths),
        r"New-Item -ItemType Directory -Force -Path 'C:\host\reverse-tunnel-copy' > $null; if ($?) { Copy-Item -Force -LiteralPath 'C:\host\bin\reverse-tunnel.exe' -Destination 'C:\host\reverse-tunnel-copy\reverse-tunnel.exe'; if ($?) { & 'C:\host\reverse-tunnel-copy\reverse-tunnel.exe' uninstall } }; Remove-Item -Recurse -Force -LiteralPath 'C:\host\reverse-tunnel-copy'"
    );
}

#[test]
fn a_quote_in_a_path_is_doubled_so_that_nothing_expands() {
    let paths = Paths::testing(r"C:\it's");

    assert!(copy_out_commands(&paths).contains(r"'C:\it''s\bin\reverse-tunnel.exe'"));
}

#[test]
fn the_rerun_advice_is_the_copy_out_line() {
    let (_dir, paths) = installed();

    assert_eq!(
        rerun_uninstall(&paths),
        format!("run `{}` in an elevated PowerShell", copy_out_commands(&paths))
    );
}

#[test]
fn the_rerun_advice_without_the_installed_binary_names_any_other() {
    let dir = tempfile::tempdir().unwrap();

    let advice = rerun_uninstall(&Paths::testing(dir.path()));

    assert!(advice.contains("any `reverse-tunnel` binary"), "{advice}");
}

#[test]
fn uninstall_refuses_to_run_from_the_bin_dir_with_the_whole_text() {
    let (_dir, paths) = installed();

    let err = refuse_running_from_a_deleted_directory(&paths, &service::exe(&paths)).unwrap_err();

    assert_eq!(
        format!("{err:#}"),
        format!(
            "`uninstall` is running from {}, which the removal deletes, and Windows cannot delete a running binary. \
             Run it from a copy, in an elevated PowerShell (over SSH, run `powershell` first):\n    {}",
            paths.bin_dir.display(),
            copy_out_commands(&paths)
        )
    );
}

#[test]
fn uninstall_refuses_to_run_from_the_removals_own_directory() {
    let (_dir, paths) = installed();
    fs::create_dir_all(removal_dir(&paths)).unwrap();
    let copy = removal_dir(&paths).join("reverse-tunnel.exe");
    fs::write(&copy, "").unwrap();

    let err = refuse_running_from_a_deleted_directory(&paths, &copy).unwrap_err();

    assert!(format!("{err:#}").contains(&removal_dir(&paths).display().to_string()));
}

#[test]
fn the_directory_is_the_same_by_whatever_case_the_path_names_it() {
    let (_dir, paths) = installed();
    let shouted = PathBuf::from(service::exe(&paths).to_string_lossy().to_uppercase());

    assert!(refuse_running_from_a_deleted_directory(&paths, &shouted).is_err());
}

#[test]
fn uninstall_runs_from_a_binary_elsewhere_or_with_nothing_installed() {
    let (dir, paths) = installed();
    let elsewhere = dir.path().join("reverse-tunnel.exe");
    fs::write(&elsewhere, "").unwrap();
    refuse_running_from_a_deleted_directory(&paths, &elsewhere).unwrap();
    // The copy-out line's own directory is outside what the removal deletes.
    fs::create_dir_all(copy_dir(&paths)).unwrap();
    let copy = copy_dir(&paths).join("reverse-tunnel.exe");
    fs::write(&copy, "").unwrap();
    refuse_running_from_a_deleted_directory(&paths, &copy).unwrap();

    fs::remove_dir_all(&paths.bin_dir).unwrap();
    refuse_running_from_a_deleted_directory(&paths, &elsewhere).unwrap();
}
