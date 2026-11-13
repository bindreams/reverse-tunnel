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
    // The task did not reach its last step, which deletes the leftover images.
    assert!(why.contains(r"C:\.reverse-tunnel.*.exe"), "{why}");
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
    let (_dir, paths) = installed();

    assert_eq!(
        rerun_uninstall(&paths),
        "run `reverse-tunnel uninstall` in an elevated prompt (with any `reverse-tunnel` binary, if that is not found)"
    );
}

#[test]
fn once_the_installed_binary_is_gone_the_rerun_advice_names_the_leftover_images_as_binaries_to_run() {
    let (dir, paths) = installed();
    fs::remove_file(service::exe(&paths)).unwrap();
    assert_eq!(
        rerun_uninstall(&paths),
        "run `uninstall` in an elevated prompt with any `reverse-tunnel` binary (the installed one is gone)"
    );
    let images = [
        dir.path().join(schtasks::leftover_name("a")),
        dir.path().join(schtasks::leftover_name("b")),
    ];
    for image in &images {
        fs::write(image, "").unwrap();
    }

    let advice = rerun_uninstall(&paths);

    let by_image = |image: &PathBuf| format!("`\"{}\" uninstall`", image.display());
    assert_eq!(
        advice,
        format!(
            "run {} in an elevated prompt (the installed binary is gone)",
            images.iter().map(by_image).collect::<Vec<_>>().join(" or ")
        )
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

/// A process that runs the image `path`, a copy of `cmd.exe`, until it drops: Windows will not delete a running image,
/// and will rename it.
struct Running(std::process::Child);

fn running(path: &Path) -> Running {
    let cmd = Path::new(&env::var("SystemRoot").unwrap())
        .join("System32")
        .join("cmd.exe");
    fs::copy(cmd, path).unwrap();
    // Waits for input, which the pipe gives it when it is killed.
    let child = std::process::Command::new(path)
        .args(["/c", "set /p x="])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    Running(child)
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_running_image_in_the_bin_dir_is_renamed_next_to_it_and_the_rest_is_deleted() {
    let (dir, paths) = installed();
    let _running = running(&paths.bin_dir.join("frpc-0.1.exe"));
    fs::write(paths.bin_dir.join("upgrade-1.exe"), "").unwrap();

    remove_bin_dir(&paths).unwrap();

    assert!(!paths.bin_dir.exists());
    let images = leftover_images(&paths).unwrap();
    let [image] = images.as_slice() else {
        panic!("expected one image: {images:?}")
    };
    assert_eq!(image.parent(), Some(dir.path()));
    let name = image.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with(schtasks::LEFTOVER_PREFIX) && name.ends_with(schtasks::LEFTOVER_SUFFIX),
        "{name}"
    );
}

#[test]
fn nothing_is_renamed_when_everything_can_be_deleted() {
    let (_dir, paths) = installed();
    fs::write(paths.bin_dir.join("frpc-0.1.exe"), "").unwrap();

    remove_bin_dir(&paths).unwrap();

    assert!(!paths.bin_dir.exists());
    assert!(leftover_images(&paths).unwrap().is_empty());
}

#[test]
fn a_bin_dir_that_is_gone_is_removed() {
    let (_dir, paths) = installed();
    fs::remove_dir_all(&paths.bin_dir).unwrap();

    remove_bin_dir(&paths).unwrap();
}

#[test]
fn a_file_that_can_be_neither_deleted_nor_renamed_fails_the_removal_naming_both() {
    let (_dir, paths) = installed();
    let stuck = paths.bin_dir.join("frpc-0.1.exe");
    let _held = held(&stuck);

    let err = format!("{:#}", remove_bin_dir(&paths).unwrap_err());

    assert!(err.contains("frpc-0.1.exe"), "{err}");
    assert!(err.contains("moving it to"), "{err}");
    assert!(stuck.exists());
    assert!(leftover_images(&paths).unwrap().is_empty());
}

#[test]
fn a_directory_that_cannot_be_deleted_fails_the_removal_and_is_not_renamed() {
    let (_dir, paths) = installed();
    let sub = paths.bin_dir.join("old");
    fs::create_dir_all(&sub).unwrap();
    let _running = running(&sub.join("frpc-0.1.exe"));

    let err = format!("{:#}", remove_bin_dir(&paths).unwrap_err());

    assert!(err.contains("old"), "{err}");
    assert!(sub.exists());
    assert!(leftover_images(&paths).unwrap().is_empty());
}
