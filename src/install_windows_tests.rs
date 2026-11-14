use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;

/// Where the leftover images go, in these tests.
const LEFTOVERS: &str = r"C:\";

fn failure_of(state: TaskState, dir_present: bool) -> String {
    match removal_outcome(state, dir_present, Path::new(LEFTOVERS)) {
        Some(WaitOutcome::Failed(why)) => why,
        _ => panic!("the removal should have failed"),
    }
}

#[test]
fn a_removal_task_that_runs_is_waited_for() {
    assert!(removal_outcome(TaskState::Running, true, Path::new(LEFTOVERS)).is_none());
}

#[test]
fn a_task_that_deleted_itself_after_the_directory_is_a_removal_that_succeeded() {
    assert!(matches!(
        removal_outcome(TaskState::Gone, false, Path::new(LEFTOVERS)),
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
    // A task that was ended by something else has no code of the script's.
    assert!(failure_of(TaskState::Ended(0x41306), true).contains("0x41306"));
    assert!(failure_of(TaskState::Ended(-1073741510), true).contains("0xc000013a"));
}

#[test]
fn a_removal_that_left_only_its_task_is_done_and_says_how_to_delete_it() {
    // The task did not reach its last step, which deletes the leftover images.
    let Some(WaitOutcome::LeftBehind(why)) = removal_outcome(TaskState::Ended(4), false, Path::new(LEFTOVERS)) else {
        panic!("the removal's task is left, but the removal is not a failure");
    };

    assert_eq!(
        why,
        r"the removal is done, but its task is still registered: delete it with `schtasks /Delete /TN reverse-tunnel-uninstall`, and the files C:\.reverse-tunnel.* by hand"
    );
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

/// The leftover file in `dir` that renamed a file called `original`, called `id`.
fn leftover_in(dir: &Path, id: &str, original: &str) -> PathBuf {
    dir.join(schtasks::leftover_name(id, OsStr::new(original)))
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
        leftover_in(dir.path(), "a", "reverse-tunnel.exe"),
        leftover_in(dir.path(), "b", "reverse-tunnel.exe"),
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

#[test]
fn the_rerun_advice_does_not_name_a_leftover_that_was_another_program() {
    let (dir, paths) = installed();
    fs::remove_file(service::exe(&paths)).unwrap();
    // frpc is renamed by the same removal, and running it with `uninstall` would not uninstall anything.
    fs::write(leftover_in(dir.path(), "a", "frpc-0.1.exe"), "").unwrap();

    assert_eq!(
        rerun_uninstall(&paths),
        "run `uninstall` in an elevated prompt with any `reverse-tunnel` binary (the installed one is gone)"
    );

    let ours = leftover_in(dir.path(), "b", "REVERSE-TUNNEL.EXE");
    fs::write(&ours, "").unwrap();
    assert_eq!(
        rerun_uninstall(&paths),
        format!(
            "run `\"{}\" uninstall` in an elevated prompt (the installed binary is gone)",
            ours.display()
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

// Shared with `tests/`, which uses all of it.
#[allow(dead_code)]
#[path = "../tests/support/held.rs"]
mod held;

use held::running;

#[test]
fn a_staged_copy_that_runs_does_not_fail_the_sweep_of_the_bin_dir() {
    let (_dir, paths) = installed();
    let staged = paths.bin_dir.join(format!("{}x.exe", upgrade::STAGED));
    let _running = running(&staged);

    clean_bin_dir(&paths).unwrap();

    assert!(staged.exists());
}

#[test]
fn a_stale_file_that_runs_fails_the_sweep_of_the_bin_dir() {
    let (_dir, paths) = installed();
    let stale = paths.bin_dir.join("frpc-0.0.1");
    let _running = running(&stale);

    let err = format!("{:#}", clean_bin_dir(&paths).unwrap_err());

    assert!(err.contains("frpc-0.0.1"), "{err}");
}

#[test]
fn a_running_image_in_the_bin_dir_is_renamed_next_to_it_and_the_rest_is_deleted() {
    let (dir, paths) = installed();
    let _running = running(&paths.bin_dir.join("frpc-0.1.exe"));
    fs::write(paths.bin_dir.join("upgrade-1.exe"), "").unwrap();

    remove_or_rename(&paths.bin_dir, leftover_dir(&paths).unwrap()).unwrap();

    assert!(!paths.bin_dir.exists());
    let images = leftover_images(&paths).unwrap();
    let [image] = images.as_slice() else {
        panic!("expected one image: {images:?}")
    };
    assert_eq!(image.parent(), Some(dir.path()));
    let name = image.file_name().unwrap().to_string_lossy().into_owned();
    assert!(schtasks::is_leftover_of(&name, "frpc-0.1.exe"), "{name}");
    let pending = deletions_at_reboot();
    // The system writes the long form of the directory, and its own prefix, so only the file's name is compared.
    let scheduled = name.to_lowercase();
    assert!(
        pending.contains(&scheduled),
        "{scheduled} is not scheduled for deletion at the next boot: {pending}"
    );
}

/// The text of the files that the system deletes at its next boot, lower-cased, each as `\??\<path>`: the value is
/// a list of strings, read raw, with its NULs.
fn deletions_at_reboot() -> String {
    let session = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager")
        .unwrap();
    let value = session.get_raw_value("PendingFileRenameOperations").unwrap();
    let (pairs, _) = value.bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    String::from_utf16_lossy(&units).to_lowercase()
}

#[test]
fn only_the_bin_dir_has_a_running_image_renamed() {
    let (dir, paths) = installed();
    for removed in [&paths.config_dir, &paths.log_dir] {
        fs::create_dir_all(removed).unwrap();
    }
    fs::write(uninstalling_file(&paths), "").unwrap();
    let _running = [
        running(&paths.bin_dir.join("a.exe")),
        running(&paths.config_dir.join("b.exe")),
    ];

    let err = format!("{:#}", remove_files(&paths).unwrap_err());

    // Anything running from the config dir is the operator's, and fails the removal.
    assert!(err.contains("b.exe"), "{err}");
    assert!(paths.config_dir.join("b.exe").exists());
    assert!(!paths.bin_dir.exists());
    let names: Vec<_> = leftover_images(&paths)
        .unwrap()
        .iter()
        .map(|image| {
            assert_eq!(image.parent(), Some(dir.path()));
            image.file_name().unwrap().to_string_lossy().into_owned()
        })
        .collect();
    assert!(
        names.len() == 1 && schtasks::is_leftover_of(&names[0], "a.exe"),
        "{names:?}"
    );
}

#[test]
fn the_leftover_images_of_the_binary_are_those_that_kept_its_name() {
    let (dir, paths) = installed();
    fs::remove_file(service::exe(&paths)).unwrap();
    let ours = [
        leftover_in(dir.path(), "a", "reverse-tunnel.exe"),
        leftover_in(dir.path(), "b", "REVERSE-TUNNEL.EXE"),
    ];
    let others = [
        leftover_in(dir.path(), "c", "frpc-0.1.exe"),
        leftover_in(dir.path(), "d", "old-reverse-tunnel.exe"),
    ];
    for image in ours.iter().chain(&others) {
        fs::write(image, "").unwrap();
    }

    assert_eq!(leftover_images_of_the_binary(&paths).unwrap(), ours);
}

#[test]
fn nothing_is_renamed_when_everything_can_be_deleted() {
    let (_dir, paths) = installed();
    fs::write(paths.bin_dir.join("frpc-0.1.exe"), "").unwrap();

    remove_or_rename(&paths.bin_dir, leftover_dir(&paths).unwrap()).unwrap();

    assert!(!paths.bin_dir.exists());
    assert!(leftover_images(&paths).unwrap().is_empty());
}

#[test]
fn a_bin_dir_that_is_gone_is_removed() {
    let (_dir, paths) = installed();
    fs::remove_dir_all(&paths.bin_dir).unwrap();

    remove_or_rename(&paths.bin_dir, leftover_dir(&paths).unwrap()).unwrap();
}

#[test]
fn a_file_that_can_be_neither_deleted_nor_renamed_fails_the_removal_naming_both() {
    let (dir, paths) = installed();
    let stuck = paths.bin_dir.join("frpc-0.1.exe");
    let _running = running(&stuck);

    // Nothing to rename it into.
    let err = format!(
        "{:#}",
        remove_or_rename(&paths.bin_dir, &dir.path().join("missing")).unwrap_err()
    );

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

    let err = format!(
        "{:#}",
        remove_or_rename(&paths.bin_dir, leftover_dir(&paths).unwrap()).unwrap_err()
    );

    assert!(err.contains("old"), "{err}");
    assert!(sub.exists());
    assert!(leftover_images(&paths).unwrap().is_empty());
}
