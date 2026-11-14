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
        r"the removal is done, but its task is still registered: delete it with `schtasks /Delete /TN reverse-tunnel-uninstall`. The files that remain (C:\.reverse-tunnel.*) can be deleted by hand once this `uninstall` has exited"
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
    dir.join(leftovers::name(id, OsStr::new(original)))
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

use crate::held::running;

/// The leftovers in `paths`' leftover folder, by the name each kept.
fn kept_names(paths: &Paths) -> Vec<String> {
    let images = leftovers::images(paths).unwrap();
    let names = images.iter().map(|image| image.file_name().unwrap().to_string_lossy());
    names
        .map(|name| leftovers::kept_name(&name).unwrap().to_string())
        .collect()
}

#[test]
fn a_staged_copy_that_runs_is_moved_aside_by_the_sweep_and_deleted_by_the_next_once_it_exits() {
    let (_dir, paths) = installed();
    let staged = paths.bin_dir.join(format!("{}x.exe", upgrade::STAGED));
    let running = running(&staged);

    clean_bin_dir(&paths).unwrap();

    assert!(!staged.exists());
    assert_eq!(kept_names(&paths), ["upgrade-x.exe"]);
    let kept = leftovers::delete_what_can_be(leftovers::images(&paths).unwrap());
    let [why] = kept.as_slice() else {
        panic!("it still runs: {kept:?}")
    };
    assert!(format!("{why:#}").contains("each `install` tries again"), "{why:#}");
    assert_eq!(kept_names(&paths), ["upgrade-x.exe"]);
    drop(running);
    assert!(leftovers::delete_what_can_be(leftovers::images(&paths).unwrap()).is_empty());
    assert_eq!(kept_names(&paths), Vec::<String>::new());
}

#[test]
fn the_sweep_keeps_the_registered_image_and_deletes_the_other_old_images_or_renames_one_that_runs() {
    let (_dir, paths) = installed();
    let image = |binary: &[u8]| service::image(&paths, binary);
    let (registered, old, previous) = (image(b"registered"), image(b"old"), image(b"previous"));
    let other = paths.bin_dir.join("frpc-0.1.exe");
    for file in [&registered, &old, &other] {
        fs::write(file, "").unwrap();
    }
    let running = running(&previous);

    assert!(sweep_old_images(&paths, &registered).is_empty());

    assert_eq!([&registered, &other].map(|file| file.exists()), [true; 2]);
    assert!(!old.exists() && !previous.exists());
    // The image that runs is a leftover, whose name is the image's, and is deleted once it has exited.
    assert_eq!(
        kept_names(&paths),
        [previous.file_name().unwrap().to_string_lossy().into_owned()]
    );
    drop(running);
    assert!(leftovers::delete_what_can_be(leftovers::images(&paths).unwrap()).is_empty());
    assert_eq!(kept_names(&paths), Vec::<String>::new());
}

#[test]
fn the_sweep_goes_on_past_an_image_it_cannot_delete() {
    let (_dir, paths) = installed();
    let registered = service::image(&paths, b"registered");
    let (stuck, old) = (service::image(&paths, b"stuck"), service::image(&paths, b"old"));
    fs::create_dir(&stuck).unwrap();
    fs::write(&old, "").unwrap();

    let kept = sweep_old_images(&paths, &registered);

    let [why] = kept.as_slice() else {
        panic!("expected only the directory to be reported: {kept:?}")
    };
    let why = format!("{why:#}");
    assert!(
        why.contains(&stuck.display().to_string()) && why.contains("not a regular file"),
        "{why}"
    );
    assert!(stuck.exists() && !old.exists());
}

#[test]
fn a_sweep_of_a_bin_dir_that_cannot_be_read_says_so() {
    let (_dir, paths) = installed();
    fs::remove_dir_all(&paths.bin_dir).unwrap();

    let kept = sweep_old_images(&paths, &service::image(&paths, b"registered"));

    let [why] = kept.as_slice() else {
        panic!("expected one error: {kept:?}")
    };
    let why = format!("{why:#}");
    assert!(
        why.starts_with(&format!("reading {}", paths.bin_dir.display())),
        "{why}"
    );
}

#[test]
fn a_stale_frpc_that_runs_is_renamed_aside_by_the_sweep() {
    let (_dir, paths) = installed();
    let stale = paths.bin_dir.join("frpc-0.0.1.exe");
    let _running = running(&stale);

    clean_bin_dir(&paths).unwrap();

    assert!(!stale.exists());
    assert_eq!(kept_names(&paths), ["frpc-0.0.1.exe"]);
}

#[test]
fn a_running_image_in_the_bin_dir_is_renamed_next_to_it_and_the_rest_is_deleted() {
    let (dir, paths) = installed();
    let _running = running(&paths.bin_dir.join("frpc-0.1.exe"));
    fs::write(paths.bin_dir.join("upgrade-1.exe"), "").unwrap();

    remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(&paths).unwrap()).unwrap();

    assert!(!paths.bin_dir.exists());
    let images = leftovers::images(&paths).unwrap();
    let [image] = images.as_slice() else {
        panic!("expected one image: {images:?}")
    };
    assert_eq!(image.parent(), Some(dir.path()));
    let name = image.file_name().unwrap().to_string_lossy().into_owned();
    assert!(leftovers::is_leftover_of(&name, "frpc-0.1.exe"), "{name}");
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
    let names: Vec<_> = leftovers::images(&paths)
        .unwrap()
        .iter()
        .map(|image| {
            assert_eq!(image.parent(), Some(dir.path()));
            image.file_name().unwrap().to_string_lossy().into_owned()
        })
        .collect();
    assert!(
        names.len() == 1 && leftovers::is_leftover_of(&names[0], "a.exe"),
        "{names:?}"
    );
}

#[test]
fn nothing_is_renamed_when_everything_can_be_deleted() {
    let (_dir, paths) = installed();
    fs::write(paths.bin_dir.join("frpc-0.1.exe"), "").unwrap();

    remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(&paths).unwrap()).unwrap();

    assert!(!paths.bin_dir.exists());
    assert!(leftovers::images(&paths).unwrap().is_empty());
}

#[test]
fn a_bin_dir_that_is_gone_is_removed() {
    let (_dir, paths) = installed();
    fs::remove_dir_all(&paths.bin_dir).unwrap();

    remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(&paths).unwrap()).unwrap();
}

#[test]
fn a_running_file_that_cannot_be_renamed_fails_the_removal_naming_it() {
    let (dir, paths) = installed();
    let stuck = paths.bin_dir.join("frpc-0.1.exe");
    let _running = running(&stuck);

    // Nothing to rename it into.
    let err = format!(
        "{:#}",
        remove_saying_what_it_moved_aside(&paths.bin_dir, &dir.path().join("missing")).unwrap_err()
    );

    assert!(err.contains("frpc-0.1.exe"), "{err}");
    assert!(err.contains("moving it to"), "{err}");
    // The delete's answer (access denied) and the rename's (no such path).
    assert!(err.contains("(os error 5)") && err.contains("(os error 3)"), "{err}");
    assert!(stuck.exists());
    assert!(leftovers::images(&paths).unwrap().is_empty());
}

#[test]
fn a_read_only_file_is_deleted_and_nothing_is_left() {
    let (_dir, paths) = installed();
    let file = paths.bin_dir.join("frpc-0.1.exe");
    fs::write(&file, "").unwrap();
    let mut readonly = fs::metadata(&file).unwrap().permissions();
    readonly.set_readonly(true);
    fs::set_permissions(&file, readonly).unwrap();

    remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(&paths).unwrap()).unwrap();

    assert!(!paths.bin_dir.exists());
    assert!(leftovers::images(&paths).unwrap().is_empty());
}

/// Gives `path` the protected DACL `sddl` until it drops, which restores `restored`.
struct Acl<'a> {
    path: &'a Path,
    restored: &'static str,
}

impl<'a> Acl<'a> {
    fn set(path: &'a Path, sddl: &str, restored: &'static str) -> Acl<'a> {
        crate::security::Descriptor::parse(sddl).unwrap().apply(path).unwrap();
        Acl { path, restored }
    }
}

impl Drop for Acl<'_> {
    fn drop(&mut self) {
        // Not a panic: one in a drop during a failed assertion aborts the whole test run.
        if let Ok(restored) = crate::security::Descriptor::parse(self.restored) {
            let _ = restored.apply(self.path);
        }
    }
}

/// A file whose ACL denies DELETE, in a directory whose ACL denies FILE_DELETE_CHILD, is refused both a delete and a
/// rename: the removal fails naming the file and both answers, and makes no leftover.
#[test]
fn a_file_that_its_acl_will_neither_delete_nor_rename_fails_the_removal_naming_both_refusals() {
    let (_dir, paths) = installed();
    let stuck = paths.bin_dir.join("frpc-0.1.exe");
    fs::write(&stuck, "").unwrap();
    // The directory's own ACE is not inherited, so the other files keep the full access it gives them.
    let _dir_denied = Acl::set(&paths.bin_dir, "D:P(D;;DT;;;WD)(A;OICI;FA;;;WD)", "D:P(A;OICI;FA;;;WD)");
    let _file_denied = Acl::set(&stuck, "D:P(D;;SD;;;WD)(A;;FA;;;WD)", "D:P(A;;FA;;;WD)");

    let err = format!(
        "{:#}",
        remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(&paths).unwrap()).unwrap_err()
    );

    assert!(err.contains("frpc-0.1.exe") && err.contains("moving it to"), "{err}");
    assert_eq!(
        err.matches("(os error 5)").count(),
        2,
        "the delete's and the rename's: {err}"
    );
    assert!(stuck.exists());
    assert!(leftovers::images(&paths).unwrap().is_empty());
}

#[test]
fn a_file_whose_delete_was_refused_and_is_gone_when_looked_at_is_deleted() {
    let (dir, paths) = installed();
    let gone = paths.bin_dir.join("gone.exe");
    let refused = |_: &Path| Err(io::Error::from(ErrorKind::PermissionDenied).into());

    let moved = delete_or_move_aside(&gone, dir.path(), refused).unwrap();

    assert_eq!(moved, None);
    assert!(leftovers::images(&paths).unwrap().is_empty());
}

#[test]
fn a_refused_delete_and_a_refused_move_keep_the_refusal_as_the_cause() {
    let (dir, paths) = installed();
    let file = paths.bin_dir.join("frpc-0.1.exe");
    fs::write(&file, "").unwrap();
    let refused = |_: &Path| Err(io::Error::from(ErrorKind::PermissionDenied).into());

    let err = delete_or_move_aside(&file, &dir.path().join("missing"), refused).unwrap_err();

    assert!(is_access_denied(&err), "{err:#}");
    assert!(format!("{err:#}").contains("moving it to"), "{err:#}");
}

#[test]
fn a_directory_that_cannot_be_deleted_fails_the_removal_and_is_not_renamed() {
    let (_dir, paths) = installed();
    let sub = paths.bin_dir.join("old");
    fs::create_dir_all(&sub).unwrap();
    let _running = running(&sub.join("frpc-0.1.exe"));

    let err = format!(
        "{:#}",
        remove_saying_what_it_moved_aside(&paths.bin_dir, leftovers::dir(&paths).unwrap()).unwrap_err()
    );

    assert!(err.contains("old"), "{err}");
    assert!(err.contains("not moved"), "{err}");
    assert!(sub.exists());
    assert!(leftovers::images(&paths).unwrap().is_empty());
}

#[test]
fn bin_dir_cleaning_never_recurses_into_a_directory_that_has_a_stale_name() {
    let (_dir, paths) = installed();
    let stale = paths.bin_dir.join("frpc-0.0.1");
    fs::create_dir_all(&stale).unwrap();
    fs::write(stale.join("inside"), b"x").unwrap();

    clean_bin_dir(&paths).unwrap_err();

    assert!(stale.join("inside").exists());
}
