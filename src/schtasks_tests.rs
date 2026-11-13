use std::ffi::OsStr;

use windows::Win32::System::TaskScheduler::{TASK_STATE_DISABLED, TASK_STATE_READY};

use super::*;

#[test]
fn the_script_reaches_cmd_whole() {
    let xml = task_xml(r#""C:\a b\x.exe" uninstall --finish > "C:\a b\log" 2>&1 & rmdir /s /q "C:\a b""#);
    assert!(
        xml.contains(r#"<Arguments>/s /c ""C:\a b\x.exe" uninstall --finish &gt; "C:\a b\log" 2&gt;&amp;1 &amp; rmdir /s /q "C:\a b""</Arguments>"#),
        "{xml}"
    );
}

#[test]
fn each_step_of_the_script_fails_with_its_own_exit_code() {
    let script = removal_script(
        Path::new(r"C:\d\x.exe"),
        Path::new(r"C:\d\log"),
        Path::new(r"C:\d"),
        "task",
        Path::new(r"C:\p"),
    );
    // A program is judged by its exit code, a builtin (`del`, `rmdir`) by what it left, since it reports a held file
    // only in its message. The last step, the sweep, has no code: it goes on until it is done.
    assert!(
        script.starts_with(
            r#"("C:\d\x.exe" uninstall --finish > "C:\d\log" 2>&1 || exit /b 1) & del /q "C:\d\x.exe" >> "C:\d\log" 2>&1 & (if exist "C:\d\x.exe" exit /b 2) & rmdir /s /q "C:\d" & (if exist "C:\d" exit /b 3) & (schtasks /Delete /F /TN task || exit /b 4) & "#
        ),
        "{script}"
    );
}

#[test]
fn a_task_that_is_queued_or_running_runs_whatever_its_last_result() {
    assert_eq!(task_state(TASK_STATE_RUNNING, 0, 1), TaskState::Running);
    assert_eq!(task_state(TASK_STATE_QUEUED, 0, 0), TaskState::Running);
}

#[test]
fn a_task_that_is_ready_has_ended_unless_its_result_says_it_has_not_run() {
    assert_eq!(task_state(TASK_STATE_READY, 0, 3), TaskState::Ended(3));
    assert_eq!(
        task_state(TASK_STATE_READY, 0, -1073741510),
        TaskState::Ended(-1073741510)
    );
    for not_ended in NOT_ENDED {
        assert_eq!(task_state(TASK_STATE_READY, 0, not_ended), TaskState::Running);
    }
}

#[test]
fn an_informational_result_that_is_not_a_not_ended_one_is_an_ended_task_with_that_code() {
    // Disabled, no more runs, terminated: the task will not run, and none of them is an exit code of the script's.
    for informational in [0x41302, 0x41304, 0x41306, 0x4130F] {
        assert_eq!(
            task_state(TASK_STATE_READY, 0, informational),
            TaskState::Ended(informational)
        );
        assert_eq!(
            task_state(TASK_STATE_DISABLED, 0, informational),
            TaskState::Ended(informational)
        );
    }
}

#[test]
fn a_task_that_is_disabled_before_it_ran_is_disabled() {
    for not_ended in NOT_ENDED {
        assert_eq!(task_state(TASK_STATE_DISABLED, 0, not_ended), TaskState::Disabled);
    }
}

#[test]
fn a_task_that_ran_and_was_disabled_after_has_ended() {
    assert_eq!(task_state(TASK_STATE_DISABLED, 0, 4), TaskState::Ended(4));
    assert_eq!(task_state(TASK_STATE_DISABLED, 0, 0), TaskState::Ended(0));
}

#[test]
fn a_task_with_an_instance_running_runs_even_when_it_is_disabled() {
    // Disabling a task does not stop the instance that runs.
    assert_eq!(task_state(TASK_STATE_DISABLED, 1, 0x41301), TaskState::Running);
    assert_eq!(task_state(TASK_STATE_DISABLED, 1, 0), TaskState::Running);
}

#[test]
fn a_failed_read_is_gone_if_the_task_is_gone_when_looked_up_again_and_an_error_otherwise() {
    let failed = || windows::core::Error::from(windows::Win32::Foundation::E_FAIL);

    let gone = windows::core::Error::from_hresult(not_found());
    assert_eq!(after_a_failed_read(Err(gone), failed()).unwrap(), TaskState::Gone);
    // Found again, or another failure: nothing says the task is gone, and a failed read is no state.
    let found = after_a_failed_read(Ok(()), failed()).unwrap_err().to_string();
    assert!(found.contains("reading the removal's task"), "{found}");
    assert!(after_a_failed_read(Err(failed()), failed()).is_err());
}

#[test]
fn the_script_sweeps_the_leftover_images_after_the_task_itself_and_until_none_is_left() {
    let script = removal_script(
        Path::new(r"C:\d\x.exe"),
        Path::new(r"C:\d\log"),
        Path::new(r"C:\d"),
        "task",
        Path::new(r"C:\p"),
    );

    // The waiter holds its image until the task is gone, so the step comes after it; it repeats, with a pause between
    // the checks, until no file of the pattern is there. `/f` deletes a read-only file too.
    let pattern = leftover_pattern(Path::new(r"C:\p")).display().to_string();
    assert_eq!(pattern, r"C:\p\.reverse-tunnel.*");
    assert!(
        script.ends_with(&format!(
            r#"(schtasks /Delete /F /TN task || exit /b 4) & for /l %i in (1,0,2) do ((del /f /q "{pattern}" >nul 2>&1) & (if not exist "{pattern}" exit /b 0) & ping -n 2 127.0.0.1 >nul)"#
        )),
        "{script}"
    );
}

#[test]
fn a_leftover_keeps_the_name_of_the_file_it_was() {
    let name = leftover_name("ab12", OsStr::new("frpc-0.1.exe"));

    assert_eq!(name, ".reverse-tunnel.ab12.frpc-0.1.exe");
}

#[test]
fn a_leftover_is_what_the_pattern_matches_whatever_the_case() {
    let name = leftover_name("ab12", OsStr::new("frpc-0.1.exe"))
        .to_string_lossy()
        .into_owned();

    assert!(is_leftover(&name));
    assert!(is_leftover(&name.to_uppercase()));
    assert!(!is_leftover("reverse-tunnel.exe"));
    assert!(!is_leftover("x.reverse-tunnel.ab12.exe"));
}

#[test]
fn a_leftover_is_of_a_file_by_the_name_it_kept_whatever_the_case() {
    let ours = leftover_name("ab12", OsStr::new("reverse-tunnel.exe"))
        .to_string_lossy()
        .into_owned();
    let frpc = leftover_name("ab12", OsStr::new("frpc-0.1.exe"))
        .to_string_lossy()
        .into_owned();

    assert!(is_leftover_of(&ours, "reverse-tunnel.exe"));
    assert!(is_leftover_of(&ours.to_uppercase(), "reverse-tunnel.exe"));
    assert!(!is_leftover_of(&frpc, "reverse-tunnel.exe"));
    // A name that only ends like the original is another file.
    let longer = leftover_name("ab12", OsStr::new("old-reverse-tunnel.exe"))
        .to_string_lossy()
        .into_owned();
    assert!(!is_leftover_of(&longer, "reverse-tunnel.exe"));
    assert!(!is_leftover_of("reverse-tunnel.exe", "reverse-tunnel.exe"));
}
