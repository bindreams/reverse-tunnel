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
    );
    // A program is judged by its exit code, a builtin (`del`, `rmdir`) by what it left, since it reports a held file
    // only in its message.
    assert_eq!(
        script,
        r#"("C:\d\x.exe" uninstall --finish > "C:\d\log" 2>&1 || exit /b 1) & del /q "C:\d\x.exe" >> "C:\d\log" 2>&1 & (if exist "C:\d\x.exe" exit /b 2) & rmdir /s /q "C:\d" & (if exist "C:\d" exit /b 3) & (schtasks /Delete /F /TN task || exit /b 4)"#
    );
}

#[test]
fn a_task_that_is_queued_or_running_runs_whatever_its_last_result() {
    assert_eq!(task_state(TASK_STATE_RUNNING, 1), TaskState::Running);
    assert_eq!(task_state(TASK_STATE_QUEUED, 0), TaskState::Running);
}

#[test]
fn a_task_that_is_ready_has_ended_unless_its_result_says_it_has_not_run() {
    assert_eq!(task_state(TASK_STATE_READY, 3), TaskState::Ended(3));
    assert_eq!(task_state(TASK_STATE_READY, -1073741510), TaskState::Ended(-1073741510));
    for not_ended in NOT_ENDED {
        assert_eq!(task_state(TASK_STATE_READY, not_ended), TaskState::Running);
    }
}

#[test]
fn a_disabled_task_never_runs_whatever_its_last_result() {
    assert_eq!(task_state(TASK_STATE_DISABLED, 0x41303), TaskState::Disabled);
    assert_eq!(task_state(TASK_STATE_DISABLED, 4), TaskState::Disabled);
}
