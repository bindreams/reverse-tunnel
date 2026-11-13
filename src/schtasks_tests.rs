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
