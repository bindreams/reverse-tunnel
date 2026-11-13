use super::*;

const RUNNING_LINE: &str = r#""HOST","\reverse-tunnel-uninstall","N/A","Running","Interactive/Background","11/12/2026 1:02:03 PM","267009","bindreams","cmd.exe /s /c ...""#;

#[test]
fn a_task_that_runs_or_has_not_run_has_no_exit_code() {
    assert_eq!(last_result(RUNNING_LINE).unwrap(), None);
    assert_eq!(last_result(&RUNNING_LINE.replace("267009", "267011")).unwrap(), None);
}

#[test]
fn a_task_that_is_ready_or_queued_has_not_ended() {
    // SCHED_S_TASK_READY and SCHED_S_TASK_QUEUED.
    assert_eq!(last_result(&RUNNING_LINE.replace("267009", "267008")).unwrap(), None);
    assert_eq!(last_result(&RUNNING_LINE.replace("267009", "267045")).unwrap(), None);
}

#[test]
fn a_task_that_ended_has_its_exit_code() {
    assert_eq!(last_result(&RUNNING_LINE.replace("267009", "0")).unwrap(), Some(0));
    assert_eq!(
        last_result(&RUNNING_LINE.replace("267009", "-2147024894")).unwrap(),
        Some(-2147024894)
    );
}

#[test]
fn a_word_where_the_code_belongs_is_an_error() {
    assert!(last_result(&RUNNING_LINE.replace("267009", "Ready")).is_err());
    assert!(last_result("").is_err());
}

#[test]
fn the_script_reaches_cmd_whole() {
    let xml = task_xml(r#""C:\a b\x.exe" uninstall --finish > "C:\a b\log" 2>&1 && rmdir /s /q "C:\a b""#);
    assert!(
        xml.contains(r#"<Arguments>/s /c ""C:\a b\x.exe" uninstall --finish &gt; "C:\a b\log" 2&gt;&amp;1 &amp;&amp; rmdir /s /q "C:\a b""</Arguments>"#),
        "{xml}"
    );
}

#[test]
fn a_copy_that_cannot_be_deleted_fails_inside_the_log() {
    let script = removal_script(
        Path::new(r"C:\d\x.exe"),
        Path::new(r"C:\d\log"),
        Path::new(r"C:\d"),
        "task",
    );
    let (logged, after) = script.split_once(" > ").unwrap();
    assert!(logged.contains(r#"del /q "C:\d\x.exe""#), "{script}");
    // `del` succeeds on a copy that is held; the group must fail by itself.
    assert!(logged.contains(r#"&& if exist "C:\d\x.exe" exit /b 1 )"#), "{script}");
    assert!(
        after.starts_with(r#""C:\d\log" 2>&1 && rmdir /s /q "C:\d" && schtasks /Delete /F /TN task"#),
        "{script}"
    );
}

const LISTING: &str = r#"
"\Microsoft\Windows\Defrag\ScheduledDefrag","N/A","Ready"
"\reverse-tunnel-uninstall-old","N/A","Ready"
"#;

#[test]
fn a_listing_without_the_task_says_it_is_gone() {
    assert!(
        !lists_task(LISTING, "reverse-tunnel-uninstall"),
        "a task with a longer name is not it"
    );
    assert!(!lists_task("", "reverse-tunnel-uninstall"));
}

#[test]
fn a_listing_with_the_task_says_it_is_there() {
    let listing = format!("{LISTING}{}", r#""\Reverse-Tunnel-Uninstall","N/A","Running""#);
    assert!(lists_task(&listing, "reverse-tunnel-uninstall"));
}
