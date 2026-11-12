use super::*;

const RUNNING_LINE: &str = r#""HOST","\reverse-tunnel-uninstall","N/A","Running","Interactive/Background","11/12/2026 1:02:03 PM","267009","bindreams","cmd.exe /s /c ...""#;

#[test]
fn a_task_that_runs_or_has_not_run_has_no_exit_code() {
    assert_eq!(last_result(RUNNING_LINE).unwrap(), None);
    assert_eq!(last_result(&RUNNING_LINE.replace("267009", "267011")).unwrap(), None);
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
