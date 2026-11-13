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
