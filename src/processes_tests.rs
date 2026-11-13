use super::*;

/// The listing's entry for this test process.
fn this_process() -> Listed {
    let pid = std::process::id();
    list()
        .unwrap()
        .into_iter()
        .find(|process| process.pid == pid)
        .unwrap_or_else(|| panic!("the listing has no process {pid}"))
}

#[test]
fn a_process_is_listed_with_its_image_and_the_user_it_runs_as() {
    let this = this_process();

    let exe = std::env::current_exe().unwrap();
    let image = exe.file_name().unwrap().to_str().unwrap();
    assert!(this.image.eq_ignore_ascii_case(image), "{} is not {image}", this.image);
    let sid = this.sid.expect("a user process has a user");
    assert!(sid.starts_with("S-1-5-"), "{sid}");
}

#[test]
fn the_processes_that_run_as_a_user_are_those_listed_with_its_sid() {
    let this = this_process();
    let sid = this.sid.clone().unwrap();

    let ours = running_as(&sid).unwrap();

    assert!(ours.iter().any(|process| process.pid == this.pid));
    assert!(ours.iter().all(|process| process.sid.as_deref() == Some(sid.as_str())));
    // The SID of a service that does not exist.
    assert!(running_as("S-1-5-80-1-2-3-4-5").unwrap().is_empty());
}

/// Windows ids are multiples of four, so no process has the id 1.
#[test]
fn a_process_that_has_ended_is_gone_when_it_is_opened_and_not_an_error() {
    let ended = Listed {
        pid: 1,
        image: "ended.exe".into(),
        sid: None,
    };

    assert!(open(&ended).unwrap().is_none());
}

#[test]
fn the_line_names_each_process_to_wait_for_by_id_and_image() {
    let process = |pid, image: &str| Listed {
        pid,
        image: image.into(),
        sid: None,
    };

    let line = waiting_line(
        r"NT SERVICE\reverse-tunnel",
        &[process(12, "reverse-tunnel.exe"), process(34, "frpc.exe")],
    );

    assert_eq!(
        line,
        r"waiting for 2 processes of NT SERVICE\reverse-tunnel to end: 12 reverse-tunnel.exe, 34 frpc.exe"
    );
}

#[test]
fn a_service_that_no_process_runs_as_has_no_process_to_wait_for() {
    wait_until_none_runs_as_service("reverse-tunnel-no-such-service").unwrap();
}
