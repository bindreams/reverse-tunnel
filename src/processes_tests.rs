use std::ptr::null_mut;

use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::*;

/// The user this test process runs as.
fn this_user() -> Sid {
    // SAFETY: a plain call; its result is a pseudo handle.
    user_of(unsafe { GetCurrentProcess() }).unwrap()
}

/// The SID of a service that does not exist.
fn nobody() -> Sid {
    Sid::parse("S-1-5-80-1-2-3-4-5").unwrap()
}

fn this_process() -> Listed {
    Listed {
        pid: std::process::id(),
        image: "this.exe".into(),
    }
}

#[test]
fn a_process_is_listed_with_its_image_and_the_user_it_runs_as() {
    let pid = std::process::id();

    let ours = running_as(&this_user()).unwrap();

    let this = ours
        .iter()
        .find(|process| process.pid == pid)
        .unwrap_or_else(|| panic!("the listing has no process {pid} of its user"));
    let exe = std::env::current_exe().unwrap();
    let image = exe.file_name().unwrap().to_str().unwrap();
    assert!(this.image.eq_ignore_ascii_case(image), "{} is not {image}", this.image);
}

#[test]
fn no_process_is_listed_for_a_user_that_none_runs_as() {
    assert!(running_as(&nobody()).unwrap().is_empty());
}

/// Windows ids are multiples of four, so no process has the id 1.
#[test]
fn a_process_that_has_ended_is_gone_when_it_is_opened_and_not_an_error() {
    let ended = Listed {
        pid: 1,
        image: "ended.exe".into(),
    };

    assert!(open(&ended, &this_user()).unwrap().is_none());
}

#[test]
fn a_process_that_runs_as_the_user_it_was_listed_for_is_opened() {
    assert!(open(&this_process(), &this_user()).unwrap().is_some());
}

/// The id of a process that ended can be given to another, which then must not be waited for.
#[test]
fn a_process_that_runs_as_another_user_than_the_one_it_was_listed_for_is_not_ours() {
    assert!(open(&this_process(), &nobody()).unwrap().is_none());
}

#[test]
fn the_line_names_each_process_to_wait_for_by_id_and_image() {
    let process = |pid, image: &str| Listed {
        pid,
        image: image.into(),
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
fn the_line_says_process_for_one() {
    let line = waiting_line(r"NT SERVICE\x", &[this_process()]);

    assert!(line.starts_with("waiting for 1 process of "), "{line}");
}

/// A listing that returned no buffer or no entries has nothing to read, and a slice must never be made from null.
#[test]
fn a_listing_without_a_buffer_or_entries_is_empty() {
    assert!(Buffer::new(null_mut(), 0, 1).unwrap().entries().is_empty());
    assert!(Buffer::new(null_mut(), 3, 1).unwrap().entries().is_empty());
}

#[test]
fn a_listing_of_another_level_than_the_one_asked_for_is_refused() {
    let err = Buffer::new(null_mut(), 0, 0).err().expect("level 0 is not level 1");

    assert!(err.to_string().contains("level 0"), "{err}");
}

#[test]
fn an_account_that_no_process_runs_as_has_no_process_to_wait_for() {
    wait_until_none_runs_as(r"NT SERVICE\reverse-tunnel-no-such-service").unwrap();
}
