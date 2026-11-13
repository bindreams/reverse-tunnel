use std::ptr::null_mut;

use windows_sys::Win32::System::RemoteDesktop::{WTSTypeProcessInfoLevel0, WTSTypeProcessInfoLevel1};
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
        "reverse-tunnel",
        &[process(12, "reverse-tunnel.exe"), process(34, "frpc.exe")],
    );

    assert_eq!(
        line,
        r"waiting for 2 processes of NT SERVICE\reverse-tunnel to end: 12 reverse-tunnel.exe, 34 frpc.exe"
    );
}

#[test]
fn the_line_says_process_for_one() {
    let line = waiting_line("x", &[this_process()]);

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

/// A buffer is freed as the class of the level it came back with; for a level that is none of the two, as the class
/// that was asked for.
#[test]
fn a_buffer_is_freed_as_the_class_of_its_level_or_else_as_the_one_asked_for() {
    assert_eq!(class_of(0), WTSTypeProcessInfoLevel0);
    assert_eq!(class_of(1), WTSTypeProcessInfoLevel1);
    assert_eq!(class_of(7), WTSTypeProcessInfoLevel1);
}

/// An image name is for the log line only, so it never fails the wait.
#[test]
fn an_image_name_that_is_not_utf16_is_decoded_with_replacement_characters() {
    let name: Vec<u16> = vec![0xD800, 'a' as u16, 0];

    // SAFETY: NUL-terminated.
    assert_eq!(unsafe { image_name(PCWSTR(name.as_ptr())) }, "\u{FFFD}a");
}

#[test]
fn a_service_that_no_process_runs_as_has_no_process_to_wait_for() {
    wait_until_none_runs_as("reverse-tunnel-no-such-service").unwrap();
}

/// What the wait names is what it waits for: a process that cannot be waited for is not named.
#[test]
fn only_the_processes_that_were_opened_are_waited_on() {
    let ended = Listed {
        pid: 1,
        image: "ended.exe".into(),
    };

    let ours = open_all(&[ended, this_process()], &this_user()).unwrap();
    let not_ours = open_all(&[this_process()], &nobody()).unwrap();

    assert_eq!(ours.len(), 1);
    assert_eq!(ours[0].0.pid, std::process::id());
    assert!(not_ours.is_empty());
}

/// A reused id that cannot be opened is not ours, once the listing no longer has it under the service's SID.
#[test]
fn a_process_that_cannot_be_opened_and_is_no_longer_listed_is_skipped() {
    let listing = [Listed {
        pid: 8,
        image: "other.exe".into(),
    }];

    assert!(skip_if_unlisted(anyhow!("access denied"), 4, &listing).is_ok());
}

#[test]
fn a_process_that_cannot_be_opened_and_is_still_listed_fails_with_the_error() {
    let listing = [Listed {
        pid: 4,
        image: "frpc.exe".into(),
    }];

    let err = skip_if_unlisted(anyhow!("opening process 4 (frpc.exe): access denied"), 4, &listing).unwrap_err();

    assert!(
        err.to_string().contains("opening process 4 (frpc.exe): access denied"),
        "{err}"
    );
}
