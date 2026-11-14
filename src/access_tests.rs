use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_GENERIC_WRITE};

use super::*;

const SERVICE: &str = "S-1-5-80-1-2-3-4-5";
const EVERYONE: &str = "S-1-1-0";
const USERS: &str = "S-1-5-32-545";
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn ace(allows: bool, sid: &str, mask: u32) -> Ace {
    Ace {
        allows,
        inherit_only: false,
        mask,
        sid: Sid::parse(sid).unwrap(),
    }
}

/// What the check finds for `aces`, with the service and the groups Everyone and Users credited.
fn barrier(aces: &[Ace], needs: u32) -> Option<Barrier> {
    let who = [(EVERYONE, "Everyone"), (USERS, "Users"), (SERVICE, "the service")];
    let who: Vec<(Sid, &str)> = who
        .iter()
        .map(|(sid, name)| (Sid::parse(sid).unwrap(), *name))
        .collect();
    barrier_of(aces, &who, needs)
}

#[test]
fn an_allow_for_the_service_is_enough() {
    assert!(barrier(&[ace(true, SERVICE, FILE_GENERIC_READ)], FILE_GENERIC_READ).is_none());
}

#[test]
fn an_allow_for_a_credited_group_is_enough() {
    assert!(barrier(&[ace(true, USERS, FILE_GENERIC_READ)], FILE_GENERIC_READ).is_none());
}

#[test]
fn an_allow_for_a_group_the_service_is_not_known_to_have_is_not_enough() {
    let found = barrier(&[ace(true, ADMINISTRATORS, FILE_GENERIC_READ)], FILE_GENERIC_READ);

    assert!(matches!(found, Some(Barrier::NotAllowed)), "{found:?}");
}

#[test]
fn rights_allowed_by_several_aces_add_up() {
    let aces = [ace(true, USERS, 0x1), ace(true, SERVICE, FILE_GENERIC_READ & !0x1)];

    assert!(barrier(&aces, FILE_GENERIC_READ).is_none());
}

#[test]
fn an_allow_of_less_than_is_needed_is_not_enough() {
    let found = barrier(&[ace(true, SERVICE, FILE_GENERIC_READ & !0x1)], FILE_GENERIC_READ);

    assert!(matches!(found, Some(Barrier::NotAllowed)), "{found:?}");
}

#[test]
fn a_deny_for_the_service_or_a_credited_group_names_who_is_denied() {
    for (sid, name) in [(SERVICE, "the service"), (EVERYONE, "Everyone")] {
        let aces = [ace(false, sid, 0x1), ace(true, EVERYONE, FILE_GENERIC_READ)];

        let found = barrier(&aces, FILE_GENERIC_READ);

        assert!(matches!(found, Some(Barrier::Denied(who)) if who == name), "{sid}");
    }
}

#[test]
fn a_deny_for_someone_else_or_of_other_rights_is_no_barrier() {
    let aces = [
        ace(false, ADMINISTRATORS, FILE_GENERIC_READ),
        ace(false, SERVICE, FILE_GENERIC_WRITE & !FILE_GENERIC_READ),
        ace(true, SERVICE, FILE_GENERIC_READ),
    ];

    assert!(barrier(&aces, FILE_GENERIC_READ).is_none());
}

#[test]
fn an_ace_that_only_applies_to_what_the_object_contains_counts_for_nothing() {
    let allow_only_below = Ace {
        inherit_only: true,
        ..ace(true, SERVICE, FILE_GENERIC_READ)
    };
    let deny_only_below = Ace {
        inherit_only: true,
        ..ace(false, SERVICE, FILE_GENERIC_READ)
    };

    let not_allowed = barrier(&[allow_only_below], FILE_GENERIC_READ);
    let allowed = barrier(
        &[deny_only_below, ace(true, SERVICE, FILE_GENERIC_READ)],
        FILE_GENERIC_READ,
    );

    assert!(matches!(not_allowed, Some(Barrier::NotAllowed)), "{not_allowed:?}");
    assert!(allowed.is_none(), "{allowed:?}");
}
