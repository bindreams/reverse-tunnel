use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

use super::*;

const SERVICE: &str = "S-1-5-80-1-2-3-4-5";
const EVERYONE: &str = "S-1-1-0";
const USERS: &str = "S-1-5-32-545";
const ADMINISTRATORS: &str = "S-1-5-32-544";

fn ace(allows: bool, sid: &str, mask: u32) -> Ace {
    Ace {
        allows,
        inherit_only: false,
        object_inherit: false,
        mask,
        sid: Sid::parse(sid).unwrap(),
    }
}

fn who() -> Vec<(Sid, &'static str)> {
    [(EVERYONE, "Everyone"), (USERS, "Users"), (SERVICE, "the service")]
        .iter()
        .map(|(sid, name)| (Sid::parse(sid).unwrap(), *name))
        .collect()
}

/// What the check finds for `aces`, with the service and the groups Everyone and Users credited, and no demand on the
/// files made in the directory.
fn barrier(aces: &[Ace], needs: u32) -> Option<Barrier> {
    barrier_of(aces, &who(), needs, 0)
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
fn an_allow_of_generic_rights_counts_as_the_file_rights_they_map_to() {
    for (generic, needs) in [
        (GENERIC_READ, FILE_GENERIC_READ),
        (GENERIC_WRITE, FILE_GENERIC_WRITE),
        (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
        (
            GENERIC_ALL,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_GENERIC_WRITE | DELETE,
        ),
    ] {
        let found = barrier(&[ace(true, EVERYONE, generic)], needs);

        assert!(found.is_none(), "{generic:#x}: {found:?}");
    }
}

#[test]
fn any_deny_ace_is_a_barrier_naming_its_sid_whoever_it_names_and_whatever_it_denies() {
    for sid in [SERVICE, EVERYONE, ADMINISTRATORS] {
        let aces = [ace(false, sid, 0x1), ace(true, EVERYONE, FILE_GENERIC_READ)];

        let found = barrier(&aces, FILE_GENERIC_READ);

        assert!(matches!(found, Some(Barrier::Denied(_))), "{sid}: {found:?}");
    }
    let other_rights = [
        ace(false, ADMINISTRATORS, FILE_GENERIC_WRITE & !FILE_GENERIC_READ),
        ace(true, SERVICE, FILE_GENERIC_READ),
    ];

    assert!(matches!(
        barrier(&other_rights, FILE_GENERIC_READ),
        Some(Barrier::Denied(_))
    ));
}

#[test]
fn an_allow_that_only_applies_to_what_the_object_contains_counts_for_nothing_but_a_deny_still_fails() {
    let allow_only_below = Ace {
        inherit_only: true,
        ..ace(true, SERVICE, FILE_GENERIC_READ)
    };
    let deny_only_below = Ace {
        inherit_only: true,
        ..ace(false, SERVICE, FILE_GENERIC_READ)
    };

    let not_allowed = barrier(&[allow_only_below], FILE_GENERIC_READ);
    let denied = barrier(
        &[deny_only_below, ace(true, SERVICE, FILE_GENERIC_READ)],
        FILE_GENERIC_READ,
    );

    assert!(matches!(not_allowed, Some(Barrier::NotAllowed)), "{not_allowed:?}");
    assert!(matches!(denied, Some(Barrier::Denied(_))), "{denied:?}");
}

#[test]
fn a_missing_path_is_reported_as_missing() {
    let dir = tempfile::tempdir().unwrap();

    let said = problem(&Need::of(dir.path().join("config.yaml"), READ), &who()).unwrap();

    assert!(said.contains("is missing"), "{said}");
}

#[test]
fn a_missing_file_that_run_makes_is_no_problem() {
    let dir = tempfile::tempdir().unwrap();

    assert!(problem(&Need::made(dir.path().join("supervisor.log"), LOG), &who()).is_none());
}

#[test]
fn a_deny_names_the_account_or_group_and_only_an_sid_that_has_no_name_by_its_text() {
    let denied = |sid| match barrier(&[ace(false, sid, 0x1)], FILE_GENERIC_READ) {
        Some(Barrier::Denied(by)) => by,
        other => panic!("{other:?}"),
    };

    assert_eq!(denied(SERVICE), SERVICE);
    assert!(!denied(EVERYONE).contains("S-1-"), "{}", denied(EVERYONE));
    assert!(
        denied(ADMINISTRATORS).ends_with("Administrators"),
        "{}",
        denied(ADMINISTRATORS)
    );
}

#[test]
fn what_files_made_in_a_directory_inherit_is_judged_by_the_allows_they_inherit() {
    let inheriting = |inherit_only| Ace {
        object_inherit: true,
        inherit_only,
        ..ace(true, SERVICE, FILE_GENERIC_READ | FILE_GENERIC_WRITE)
    };
    let not_inheriting = ace(true, SERVICE, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
    let needs = (FILE_ADD_FILE, FILE_GENERIC_WRITE);

    let ok = barrier_of(&[inheriting(false)], &who(), needs.0, needs.1);
    let inherit_only = barrier_of(
        &[inheriting(true), ace(true, SERVICE, needs.0)],
        &who(),
        needs.0,
        needs.1,
    );
    let not_inherited = barrier_of(&[not_inheriting], &who(), needs.0, needs.1);

    assert!(ok.is_none(), "{ok:?}");
    assert!(inherit_only.is_none(), "{inherit_only:?}");
    assert!(
        matches!(not_inherited, Some(Barrier::NotInherited)),
        "{not_inherited:?}"
    );
}
