use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES,
};

use super::*;

const SERVICE: &str = "S-1-5-80-1-2-3-4-5";
const EVERYONE: &str = "S-1-1-0";
const USERS: &str = "S-1-5-32-545";
const ADMINISTRATORS: &str = "S-1-5-32-544";
/// An account of a domain that is not this machine's.
const FOREIGN_DOMAIN_ACCOUNT: &str = "S-1-5-21-111-222-333-1000";

fn ace(allows: bool, sid: &str, mask: u32) -> Ace {
    Ace {
        allows,
        inherit_only: false,
        object_inherit: false,
        mask,
        sid: Sid::parse(sid).unwrap(),
    }
}

fn who() -> Principals {
    Principals {
        holders: [(EVERYONE, "Everyone"), (USERS, "Users"), (SERVICE, "the service")]
            .iter()
            .map(|(sid, name)| (Sid::parse(sid).unwrap(), *name))
            .collect(),
    }
}

/// `barrier_of` with no demand on files made in the directory.
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

/// What a deny ACE for `sid` is reported as, with an allow for another SID that would otherwise be enough.
fn denied_by(sid: &str, denied: u32) -> Barrier {
    let allowed = if sid == EVERYONE { USERS } else { EVERYONE };
    let aces = [ace(false, sid, denied), ace(true, allowed, FILE_GENERIC_READ)];
    barrier(&aces, FILE_GENERIC_READ).expect("a deny ACE is a barrier")
}

#[test]
fn any_deny_ace_is_a_barrier_whoever_it_names_and_whatever_it_denies() {
    for sid in [SERVICE, EVERYONE, ADMINISTRATORS, FOREIGN_DOMAIN_ACCOUNT] {
        assert!(matches!(denied_by(sid, 0x1), Barrier::Denied(_)), "{sid}");
    }
    let found = denied_by(ADMINISTRATORS, FILE_GENERIC_WRITE & !FILE_GENERIC_READ);

    assert!(matches!(found, Barrier::Denied(_)), "{found:?}");
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

fn dacl(aces: Vec<Ace>, left_out: usize) -> io::Result<Dacl> {
    Ok(Dacl { aces, left_out })
}

#[test]
fn a_denied_path_is_explained_by_the_principal_denied_and_the_remedy() {
    let aces = vec![ace(false, ADMINISTRATORS, 0x1), ace(true, EVERYONE, FILE_GENERIC_READ)];

    let said = explain(&Need::of("config.yaml".into(), READ), &who(), dacl(aces, 0)).unwrap();

    let by = Sid::parse(ADMINISTRATORS).unwrap().label();
    assert!(said.contains(&format!("denies access to {by}")), "{said}");
    assert!(
        said.contains(&format!("{} must not be denied anything", service::ACCOUNT)),
        "{said}"
    );
}

#[test]
fn a_path_nothing_allows_is_explained_by_the_right_the_groups_and_any_ace_not_counted() {
    let need = Need::of("config.yaml".into(), READ);
    let aces = || vec![ace(true, ADMINISTRATORS, FILE_GENERIC_READ)];

    let plain = explain(&need, &who(), dacl(aces(), 0)).unwrap();
    let one = explain(&need, &who(), dacl(aces(), 1)).unwrap();
    let several = explain(&need, &who(), dacl(aces(), 3)).unwrap();

    // `who()` lists the groups after the first holder.
    assert!(
        plain.contains(&format!("{} cannot read it", service::ACCOUNT)) && plain.contains("(Users, the service)"),
        "{plain}"
    );
    assert!(!plain.contains("not counted"), "{plain}");
    assert!(
        one.contains("One conditional or object allow ACE was not counted."),
        "{one}"
    );
    assert!(
        several.contains("3 conditional or object allow ACEs were not counted."),
        "{several}"
    );
}

#[test]
fn a_directory_whose_files_would_not_be_allowed_is_explained_with_any_ace_not_counted() {
    let need = Need {
        files: Some(NEW_FILE),
        ..Need::of("logs".into(), MAKE_FILES)
    };
    let aces = || vec![ace(true, SERVICE, FILE_ADD_FILE)];

    let plain = explain(&need, &who(), dacl(aces(), 0)).unwrap();
    let left_out = explain(&need, &who(), dacl(aces(), 1)).unwrap();

    assert!(
        plain.contains("the files")
            && plain.contains("read, write and delete themselves")
            && plain.contains("that files inherit"),
        "{plain}"
    );
    assert!(!plain.contains("not counted"), "{plain}");
    assert!(
        left_out.contains("One conditional or object allow ACE was not counted."),
        "{left_out}"
    );
}

#[test]
fn a_path_whose_acl_cannot_be_read_is_explained_by_the_error() {
    let unreadable = Err(io::Error::new(ErrorKind::PermissionDenied, "access is denied"));

    let said = explain(&Need::of("config.yaml".into(), READ), &who(), unreadable).unwrap();

    assert!(
        said.contains("its ACL cannot be read") && said.contains("access is denied"),
        "{said}"
    );
}

#[test]
fn a_path_with_what_it_needs_is_no_problem() {
    let aces = vec![ace(true, SERVICE, FILE_GENERIC_READ)];

    assert!(explain(&Need::of("config.yaml".into(), READ), &who(), dacl(aces, 0)).is_none());
}

#[test]
fn a_deny_is_reported_by_the_denied_principal_not_the_allowed_one() {
    let denied = |sid| match denied_by(sid, 0x1) {
        Barrier::Denied(by) => by,
        other => panic!("{other:?}"),
    };

    assert_eq!(denied(SERVICE), SERVICE);
    // A domain account is not looked up: it is shown by its SID.
    assert_eq!(denied(FOREIGN_DOMAIN_ACCOUNT), FOREIGN_DOMAIN_ACCOUNT);
    // The name is the system's, which a localized Windows gives in its language: only that it is a name, and not the
    // one of the principal that is allowed.
    let everyone = denied(EVERYONE);
    assert!(!everyone.contains("S-1-"), "{everyone}");
    assert_ne!(everyone, Sid::parse(USERS).unwrap().label());
    let admins = denied(ADMINISTRATORS);
    assert!(!admins.contains("S-1-"), "{admins}");
    assert_ne!(admins, Sid::parse(EVERYONE).unwrap().label());
}

#[test]
fn a_deny_is_reported_whether_the_allow_comes_before_it_or_after() {
    let aces = [ace(true, EVERYONE, FILE_GENERIC_READ), ace(false, SERVICE, 0x1)];

    match barrier(&aces, FILE_GENERIC_READ) {
        Some(Barrier::Denied(by)) => assert_eq!(by, SERVICE),
        other => panic!("{other:?}"),
    }
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

#[test]
fn an_existing_log_needs_the_right_to_read_its_attributes_which_opening_it_uses() {
    let without = ace(true, SERVICE, (FILE_GENERIC_WRITE | DELETE) & !FILE_READ_ATTRIBUTES);
    let with = ace(true, SERVICE, FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES);

    let found = barrier(&[without], LOG.0);

    assert!(matches!(found, Some(Barrier::NotAllowed)), "{found:?}");
    assert!(barrier(&[with], LOG.0).is_none());
}

#[test]
fn creator_owner_allow_that_files_inherit_counts_for_the_files_the_service_makes() {
    let creator_owner = |object_inherit| Ace {
        object_inherit,
        inherit_only: true,
        ..ace(true, CREATOR_OWNER, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
    };
    let add_files = ace(true, SERVICE, FILE_ADD_FILE);
    let files_get = FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE;

    let inherited = barrier_of(&[creator_owner(true), add_files], &who(), FILE_ADD_FILE, files_get);
    let not_inherited = barrier_of(
        &[creator_owner(false), ace(true, SERVICE, FILE_ADD_FILE)],
        &who(),
        FILE_ADD_FILE,
        files_get,
    );
    let for_the_directory = barrier_of(&[creator_owner(true)], &who(), FILE_ADD_FILE, 0);

    assert!(inherited.is_none(), "{inherited:?}");
    assert!(
        matches!(not_inherited, Some(Barrier::NotInherited)),
        "{not_inherited:?}"
    );
    assert!(
        matches!(for_the_directory, Some(Barrier::NotAllowed)),
        "{for_the_directory:?}"
    );
}

#[test]
fn a_directory_with_no_dacl_is_refused_for_what_its_files_get() {
    // `aces_of` reports a missing DACL as full access for Everyone, which no file inherits.
    let no_dacl = ace(true, EVERYONE, FILE_ALL_ACCESS);

    let found = barrier_of(&[no_dacl], &who(), FILE_ADD_FILE, FILE_GENERIC_WRITE);

    assert!(matches!(found, Some(Barrier::NotInherited)), "{found:?}");
}
