use super::*;
use crate::security::Descriptor;

fn service() -> Account {
    Account::of_service("reverse-tunnel")
}

const ADMINS: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[test]
fn a_directory_others_may_read_is_read_by_everyone() {
    assert_eq!(Perm::new(0o755).sddl(), format!("{ADMINS}(A;OICI;0x1200a9;;;WD)"));
}

#[test]
fn a_directory_closed_to_others_is_read_only_by_its_group() {
    let sid = service().sid();
    assert_eq!(
        Perm::new(0o750).group(service()).sddl(),
        format!("{ADMINS}(A;OICI;0x1200a9;;;{sid})")
    );
}

#[test]
fn a_directory_its_owner_may_write_is_written_by_that_account() {
    let sid = service().sid();
    assert_eq!(
        Perm::new(0o755).owner(service()).group(service()).sddl(),
        format!("{ADMINS}(A;OICI;0x1200a9;;;WD)(A;OICI;0x1301bf;;;{sid})")
    );
}

#[test]
fn a_directory_no_one_else_may_enter_has_only_administrators() {
    assert_eq!(Perm::new(0o700).sddl(), ADMINS);
}

#[test]
fn every_descriptor_is_one_windows_accepts() {
    for perm in [Perm::new(0o755), Perm::new(0o700), Perm::new(0o750).group(service())] {
        Descriptor::parse(&perm.sddl()).unwrap_or_else(|err| panic!("{}: {err}", perm.sddl()));
    }
    Descriptor::parse(OWNED_BY_ADMINISTRATORS).unwrap();
}
