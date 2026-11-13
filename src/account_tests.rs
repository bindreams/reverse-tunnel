use super::*;

/// The SID `sc showsid TrustedInstaller` prints, the best known of the per-service SIDs.
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

#[test]
fn the_sid_of_a_service_is_the_hash_of_its_upper_cased_name() {
    assert_eq!(Account::of_service("TrustedInstaller").sid(), TRUSTED_INSTALLER);
    // Windows upper-cases the name first: a name in another case is the same account.
    assert_eq!(Account::of_service("trustedinstaller").sid(), TRUSTED_INSTALLER);
}

#[test]
fn ensure_takes_the_service_from_the_account_name() {
    assert_eq!(ensure(r"NT SERVICE\TrustedInstaller").unwrap().sid(), TRUSTED_INSTALLER);
    assert!(
        ensure("TrustedInstaller").is_err(),
        "a name outside NT SERVICE is not a virtual account"
    );
}

#[test]
fn the_binary_sid_of_a_service_is_the_one_its_text_spells() {
    let known = crate::security::Sid::parse(TRUSTED_INSTALLER).unwrap();

    assert!(Account::of_service("TrustedInstaller").to_sid() == known);
}
