// `TZ=Europe/Berlin` in a unit's environment must not leave every stamp at `+00:00`.
#[cfg(unix)]
#[test]
fn unix_resolves_iana_zone_names() {
    jiff::tz::db()
        .get("Europe/Berlin")
        .expect("Europe/Berlin is not found: is the system's tzdata installed?");
}
