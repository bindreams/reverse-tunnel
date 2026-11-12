//! The release workflow builds what `upgrade` asks for.

use reverse_tunnel::download::{RELEASE_TARGETS, SUMS_FILE, asset_name};
use yaml_serde::Value;

const DRAFT_RELEASE: &str = include_str!("../.github/workflows/draft-release.yaml");

#[test]
fn draft_release_builds_every_release_target_under_the_name_upgrade_asks_for() {
    let workflow: Value = yaml_serde::from_str(DRAFT_RELEASE).unwrap();
    let build = &workflow["jobs"]["build"];
    let include = build["strategy"]["matrix"]["include"]
        .as_sequence()
        .expect("jobs.build.strategy.matrix.include is a list");

    let mut targets: Vec<&str> = include.iter().map(|entry| entry["target"].as_str().unwrap()).collect();
    targets.sort();
    let mut want = RELEASE_TARGETS.to_vec();
    want.sort();
    assert_eq!(targets, want, "the build matrix and RELEASE_TARGETS differ");

    for entry in include {
        let target = entry["target"].as_str().unwrap();
        assert_eq!(entry["asset"].as_str().unwrap(), asset_name(target), "{target}");
    }
    // The file the job copies and uploads is the one the matrix names.
    let steps = build["steps"].as_sequence().expect("jobs.build.steps is a list");
    let copy = named(steps, "Build");
    assert_eq!(
        copy["env"]["ASSET"].as_str(),
        Some("${{ matrix.asset }}"),
        "ASSET is not matrix.asset"
    );
    assert!(
        copy["run"]
            .as_str()
            .unwrap()
            .contains(r#"cp "target/$TARGET/release/$bin" "dist/$ASSET""#),
        "the build copies to something other than dist/$ASSET"
    );
    let upload = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
        })
        .expect("an upload-artifact step");
    assert_eq!(
        upload["with"]["path"].as_str(),
        Some("dist/${{ matrix.asset }}"),
        "the upload path"
    );

    // The release job writes the checksums over the assets and uploads them with the binaries.
    let release = workflow["jobs"]["release"]["steps"]
        .as_sequence()
        .expect("jobs.release.steps is a list");
    let sums = named(release, "Write SHA256SUMS");
    assert_eq!(
        sums["working-directory"].as_str(),
        Some("dist"),
        "{SUMS_FILE} is not written beside the assets"
    );
    assert!(
        sums["run"]
            .as_str()
            .unwrap()
            .contains(&format!("sha256sum reverse-tunnel-* | tee {SUMS_FILE}")),
        "the release job does not write {SUMS_FILE} over the assets"
    );
    assert!(
        named(release, "Create draft release pinned to commit SHA")["run"]
            .as_str()
            .unwrap()
            .contains(r#"gh release create "$TAG" dist/*"#),
        "the release does not upload dist/*, where {SUMS_FILE} is written"
    );
}

fn named<'a>(steps: &'a [Value], name: &str) -> &'a Value {
    steps
        .iter()
        .find(|step| step["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("a step named {name}"))
}
