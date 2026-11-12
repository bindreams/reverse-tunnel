//! The release workflow builds what `upgrade` asks for.

use reverse_tunnel::download::{RELEASE_TARGETS, asset_name};
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
    // The file the job copies and uploads is the one the matrix names: the copy's destination and the upload's path
    // both come from `matrix.asset`.
    let steps = build["steps"].as_sequence().expect("jobs.build.steps is a list");
    let copy = steps
        .iter()
        .find(|step| step["name"].as_str() == Some("Build"))
        .expect("a build step named Build");
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
}
