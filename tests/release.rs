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
    // The name the matrix declares is the name the job copies and uploads.
    let steps = yaml_serde::to_string(&build["steps"]).unwrap();
    assert!(steps.contains("matrix.asset"), "the build steps never use matrix.asset");
}
