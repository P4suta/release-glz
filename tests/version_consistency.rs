#[test]
fn cargo_cli_and_action_are_the_v1_release_line() {
    let cargo: toml_edit::DocumentMut = include_str!("../Cargo.toml").parse().unwrap();
    let cargo_version = cargo["package"]["version"].as_str().unwrap();
    let action: serde_json::Value =
        serde_json::from_str(include_str!("../action/package.json")).unwrap();

    assert_eq!(cargo_version, "1.0.0");
    assert_eq!(env!("CARGO_PKG_VERSION"), cargo_version);
    assert_eq!(action["version"], cargo_version);
}
