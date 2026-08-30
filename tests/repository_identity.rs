const REPOSITORY: &str = "P4suta/release-glz";

#[test]
fn every_project_owned_identity_points_at_the_published_repository() {
    let exact_repository_files = [
        ("Cargo.toml", include_str!("../Cargo.toml")),
        ("workflow.rs", include_str!("../src/workflow.rs")),
        ("Action wrapper", include_str!("../action/index.js")),
        ("candidate provenance", include_str!("../src/candidate.rs")),
        (
            "distribution provenance",
            include_str!("../scripts/generate-provenance.js"),
        ),
    ];
    for (name, contents) in exact_repository_files {
        assert!(
            contents.contains(REPOSITORY),
            "{name} does not identify {REPOSITORY}"
        );
        assert!(
            !contents.contains("gleam-releases/release-glz"),
            "{name} still identifies the nonexistent planned repository"
        );
    }

    for (name, schema) in [
        (
            "release plan schema",
            include_str!("../docs/release-plan.schema.json"),
        ),
        (
            "command envelope schema",
            include_str!("../docs/command-envelope.schema.json"),
        ),
        (
            "candidate schema",
            include_str!("../docs/candidate.schema.json"),
        ),
        ("hook schema", include_str!("../docs/hook.schema.json")),
        (
            "release state schema",
            include_str!("../docs/release-state.schema.json"),
        ),
    ] {
        assert!(
            schema.contains("raw.githubusercontent.com/P4suta/release-glz/v1.0.0/"),
            "{name} is not bound to the immutable v1 repository tag"
        );
        assert!(!schema.contains("p4suta.github.io/release-glz"), "{name}");
        assert!(!schema.contains("gleam-releases.github.io"), "{name}");
    }
}
