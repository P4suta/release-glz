use std::fs;

use release_glz::changelog::load_structured_notes;
use release_glz::config::Manifest;
use release_glz::migrate::Migration;

fn schema_two_manifest() -> &'static str {
    r#"name = "widget"
version = "1.0.0"

[repository]
type = "github"
user = "owner"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.12.0"

[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]
"#
}

#[test]
fn legacy_configuration_is_mapped_to_schema_two_and_preserved_byte_for_byte() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    let legacy = r#"# keep this comment
name = "widget"
version = "0.4.0"

[repository]
type = "github"
user = "owner"
repo = "widget"

[tools.release-glz]
changelog_path = "NEWS.md"
release_branch_prefix = "ship/"
allow_version_zero = true
custom_legacy_key = "preserve me"

[tools.release-glz.baseline_refs]
"0.3.0" = "v0.3.0"
"#;
    fs::write(&path, legacy).unwrap();

    let migration = Migration::prepare(&path).unwrap();
    assert!(migration.changed());
    assert_eq!(migration.legacy_source(), Some(legacy));
    let migrated = Manifest::parse(path.clone(), migration.rendered().to_owned()).unwrap();
    assert_eq!(migrated.release.schema, 2);
    assert_eq!(migrated.release.changelog.path.to_string_lossy(), "NEWS.md");
    assert_eq!(migrated.release.release_branch_prefix, "ship/");
    assert!(migrated.release.allow_version_zero);
    assert_eq!(
        migrated.release.baseline_refs.values().next().unwrap(),
        "v0.3.0"
    );

    let outcome = migration.apply().unwrap();
    assert!(outcome.written);
    assert_eq!(
        fs::read_to_string(temp.path().join(".release-glz/legacy-gleam.toml")).unwrap(),
        legacy
    );
    assert_eq!(Manifest::load(&path).unwrap().release.schema, 2);
}

#[test]
fn migration_never_replaces_a_different_legacy_backup() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    fs::write(&path, "name = \"x\"\nversion = \"1.0.0\"\n").unwrap();
    fs::create_dir_all(temp.path().join(".release-glz")).unwrap();
    fs::write(
        temp.path().join(".release-glz/legacy-gleam.toml"),
        "different",
    )
    .unwrap();
    let error = Migration::prepare(&path).unwrap().apply().unwrap_err();
    assert!(error.to_string().contains("legacy backup"));
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "name = \"x\"\nversion = \"1.0.0\"\n"
    );
}

#[test]
fn legacy_unreleased_text_is_preserved_as_a_structured_note() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    fs::write(
        &path,
        "name = \"widget\"\nversion = \"0.4.0\"\n\n[tools.release-glz]\nchangelog_path = \"CHANGELOG.md\"\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("CHANGELOG.md"),
        "# Changelog\n\n## [Unreleased]\n\n### Changed\n\n- Preserve this historical note.\n\n## [0.3.0]\n\n- Old.\n",
    )
    .unwrap();

    Migration::prepare(&path).unwrap().apply().unwrap();
    let note = fs::read_to_string(
        temp.path()
            .join(".release-glz/notes/legacy-unreleased.toml"),
    )
    .unwrap();
    assert!(note.contains("id = \"legacy-unreleased\""));
    assert!(note.contains("text = \"Preserve this historical note.\""));
    assert!(note.contains("category = \"changed\""));
}

#[test]
fn large_legacy_unreleased_sections_are_losslessly_split_into_valid_notes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    fs::write(
        &path,
        "name = \"widget\"\nversion = \"0.4.0\"\n\n[tools.release-glz]\nchangelog_path = \"CHANGELOG.md\"\n",
    )
    .unwrap();
    let expected = (1..=24)
        .map(|index| format!("Historical change {index:02}: {}", "x".repeat(80)))
        .collect::<Vec<_>>();
    let mut changelog = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n".to_owned();
    for line in &expected[..12] {
        changelog.push_str(&format!("- {line}\n"));
    }
    changelog.push_str("\n### Fixed\n\n");
    for line in &expected[12..] {
        changelog.push_str(&format!("- {line}\n"));
    }
    changelog.push_str("\n## [0.3.0]\n\n- Old.\n");
    fs::write(temp.path().join("CHANGELOG.md"), &changelog).unwrap();

    Migration::prepare(&path).unwrap().apply().unwrap();

    assert_eq!(
        fs::read_to_string(temp.path().join("CHANGELOG.md")).unwrap(),
        changelog
    );
    let notes = load_structured_notes(
        temp.path(),
        std::path::Path::new(".release-glz/notes"),
        None,
    )
    .unwrap();
    assert_eq!(notes.len(), expected.len());
    for (index, (entry, original)) in notes.iter().zip(&expected).enumerate() {
        assert!(entry.title.starts_with(original), "{}", entry.title);
        assert_eq!(entry.category, if index < 12 { "Added" } else { "Fixed" });
    }
}

#[test]
fn schema_two_migration_is_a_complete_non_mutating_noop() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    fs::write(&path, schema_two_manifest()).unwrap();

    let migration = Migration::prepare(&path).unwrap();
    assert!(!migration.changed());
    assert_eq!(migration.rendered(), schema_two_manifest());
    assert_eq!(migration.legacy_source(), None);
    assert_eq!(migration.diff(), None);
    let preview = migration.outcome(false);
    assert!(!preview.changed);
    assert!(!preview.written);
    assert_eq!(preview.legacy_backup_path, None);

    let outcome = migration.apply().unwrap();
    assert!(!outcome.changed);
    assert!(!outcome.written);
    assert_eq!(fs::read_to_string(&path).unwrap(), schema_two_manifest());
    assert!(!temp.path().join(".release-glz").exists());
}

#[test]
fn migration_refuses_a_manifest_changed_after_prepare_without_side_effects() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    let legacy = "name = \"widget\"\nversion = \"0.4.0\"\n";
    fs::write(&path, legacy).unwrap();
    let migration = Migration::prepare(&path).unwrap();
    let changed = legacy.replace("0.4.0", "0.4.1");
    fs::write(&path, &changed).unwrap();

    let error = migration.apply().unwrap_err().to_string();
    assert!(error.contains("manifest changed after migration was prepared"));
    assert_eq!(fs::read_to_string(&path).unwrap(), changed);
    assert!(!temp.path().join(".release-glz").exists());
}

#[test]
fn migration_resumes_over_identical_backup_and_note_but_never_replaces_a_note() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    let legacy = "name = \"widget\"\nversion = \"0.4.0\"\n";
    let changelog = "# Changelog\n\n## [Unreleased]\n\n### Security\n\n- Preserve this note.\n";
    fs::write(&path, legacy).unwrap();
    fs::write(temp.path().join("CHANGELOG.md"), changelog).unwrap();
    Migration::prepare(&path).unwrap().apply().unwrap();

    let backup_path = temp.path().join(".release-glz/legacy-gleam.toml");
    let note_path = temp
        .path()
        .join(".release-glz/notes/legacy-unreleased.toml");
    let backup = fs::read_to_string(&backup_path).unwrap();
    let note = fs::read_to_string(&note_path).unwrap();
    fs::write(&path, legacy).unwrap();

    let resumed = Migration::prepare(&path).unwrap().apply().unwrap();
    assert!(resumed.written);
    assert_eq!(fs::read_to_string(&backup_path).unwrap(), backup);
    assert_eq!(fs::read_to_string(&note_path).unwrap(), note);

    fs::write(&path, legacy).unwrap();
    fs::write(&note_path, "different\n").unwrap();
    let error = Migration::prepare(&path)
        .unwrap()
        .apply()
        .unwrap_err()
        .to_string();
    assert!(error.contains("legacy Unreleased note"), "{error}");
    assert_eq!(fs::read_to_string(&path).unwrap(), legacy);
    assert_eq!(fs::read_to_string(&backup_path).unwrap(), backup);
    assert_eq!(fs::read_to_string(&note_path).unwrap(), "different\n");
}

#[test]
fn legacy_changelog_categories_empty_lines_and_missing_markers_are_lossless() {
    let headings = [
        ("Added", "added"),
        ("Deprecated", "deprecated"),
        ("Fixed", "fixed"),
        ("Removed", "removed"),
        ("Security", "security"),
        ("Unknown", "changed"),
    ];
    for (heading, category) in headings {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gleam.toml");
        fs::write(&path, "name = \"widget\"\nversion = \"0.4.0\"\n").unwrap();
        fs::write(
            temp.path().join("CHANGELOG.md"),
            format!(
                "# Changelog\n\n## [Unreleased]\n\n### {heading}\n\n- \n- kept\nnot a bullet\n"
            ),
        )
        .unwrap();
        Migration::prepare(&path).unwrap().apply().unwrap();
        let note = fs::read_to_string(
            temp.path()
                .join(".release-glz/notes/legacy-unreleased.toml"),
        )
        .unwrap();
        assert!(
            note.contains(&format!("category = \"{category}\"")),
            "{note}"
        );
        assert!(note.contains("text = \"kept\""), "{note}");
    }

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    let legacy = "name = \"widget\"\nversion = \"0.4.0\"\n";
    fs::write(&path, legacy).unwrap();
    fs::write(temp.path().join("CHANGELOG.md"), "# Changelog\n").unwrap();
    Migration::prepare(&path).unwrap().apply().unwrap();
    assert!(!temp.path().join(".release-glz/notes").exists());
}

#[test]
fn migration_propagates_non_missing_changelog_read_failures() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("gleam.toml");
    fs::write(&path, "name = \"widget\"\nversion = \"0.4.0\"\n").unwrap();
    fs::create_dir(temp.path().join("CHANGELOG.md")).unwrap();

    assert!(Migration::prepare(&path).is_err());
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "name = \"widget\"\nversion = \"0.4.0\"\n"
    );
    assert!(!temp.path().join(".release-glz").exists());
}
