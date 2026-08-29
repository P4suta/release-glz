use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Deserialize;

use crate::model::ChangeEntry;

const PREAMBLE: &str = "# Changelog\n\nAll notable changes to this project will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),\nand this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n\n## [Unreleased]\n";

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReleaseNotesFile {
    #[serde(default)]
    pub changelog: ReleaseNotesConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReleaseNotesConfig {
    #[serde(default)]
    pub exclude: Exclude,
    #[serde(default)]
    pub categories: Vec<Category>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Exclude {
    #[serde(default)]
    pub labels: BTreeSet<String>,
    #[serde(default)]
    pub authors: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Category {
    pub title: String,
    #[serde(default)]
    pub labels: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NoteCategory {
    Added,
    Changed,
    Deprecated,
    Fixed,
    Removed,
    Security,
}

impl NoteCategory {
    fn title(self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Changed => "Changed",
            Self::Deprecated => "Deprecated",
            Self::Fixed => "Fixed",
            Self::Removed => "Removed",
            Self::Security => "Security",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredNote {
    id: String,
    category: NoteCategory,
    text: String,
    #[serde(default)]
    pull_request: Option<u64>,
}

impl ReleaseNotesConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Ok(Self::default());
        }
        let source = fs::read_to_string(path)?;
        Ok(serde_yaml::from_str::<ReleaseNotesFile>(&source)
            .with_context(|| format!("invalid release notes config `{}`", path.display()))?
            .changelog)
    }

    pub fn apply(&self, entries: impl IntoIterator<Item = ChangeEntry>) -> Vec<ChangeEntry> {
        let mut entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| {
                !entry
                    .author
                    .as_ref()
                    .is_some_and(|author| self.exclude.authors.contains(author))
                    && !entry
                        .labels
                        .iter()
                        .any(|label| self.exclude.labels.contains(label))
            })
            .map(|mut entry| {
                if let Some(category) = self.categories.iter().find(|category| {
                    category.labels.contains("*")
                        || entry
                            .labels
                            .iter()
                            .any(|label| category.labels.contains(label))
                }) {
                    entry.category.clone_from(&category.title);
                }
                entry
            })
            .collect();
        if !self.categories.is_empty() {
            entries.sort_by_key(|entry| {
                self.categories
                    .iter()
                    .position(|category| category.title == entry.category)
                    .unwrap_or(usize::MAX)
            });
        }
        entries
    }
}

pub fn load_structured_notes(
    package_root: &Path,
    notes_directory: &Path,
    existing_changelog: Option<&str>,
) -> Result<Vec<ChangeEntry>> {
    let directory = package_root.join(notes_directory);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.file_type().is_dir() {
        anyhow::bail!("structured changelog notes path is not a directory");
    }
    let mut paths = fs::read_dir(&directory)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.len() > 1_000 {
        anyhow::bail!("structured changelog notes exceed the 1000 file limit");
    }
    let mut ids = BTreeSet::new();
    let mut entries = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
            anyhow::bail!("structured changelog note must be a regular file under 64 KiB");
        }
        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read structured note `{}`", path.display()))?;
        let note: StructuredNote = toml_edit::de::from_str(&source)
            .with_context(|| format!("invalid structured note `{}`", path.display()))?;
        validate_note(&note, &path)?;
        if !ids.insert(note.id.clone()) {
            anyhow::bail!("duplicate structured changelog note id `{}`", note.id);
        }
        let marker = format!("<!-- release-glz-note:{} -->", note.id);
        if existing_changelog.is_some_and(|existing| existing.contains(&marker)) {
            continue;
        }
        entries.push(ChangeEntry {
            title: format!("{} {marker}", note.text),
            pull_request: note.pull_request,
            author: None,
            url: None,
            labels: vec![],
            category: note.category.title().into(),
        });
    }
    Ok(entries)
}

pub fn merge_supplemental_notes(
    mut entries: Vec<ChangeEntry>,
    notes: Vec<ChangeEntry>,
) -> Vec<ChangeEntry> {
    let mut pull_requests = entries
        .iter()
        .filter_map(|entry| entry.pull_request)
        .collect::<BTreeSet<_>>();
    for note in notes {
        if note
            .pull_request
            .is_some_and(|number| !pull_requests.insert(number))
        {
            continue;
        }
        entries.push(note);
    }
    entries
}

fn validate_note(note: &StructuredNote, path: &Path) -> Result<()> {
    let valid_id = !note.id.is_empty()
        && note.id.len() <= 128
        && note.id.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' => true,
            b'0'..=b'9' | b'-' | b'_' => index > 0,
            _ => false,
        });
    if !valid_id || path.file_stem().and_then(|stem| stem.to_str()) != Some(note.id.as_str()) {
        anyhow::bail!("structured changelog note id must be safe and match its filename");
    }
    if note.text.is_empty()
        || note.text.len() > 1_000
        || note.text.trim() != note.text
        || note.text.contains(['\n', '\r', '\0'])
    {
        anyhow::bail!("structured changelog note text must be one non-empty trimmed line");
    }
    if note.pull_request == Some(0) {
        anyhow::bail!("structured changelog note pull_request must be positive");
    }
    Ok(())
}

pub fn render(existing: Option<&str>, version: &str, entries: &[ChangeEntry]) -> String {
    let mut changelog = existing.unwrap_or(PREAMBLE).to_owned();
    if !changelog.contains("## [Unreleased]") {
        let rest = changelog.trim_start_matches("# Changelog").trim_start();
        changelog = format!("{PREAMBLE}\n{rest}");
    }

    let section = render_section(version, entries);
    if let Some(range) = release_section_range(&changelog, version) {
        changelog.replace_range(range, section.trim_end());
        if !changelog.ends_with('\n') {
            changelog.push('\n');
        }
        return changelog;
    }

    let marker = "## [Unreleased]";
    let insertion = changelog
        .find(marker)
        .map(|index| {
            changelog[index..]
                .find('\n')
                .map(|offset| index + offset + 1)
                .unwrap_or(changelog.len())
        })
        .unwrap_or(changelog.len());
    changelog.insert_str(insertion, &format!("\n{section}"));
    changelog
}

pub fn render_section(version: &str, entries: &[ChangeEntry]) -> String {
    let date = Utc::now().date_naive();
    let mut groups: Vec<(&str, Vec<&ChangeEntry>)> = Vec::new();
    for entry in entries {
        if let Some((_, entries)) = groups
            .iter_mut()
            .find(|(category, _)| *category == entry.category)
        {
            entries.push(entry);
        } else {
            groups.push((&entry.category, vec![entry]));
        }
    }
    let mut output = format!("## [{version}] - {date}\n");
    if entries.is_empty() {
        output.push_str("\n### Changed\n\n- Release prepared by release-glz.\n");
        return output;
    }
    for (category, entries) in groups {
        output.push_str(&format!("\n### {category}\n\n"));
        for entry in entries {
            output.push_str("- ");
            output.push_str(&entry.title);
            if let (Some(number), Some(url)) = (entry.pull_request, &entry.url) {
                output.push_str(&format!(" ([#{number}]({url}))"));
            } else if let Some(number) = entry.pull_request {
                output.push_str(&format!(" (#{number})"));
            }
            if let Some(author) = &entry.author {
                output.push_str(&format!(" by @{author}"));
            }
            output.push('\n');
        }
    }
    output
}

pub fn release_section(changelog: &str, version: &str) -> Option<String> {
    let range = release_section_range(changelog, version)?;
    Some(changelog[range].trim().to_owned())
}

/// Remove only the section currently being regenerated. Structured-note
/// markers in older releases still suppress duplicates, while markers in the
/// target section must remain inputs so repeated updates are byte-idempotent.
pub fn without_release_section(changelog: &str, version: &str) -> String {
    let Some(range) = release_section_range(changelog, version) else {
        return changelog.to_owned();
    };
    let mut output = changelog.to_owned();
    output.replace_range(range, "");
    output
}

fn release_section_range(changelog: &str, version: &str) -> Option<Range<usize>> {
    let heading = format!("## [{version}]");
    let start = changelog.find(&heading)?;
    let end = changelog[start + heading.len()..]
        .find("\n## [")
        .map(|offset| start + heading.len() + offset)
        .unwrap_or(changelog.len());
    Some(start..end)
}

pub fn default_category(title: &str) -> String {
    let kind = title.split(':').next().unwrap_or_default();
    if kind.contains('!') {
        "Removed"
    } else if kind.starts_with("feat") {
        "Added"
    } else if kind.starts_with("fix") || kind.starts_with("perf") {
        "Fixed"
    } else {
        "Changed"
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_and_replaces_keep_a_changelog_section() {
        let entries = vec![ChangeEntry {
            title: "feat: ship it".into(),
            pull_request: Some(42),
            author: Some("octo".into()),
            url: Some("https://example.test/42".into()),
            labels: vec![],
            category: "Added".into(),
        }];
        let once = render(None, "1.2.0", &entries);
        let twice = render(Some(&once), "1.2.0", &entries);
        assert_eq!(once, twice);
        assert!(once.contains("### Added"));
        assert!(once.contains("[#42](https://example.test/42)"));
        assert!(release_section(&once, "1.2.0").is_some());
    }

    #[test]
    fn github_release_yaml_excludes_and_categorizes() {
        let config: ReleaseNotesFile = serde_yaml::from_str(
            "changelog:\n  exclude:\n    labels: [skip]\n  categories:\n    - title: Security\n      labels: [security]\n",
        )
        .unwrap();
        let make = |labels: Vec<&str>| ChangeEntry {
            title: "change".into(),
            pull_request: None,
            author: None,
            url: None,
            labels: labels.into_iter().map(str::to_owned).collect(),
            category: "Changed".into(),
        };
        let entries = config
            .changelog
            .apply([make(vec!["skip"]), make(vec!["security"])]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].category, "Security");
    }

    #[test]
    fn structured_notes_are_strict_single_line_and_deduplicated_by_pr_and_id() {
        let temp = tempfile::tempdir().unwrap();
        let notes = temp.path().join(".release-glz/notes");
        fs::create_dir_all(&notes).unwrap();
        fs::write(
            notes.join("duplicate-pr.toml"),
            "id = \"duplicate-pr\"\ncategory = \"fixed\"\ntext = \"duplicate PR note\"\npull_request = 42\n",
        )
        .unwrap();
        fs::write(
            notes.join("security-hardening.toml"),
            "id = \"security-hardening\"\ncategory = \"security\"\ntext = \"Harden archive validation\"\n",
        )
        .unwrap();
        let loaded = load_structured_notes(
            temp.path(),
            Path::new(".release-glz/notes"),
            Some("<!-- release-glz-note:already-used -->"),
        )
        .unwrap();
        let merged = merge_supplemental_notes(
            vec![ChangeEntry {
                title: "fix: existing PR".into(),
                pull_request: Some(42),
                author: None,
                url: None,
                labels: vec![],
                category: "Fixed".into(),
            }],
            loaded,
        );
        assert_eq!(merged.len(), 2);
        assert!(merged[1].title.contains("Harden archive validation"));
        assert!(
            merged[1]
                .title
                .contains("release-glz-note:security-hardening")
        );

        fs::write(
            notes.join("multiline.toml"),
            "id = \"multiline\"\ncategory = \"changed\"\ntext = \"first\\nsecond\"\n",
        )
        .unwrap();
        assert!(load_structured_notes(temp.path(), Path::new(".release-glz/notes"), None).is_err());
    }

    #[test]
    fn release_note_config_missing_invalid_exclusions_wildcards_and_sorting_are_explicit() {
        let temp = tempfile::tempdir().unwrap();
        assert!(
            ReleaseNotesConfig::load(&temp.path().join("missing.yml"))
                .unwrap()
                .categories
                .is_empty()
        );
        fs::write(temp.path().join("invalid.yml"), "changelog: [").unwrap();
        assert!(ReleaseNotesConfig::load(&temp.path().join("invalid.yml")).is_err());

        let source = r#"changelog:
  exclude:
    labels: [skip]
    authors: [bot]
  categories:
    - title: Security
      labels: [security]
    - title: Everything else
      labels: ["*"]
"#;
        fs::write(temp.path().join("release.yml"), source).unwrap();
        let config = ReleaseNotesConfig::load(&temp.path().join("release.yml")).unwrap();
        let entry = |author: Option<&str>, labels: &[&str], title: &str| ChangeEntry {
            title: title.into(),
            pull_request: None,
            author: author.map(str::to_owned),
            url: None,
            labels: labels.iter().map(|label| (*label).into()).collect(),
            category: "Changed".into(),
        };
        let entries = config.apply([
            entry(Some("bot"), &[], "excluded author"),
            entry(None, &["skip"], "excluded label"),
            entry(None, &[], "wildcard"),
            entry(None, &["security"], "security"),
        ]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "security");
        assert_eq!(entries[0].category, "Security");
        assert_eq!(entries[1].category, "Everything else");

        let no_categories = ReleaseNotesConfig::default();
        assert_eq!(
            no_categories.apply([entry(None, &[], "unchanged")])[0].category,
            "Changed"
        );
    }

    #[test]
    fn structured_note_directory_file_and_count_limits_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("notes");
        fs::write(&path, "not a directory").unwrap();
        assert!(load_structured_notes(temp.path(), Path::new("notes"), None).is_err());

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("large.toml"), vec![b'x'; 64 * 1024 + 1]).unwrap();
        assert!(load_structured_notes(temp.path(), Path::new("notes"), None).is_err());

        fs::remove_file(path.join("large.toml")).unwrap();
        for index in 0..=1_000 {
            fs::write(path.join(format!("{index}.toml")), "").unwrap();
        }
        let error = load_structured_notes(temp.path(), Path::new("notes"), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("1000 file limit"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn structured_notes_reject_symlinks_and_validate_each_identity_and_text_boundary() {
        use std::os::unix::fs::symlink;

        for (filename, source) in [
            (
                "0numeric.toml",
                "id = \"0numeric\"\ncategory = \"added\"\ntext = \"text\"\n",
            ),
            (
                "bad name.toml",
                "id = \"bad name\"\ncategory = \"changed\"\ntext = \"text\"\n",
            ),
            (
                "mismatch.toml",
                "id = \"other\"\ncategory = \"fixed\"\ntext = \"text\"\n",
            ),
            (
                "empty.toml",
                "id = \"empty\"\ncategory = \"removed\"\ntext = \"\"\n",
            ),
            (
                "spaced.toml",
                "id = \"spaced\"\ncategory = \"deprecated\"\ntext = \" text \"\n",
            ),
            (
                "long.toml",
                &format!(
                    "id = \"long\"\ncategory = \"security\"\ntext = \"{}\"\n",
                    "x".repeat(1_001)
                ),
            ),
            (
                "zero-pr.toml",
                "id = \"zero-pr\"\ncategory = \"fixed\"\ntext = \"text\"\npull_request = 0\n",
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let notes = temp.path().join("notes");
            fs::create_dir(&notes).unwrap();
            fs::write(notes.join(filename), source).unwrap();
            assert!(
                load_structured_notes(temp.path(), Path::new("notes"), None).is_err(),
                "accepted invalid note {filename}"
            );
        }

        let temp = tempfile::tempdir().unwrap();
        let notes = temp.path().join("notes");
        fs::create_dir(&notes).unwrap();
        fs::write(
            notes.join("target.toml"),
            "id = \"target\"\ncategory = \"fixed\"\ntext = \"text\"\n",
        )
        .unwrap();
        symlink("target.toml", notes.join("linked.toml")).unwrap();
        assert!(load_structured_notes(temp.path(), Path::new("notes"), None).is_err());
    }

    #[test]
    fn every_note_category_marker_and_render_shape_is_stable() {
        let temp = tempfile::tempdir().unwrap();
        let notes = temp.path().join("notes");
        fs::create_dir(&notes).unwrap();
        for category in [
            "added",
            "changed",
            "deprecated",
            "fixed",
            "removed",
            "security",
        ] {
            fs::write(
                notes.join(format!("{category}.toml")),
                format!(
                    "id = \"{category}\"\ncategory = \"{category}\"\ntext = \"{category} note\"\n"
                ),
            )
            .unwrap();
        }
        let loaded = load_structured_notes(
            temp.path(),
            Path::new("notes"),
            Some("<!-- release-glz-note:fixed -->"),
        )
        .unwrap();
        assert_eq!(loaded.len(), 5);
        assert!(!loaded.iter().any(|entry| entry.category == "Fixed"));

        let entries = vec![
            ChangeEntry {
                title: "with number".into(),
                pull_request: Some(7),
                author: None,
                url: None,
                labels: vec![],
                category: "Added".into(),
            },
            ChangeEntry {
                title: "same category".into(),
                pull_request: None,
                author: Some("octo".into()),
                url: None,
                labels: vec![],
                category: "Added".into(),
            },
        ];
        let section = render_section("2.0.0", &entries);
        assert_eq!(section.matches("### Added").count(), 1);
        assert!(section.contains("(#7)"));
        assert!(section.contains("by @octo"));
        let empty = render_section("2.0.1", &[]);
        assert!(empty.contains("Release prepared by release-glz"));

        let without_unreleased = render(Some("# Old\n\nlegacy\n"), "2.0.0", &entries);
        assert!(without_unreleased.contains("## [Unreleased]"));
        assert!(without_unreleased.contains("legacy"));
        assert!(release_section(&without_unreleased, "missing").is_none());
        assert_eq!(
            without_release_section(&without_unreleased, "missing"),
            without_unreleased
        );
        assert!(!without_release_section(&without_unreleased, "2.0.0").contains("with number"));

        for (title, category) in [
            ("feat!: remove", "Removed"),
            ("feat: add", "Added"),
            ("fix: bug", "Fixed"),
            ("perf: fast", "Fixed"),
            ("docs: words", "Changed"),
            ("", "Changed"),
        ] {
            assert_eq!(default_category(title), category);
        }
    }
}
