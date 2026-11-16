//! Changelog rendering and the structured notes that feed it.
//!
//! Rendering is idempotent, so the rolling Release PR can be regenerated on every push without producing a new diff each time.

use std::collections::BTreeSet;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use serde::Deserialize;

use crate::failure::{Refusal, RefusalReason};
use crate::fs;
use crate::git::conventional_bump;
use crate::model::{Bump, ChangeEntry};
use crate::refuse;
use crate::units::KIB;

/// Structured note files one package may carry at once.
const MAX_NOTE_FILES: usize = 1_000;

/// Size one structured note file may reach.
const MAX_NOTE_BYTES: u64 = 64 * KIB;

/// Characters a structured note id may use.
const MAX_NOTE_ID_LEN: usize = 128;

/// Characters a structured note line may use.
const MAX_NOTE_TEXT_LEN: usize = 1_000;

const PREAMBLE: &str = "# Changelog\n\nAll notable changes to this project will be documented in this file.\n\nThe format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),\nand this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).\n\n## [Unreleased]\n";

/// A `.github/release.yml` file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReleaseNotesFile {
    /// The `changelog` section of the file.
    #[serde(default)]
    pub changelog: ReleaseNotesConfig,
}

/// GitHub's release-notes configuration, as far as it is honoured.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReleaseNotesConfig {
    /// Entries to leave out.
    #[serde(default)]
    pub exclude: Exclude,
    /// Categories, in the order they should appear.
    #[serde(default)]
    pub categories: Vec<Category>,
}

/// Which entries never reach the notes.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Exclude {
    /// Labels that exclude an entry.
    #[serde(default)]
    pub labels: BTreeSet<String>,
    /// Authors whose entries are excluded, such as bots.
    #[serde(default)]
    pub authors: BTreeSet<String>,
}

/// One section of the generated notes.
#[derive(Debug, Clone, Deserialize)]
pub struct Category {
    /// Section heading.
    pub title: String,
    /// Labels that place an entry in this section.
    #[serde(default)]
    pub labels: BTreeSet<String>,
}

/// A Keep a Changelog section, which a structured note names in lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteCategory {
    /// New features.
    Added,
    /// Changes in existing behavior.
    Changed,
    /// Features that a later release removes.
    Deprecated,
    /// Bug fixes.
    Fixed,
    /// Removed features.
    Removed,
    /// Fixed vulnerabilities.
    Security,
}

impl NoteCategory {
    /// The section heading.
    pub fn title(self) -> &'static str {
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

/// One structured note fragment, as its TOML file states it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredNote {
    /// The id, which is also the stem of the file's name.
    pub id: String,
    /// The section that the note belongs in.
    pub category: NoteCategory,
    /// The single line of the note.
    pub text: String,
    /// The pull request that the note describes, when it names one.
    #[serde(default)]
    pub pull_request: Option<u64>,
}

impl ReleaseNotesConfig {
    /// Read the configuration, falling back to defaults when no regular file is at the path.
    pub fn load(path: &Path) -> Result<Self> {
        if fs::kind(path)? != fs::Kind::File {
            return Ok(Self::default());
        }
        let source = fs::read_to_string(path)?;
        Self::parse(&source)
            .with_context(|| format!("invalid release notes config `{}`", path.display()))
    }

    /// Read the `changelog` section of the text of a `.github/release.yml` file.
    pub fn parse(source: &str) -> Result<Self> {
        Ok(serde_norway::from_str::<ReleaseNotesFile>(source)?.changelog)
    }

    /// Apply exclusions and categories to a set of entries.
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
                let category = self
                    .categories
                    .iter()
                    .find(|category| {
                        !category.labels.contains("*")
                            && entry
                                .labels
                                .iter()
                                .any(|label| category.labels.contains(label))
                    })
                    .or_else(|| {
                        self.categories
                            .iter()
                            .find(|category| category.labels.contains("*"))
                    });
                if let Some(category) = category {
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

/// The text of the changelog at `path`, or `None` when the package has none.
///
/// A changelog that is there but can't be read is refused, so its releases are never rendered or sealed as if it were missing.
pub(crate) fn read_if_present(path: &Path) -> Result<Option<String>> {
    fs::read_to_string_if_present(path).with_context(|| {
        Refusal::new(
            RefusalReason::ChangelogUnreadable,
            format!("the changelog `{}` can't be read", path.display()),
        )
    })
}

/// Read the structured note fragments that have not been released yet.
pub fn load_structured_notes(
    package_root: &Path,
    notes_directory: &Path,
    existing_changelog: Option<&str>,
) -> Result<Vec<ChangeEntry>> {
    let directory = package_root.join(notes_directory);
    if fs::kind(&directory)? == fs::Kind::Absent {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.file_type().is_dir() {
        refuse!(
            ChangelogNotesLayoutInvalid,
            "structured changelog notes path is not a directory"
        );
    }
    let mut paths = fs::read_dir(&directory)?
        .into_iter()
        .map(|entry| entry.path().to_path_buf())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect::<Vec<_>>();
    paths.sort();
    if paths.len() > MAX_NOTE_FILES {
        refuse!(
            ChangelogNotesLayoutInvalid,
            "structured changelog notes exceed the {MAX_NOTE_FILES} file limit"
        );
    }
    let released = released_note_ids(existing_changelog);
    let mut ids = BTreeSet::new();
    let mut entries = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_NOTE_BYTES {
            refuse!(
                ChangelogNotesLayoutInvalid,
                "structured changelog note must be a regular file under {} KiB",
                MAX_NOTE_BYTES / KIB
            );
        }
        let source = fs::read_to_string(&path)
            .with_context(|| format!("failed to read structured note `{}`", path.display()))?;
        let note = parse_structured_note(&path, &source)?;
        if !ids.insert(note.id.clone()) {
            anyhow::bail!("duplicate structured changelog note id `{}`", note.id);
        }
        if released.contains(note.id.as_str()) {
            continue;
        }
        let marker = format!("<!-- release-glz-note:{} -->", note.id);
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

/// Merge note fragments into the collected entries.
///
/// A fragment that names a pull request already present is dropped, so a change is described once rather than twice.
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

/// Collect the note ids a changelog already records.
///
/// Reading the changelog once and looking each note up costs `O(changelog + notes * log notes)`; searching the whole changelog for every note costs `O(changelog * notes)`, and a package may carry up to a thousand pending notes.
fn released_note_ids(changelog: Option<&str>) -> BTreeSet<&str> {
    const PREFIX: &str = "<!-- release-glz-note:";
    const SUFFIX: &str = " -->";

    let mut ids = BTreeSet::new();
    let Some(changelog) = changelog else {
        return ids;
    };
    let mut rest = changelog;
    while let Some((_, marker)) = rest.split_once(PREFIX) {
        let Some((id, after)) = marker.split_once(SUFFIX) else {
            break;
        };
        ids.insert(id);
        rest = after;
    }
    ids
}

/// Read the text of the structured note file at `path`, whose name the note's id has to match.
///
/// Text that isn't a note's TOML is refused, and a note whose id, text, or pull request breaks its rule is refused with [`crate::failure::RefusalReason::ChangelogNoteInvalid`].
pub fn parse_structured_note(path: &Path, source: &str) -> Result<StructuredNote> {
    let note: StructuredNote = toml_edit::de::from_str(source)
        .with_context(|| format!("invalid structured note `{}`", path.display()))?;
    validate_note(&note, path)?;
    Ok(note)
}

fn validate_note(note: &StructuredNote, path: &Path) -> Result<()> {
    let valid_id = !note.id.is_empty()
        && note.id.len() <= MAX_NOTE_ID_LEN
        && note.id.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' => true,
            b'0'..=b'9' | b'-' | b'_' => index > 0,
            _ => false,
        });
    if !valid_id || path.file_stem().and_then(|stem| stem.to_str()) != Some(note.id.as_str()) {
        refuse!(
            ChangelogNoteInvalid,
            "structured changelog note id must be safe and match its filename"
        );
    }
    if note.text.is_empty()
        || note.text.len() > MAX_NOTE_TEXT_LEN
        || note.text.trim() != note.text
        || note.text.contains(['\n', '\r', '\0'])
    {
        refuse!(
            ChangelogNoteInvalid,
            "structured changelog note text must be one non-empty trimmed line"
        );
    }
    if note.pull_request == Some(0) {
        refuse!(
            ChangelogNoteInvalid,
            "structured changelog note pull_request must be positive"
        );
    }
    Ok(())
}

/// Render a changelog with one version's section inserted.
///
/// Repeating the rendering on its result produces the same bytes, so the Release PR can be updated in place.
pub fn render(existing: Option<&str>, version: &str, entries: &[ChangeEntry]) -> String {
    let mut changelog = existing.unwrap_or(PREAMBLE).to_owned();
    if !changelog.contains("## [Unreleased]") {
        let rest = changelog.trim_start_matches("# Changelog").trim_start();
        changelog = format!("{PREAMBLE}\n{rest}");
    }

    if let Some(range) = release_section_range(&changelog, version) {
        let date = changelog
            .get(range.clone())
            .and_then(|section| release_section_date(section, version))
            .unwrap_or_else(|| Utc::now().date_naive());
        let section = render_section_on(version, entries, date);
        changelog.replace_range(range, section.trim_end());
        if !changelog.ends_with('\n') {
            changelog.push('\n');
        }
        return changelog;
    }

    let section = render_section(version, entries);
    let marker = "## [Unreleased]";
    let insertion = changelog
        .split_once(marker)
        .and_then(|(before, after)| {
            after
                .find('\n')
                .map(|offset| before.len() + marker.len() + offset + 1)
        })
        .unwrap_or(changelog.len());
    changelog.insert_str(insertion, &format!("\n{section}"));
    changelog
}

/// Render the section for one version, dated today.
pub fn render_section(version: &str, entries: &[ChangeEntry]) -> String {
    render_section_on(version, entries, Utc::now().date_naive())
}

fn render_section_on(version: &str, entries: &[ChangeEntry], date: NaiveDate) -> String {
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

/// The date that the heading of `version`'s section records, or `None` when it records none, so rendering dates the section anew.
#[expect(
    clippy::disallowed_methods,
    reason = "a heading whose date doesn't parse records no date, and rendering replaces it"
)]
fn release_section_date(section: &str, version: &str) -> Option<NaiveDate> {
    let prefix = format!("## [{version}] - ");
    let raw = section.lines().next()?.strip_prefix(&prefix)?;
    NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()
}

/// Extract the section for one version, if the changelog has it.
pub fn release_section(changelog: &str, version: &str) -> Option<String> {
    let range = release_section_range(changelog, version)?;
    Some(changelog.get(range)?.trim().to_owned())
}

/// Remove only the section currently being regenerated.
/// Structured-note markers in older releases still suppress duplicates, while markers in the target section must remain inputs so repeated updates are byte-idempotent.
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
    let (before, after) = changelog.split_once(&heading)?;
    let body = after.find("\n## [").unwrap_or(after.len());
    let start = before.len();
    Some(start..start + heading.len() + body)
}

/// The section a Conventional Commit message belongs in by default, from the release step that the core assigns to its subject and body.
pub fn default_category(subject: &str, body: &str) -> NoteCategory {
    category_of(conventional_bump(subject, body))
}

/// The section for a change that asks for the release step `bump`.
pub const fn category_of(bump: Bump) -> NoteCategory {
    match bump {
        Bump::Major => NoteCategory::Removed,
        Bump::Minor => NoteCategory::Added,
        Bump::Patch => NoteCategory::Fixed,
        Bump::None => NoteCategory::Changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::{RefusalReason, refusal_reason};
    use release_glz_test_support::fs;

    /// The reason and message of the refusal that loading the notes under `notes` of `package_root` ends in.
    fn notes_refusal(package_root: &Path, notes: &str) -> (Option<RefusalReason>, String) {
        let error = load_structured_notes(package_root, Path::new(notes), None).unwrap_err();
        (refusal_reason(&error), error.to_string())
    }

    /// A refusal of the notes directory with `message`.
    fn layout(message: &str) -> (Option<RefusalReason>, String) {
        (
            Some(RefusalReason::ChangelogNotesLayoutInvalid),
            message.to_owned(),
        )
    }

    /// A refusal of one note with `message`.
    fn note(message: &str) -> (Option<RefusalReason>, String) {
        (
            Some(RefusalReason::ChangelogNoteInvalid),
            message.to_owned(),
        )
    }

    const NOTE_TEXT: &str = "structured changelog note text must be one non-empty trimmed line";
    const NOTE_FILE: &str = "structured changelog note must be a regular file under 64 KiB";

    #[test]
    fn released_ids_agree_with_searching_for_each_marker() {
        let changelog = concat!(
            "## [1.0.0] - 2026-01-01\n",
            "- shipped <!-- release-glz-note:alpha -->\n",
            "- also shipped <!-- release-glz-note:beta-2 -->\n",
        );
        let ids = released_note_ids(Some(changelog));
        for id in ["alpha", "beta-2", "gamma", "alph", "alphaa"] {
            let marker = format!("<!-- release-glz-note:{id} -->");
            assert_eq!(
                ids.contains(id),
                changelog.contains(&marker),
                "id `{id}` disagrees with a direct search"
            );
        }
        assert!(released_note_ids(None).is_empty());
        assert!(released_note_ids(Some("<!-- release-glz-note:unterminated")).is_empty());
    }

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
        let config: ReleaseNotesFile = serde_norway::from_str(
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
        fs::create_dir_all(&notes);
        fs::write(
            notes.join("duplicate-pr.toml"),
            "id = \"duplicate-pr\"\ncategory = \"fixed\"\ntext = \"duplicate PR note\"\npull_request = 42\n",
        );
        fs::write(
            notes.join("security-hardening.toml"),
            "id = \"security-hardening\"\ncategory = \"security\"\ntext = \"Harden archive validation\"\n",
        );
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
        );
        assert_eq!(
            notes_refusal(temp.path(), ".release-glz/notes"),
            note(NOTE_TEXT)
        );
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
        let invalid = temp.path().join("invalid.yml");
        fs::write(&invalid, "changelog: [");
        let error = ReleaseNotesConfig::load(&invalid).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("invalid release notes config `{}`", invalid.display())
        );
        assert!(
            error.downcast_ref::<serde_norway::Error>().is_some(),
            "{error:#}"
        );

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
        fs::write(temp.path().join("release.yml"), source);
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

        fs::write(
            temp.path().join("wildcard-first.yml"),
            r#"changelog:
  categories:
    - title: Everything else
      labels: ["*"]
    - title: Security
      labels: [security]
"#,
        );
        let wildcard_first =
            ReleaseNotesConfig::load(&temp.path().join("wildcard-first.yml")).unwrap();
        let categorized = wildcard_first.apply([entry(None, &["security"], "security")]);
        assert_eq!(categorized[0].category, "Security");
    }

    #[test]
    fn rerendering_an_existing_release_preserves_its_original_date() {
        let existing =
            "# Changelog\n\n## [Unreleased]\n\n## [1.2.3] - 2024-02-29\n\n### Fixed\n\n- old\n";
        let entries = [ChangeEntry {
            title: "replacement".into(),
            pull_request: None,
            author: None,
            url: None,
            labels: vec![],
            category: "Fixed".into(),
        }];

        let rendered = render(Some(existing), "1.2.3", &entries);

        assert!(rendered.contains("## [1.2.3] - 2024-02-29"));
        assert_eq!(render(Some(&rendered), "1.2.3", &entries), rendered);
    }

    #[test]
    fn structured_note_directory_file_and_count_limits_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("notes");
        fs::write(&path, "not a directory");
        assert_eq!(
            notes_refusal(temp.path(), "notes"),
            layout("structured changelog notes path is not a directory")
        );

        fs::remove_file(&path);
        fs::create_dir(&path);
        fs::write(path.join("large.toml"), vec![b'x'; 64 * 1024 + 1]);
        assert_eq!(notes_refusal(temp.path(), "notes"), layout(NOTE_FILE));

        fs::remove_file(path.join("large.toml"));
        for index in 0..=1_000 {
            fs::write(path.join(format!("{index}.toml")), "");
        }
        assert_eq!(
            notes_refusal(temp.path(), "notes"),
            layout("structured changelog notes exceed the 1000 file limit")
        );
    }

    #[cfg(unix)]
    #[test]
    fn structured_notes_reject_symlinks_and_validate_each_identity_and_text_boundary() {
        use std::os::unix::fs::symlink;

        let id = "structured changelog note id must be safe and match its filename";
        for (filename, source, message) in [
            (
                "0numeric.toml",
                "id = \"0numeric\"\ncategory = \"added\"\ntext = \"text\"\n",
                id,
            ),
            (
                "bad name.toml",
                "id = \"bad name\"\ncategory = \"changed\"\ntext = \"text\"\n",
                id,
            ),
            (
                "mismatch.toml",
                "id = \"other\"\ncategory = \"fixed\"\ntext = \"text\"\n",
                id,
            ),
            (
                "empty.toml",
                "id = \"empty\"\ncategory = \"removed\"\ntext = \"\"\n",
                NOTE_TEXT,
            ),
            (
                "spaced.toml",
                "id = \"spaced\"\ncategory = \"deprecated\"\ntext = \" text \"\n",
                NOTE_TEXT,
            ),
            (
                "long.toml",
                &format!(
                    "id = \"long\"\ncategory = \"security\"\ntext = \"{}\"\n",
                    "x".repeat(1_001)
                ),
                NOTE_TEXT,
            ),
            (
                "zero-pr.toml",
                "id = \"zero-pr\"\ncategory = \"fixed\"\ntext = \"text\"\npull_request = 0\n",
                "structured changelog note pull_request must be positive",
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let notes = temp.path().join("notes");
            fs::create_dir(&notes);
            fs::write(notes.join(filename), source);
            assert_eq!(
                notes_refusal(temp.path(), "notes"),
                note(message),
                "{filename}"
            );
        }

        let temp = tempfile::tempdir().unwrap();
        let notes = temp.path().join("notes");
        fs::create_dir(&notes);
        fs::write(
            notes.join("target.toml"),
            "id = \"target\"\ncategory = \"fixed\"\ntext = \"text\"\n",
        );
        symlink("target.toml", notes.join("linked.toml")).unwrap();
        assert_eq!(notes_refusal(temp.path(), "notes"), layout(NOTE_FILE));
    }

    #[test]
    fn every_note_category_marker_and_render_shape_is_stable() {
        let temp = tempfile::tempdir().unwrap();
        let notes = temp.path().join("notes");
        fs::create_dir(&notes);
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
            );
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

        let without_unreleased = render(Some("# Old\n\nearlier notes\n"), "2.0.0", &entries);
        assert!(without_unreleased.contains("## [Unreleased]"));
        assert!(without_unreleased.contains("earlier notes"));
        assert!(release_section(&without_unreleased, "missing").is_none());
        assert_eq!(
            without_release_section(&without_unreleased, "missing"),
            without_unreleased
        );
        assert!(!without_release_section(&without_unreleased, "2.0.0").contains("with number"));
    }

    #[test]
    fn the_default_category_follows_the_release_step_of_the_core() {
        let footer = "details\n\nBREAKING CHANGE: y";
        let disagreements = [
            ("feat: x", "", Bump::Minor, NoteCategory::Added),
            ("Feat: add", "", Bump::Minor, NoteCategory::Added),
            ("FEAT: x", "", Bump::Minor, NoteCategory::Added),
            ("feat(a!b): x", "", Bump::Minor, NoteCategory::Added),
            ("fix: x", "", Bump::Patch, NoteCategory::Fixed),
            ("FIX: bug", "", Bump::Patch, NoteCategory::Fixed),
            ("perf: x", "", Bump::Patch, NoteCategory::Fixed),
            ("Perf(core): fast", "", Bump::Patch, NoteCategory::Fixed),
            ("feat!: x", "", Bump::Major, NoteCategory::Removed),
            ("feat(scope)!: x", "", Bump::Major, NoteCategory::Removed),
            ("feat: x", footer, Bump::Major, NoteCategory::Removed),
            ("feature: x", "", Bump::None, NoteCategory::Changed),
            ("chore: x", "", Bump::None, NoteCategory::Changed),
            ("update the docs", "", Bump::None, NoteCategory::Changed),
            ("", "", Bump::None, NoteCategory::Changed),
        ]
        .into_iter()
        .filter(|&(subject, body, bump, category)| {
            conventional_bump(subject, body) != bump || default_category(subject, body) != category
        })
        .map(|(subject, body, ..)| (subject, body, default_category(subject, body)))
        .collect::<Vec<_>>();
        assert_eq!(disagreements, []);
    }
}
