//! Properties of the readers of structured changelog note files and of the `changelog` section of `.github/release.yml`.
//!
//! An accepted note has an id that is safe and names its file, one trimmed line of text within its limit, and no zero pull request, and its rendering reads back as the same note.
//! A refused note names the reason of an invalid note, or the text isn't a note's TOML.
//! An accepted release notes configuration excludes and places entries exactly as an independent statement of GitHub's rules does.

use std::path::{Path, PathBuf};

use release_glz::changelog::{ReleaseNotesConfig, StructuredNote, parse_structured_note};
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::model::ChangeEntry;
use toml_edit::DocumentMut;

const NOTES_DIRECTORY: &str = ".changelog";
const FALLBACK_ID: &str = "note";
const MAX_ID_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 1_000;
const WILDCARD: &str = "*";

/// A reader that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Note,
    ReleaseNotesConfig,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    [
        (note(text), Reached::Note),
        (release_notes_config(text), Reached::ReleaseNotesConfig),
    ]
    .into_iter()
    .filter_map(|(accepted, reader)| accepted.then_some(reader))
    .collect()
}

fn note_path(id: &str) -> PathBuf {
    Path::new(NOTES_DIRECTORY).join(format!("{id}.toml"))
}

/// The id that the text states, which names the file it is read from so that a valid note can be accepted.
///
/// Text that isn't TOML, or states no id that can name a file, is read from the fallback file.
fn stated_id(text: &str) -> String {
    let stated = match text.parse::<DocumentMut>() {
        Ok(document) => document
            .get("id")
            .and_then(|id| id.as_str())
            .map(str::to_owned),
        Err(_) => None,
    };
    stated
        .filter(|id| !id.contains(['/', '\\', '\0']) && !id.is_empty())
        .unwrap_or_else(|| FALLBACK_ID.to_owned())
}

/// Whether `id` is 1 to 128 ASCII letters, digits, `-`, and `_` that start with a letter.
fn safe_id(id: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&id.len())
        && id
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

fn note(text: &str) -> bool {
    let id = stated_id(text);
    let path = note_path(&id);
    let note = match parse_structured_note(&path, text) {
        Ok(note) => note,
        Err(error) => {
            match refusal_reason(&error) {
                Some(reason) => {
                    assert_eq!(reason, RefusalReason::ChangelogNoteInvalid, "{error:#}")
                }
                None => {
                    assert_eq!(
                        error.to_string(),
                        format!("invalid structured note `{}`", path.display())
                    );
                    assert!(toml_edit::de::from_str::<StructuredNote>(text).is_err());
                }
            }
            return false;
        }
    };
    assert!(safe_id(&note.id), "{note:?}");
    assert_eq!(note.id, id);
    assert!((1..=MAX_TEXT_BYTES).contains(&note.text.len()), "{note:?}");
    assert_eq!(note.text.trim(), note.text);
    assert!(!note.text.contains(['\n', '\r', '\0']), "{note:?}");
    assert_ne!(note.pull_request, Some(0));
    let other = note_path(&format!("{id}-renamed"));
    let error =
        parse_structured_note(&other, text).expect_err("a note names the file it is read from");
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::ChangelogNoteInvalid),
        "{error:#}"
    );
    assert_eq!(
        parse_structured_note(&path, &render_note(&note)).expect("a rendered note reads back"),
        note
    );
    true
}

fn render_note(note: &StructuredNote) -> String {
    let mut document = DocumentMut::new();
    document["id"] = toml_edit::value(note.id.as_str());
    document["category"] = toml_edit::value(note.category.title().to_ascii_lowercase());
    document["text"] = toml_edit::value(note.text.as_str());
    if let Some(pull_request) = note.pull_request {
        document["pull_request"] = toml_edit::value(
            i64::try_from(pull_request).expect("a rendered pull request fits in i64"),
        );
    }
    document.to_string()
}

fn release_notes_config(text: &str) -> bool {
    let config = match ReleaseNotesConfig::parse(text) {
        Ok(config) => config,
        Err(error) => {
            assert_eq!(refusal_reason(&error), None, "{error:#}");
            return false;
        }
    };
    let entries = entries_for(&config);
    let applied = config.apply(entries.clone());
    assert_eq!(applied, expected_application(&config, entries));
    true
}

fn entry(title: &str, author: Option<&str>, labels: &[&str]) -> ChangeEntry {
    ChangeEntry {
        title: title.to_owned(),
        pull_request: None,
        author: author.map(str::to_owned),
        url: None,
        labels: labels.iter().map(|label| (*label).to_owned()).collect(),
        category: "Changed".to_owned(),
    }
}

/// Entries that meet every rule of `config`: one for each label and author it names, and some that it names nowhere.
fn entries_for(config: &ReleaseNotesConfig) -> Vec<ChangeEntry> {
    let mut entries = vec![
        entry("unlabeled", None, &[]),
        entry("by a person", Some("alice"), &["bug"]),
        entry("two labels", Some("bob"), &["enhancement", "security"]),
    ];
    for label in config.exclude.labels.iter().chain(
        config
            .categories
            .iter()
            .flat_map(|category| &category.labels),
    ) {
        entries.push(entry(&format!("labeled {label}"), None, &[label.as_str()]));
    }
    for author in &config.exclude.authors {
        entries.push(entry(&format!("by {author}"), Some(author.as_str()), &[]));
    }
    entries
}

/// What applying `config` to `entries` yields by GitHub's rules, stated without the reader's code.
///
/// An entry whose author or one of whose labels is excluded is dropped.
/// A kept entry takes the title of the first category without the wildcard that shares a label with it, or else of the first category with the wildcard.
/// With categories, kept entries keep their order within the order of their categories, and an entry in no category comes last.
fn expected_application(
    config: &ReleaseNotesConfig,
    entries: Vec<ChangeEntry>,
) -> Vec<ChangeEntry> {
    let mut kept: Vec<ChangeEntry> = entries
        .into_iter()
        .filter(|entry| {
            entry
                .author
                .as_ref()
                .is_none_or(|author| !config.exclude.authors.contains(author))
                && entry
                    .labels
                    .iter()
                    .all(|label| !config.exclude.labels.contains(label))
        })
        .collect();
    for entry in &mut kept {
        let labeled = config.categories.iter().find(|category| {
            !category.labels.contains(WILDCARD)
                && entry
                    .labels
                    .iter()
                    .any(|label| category.labels.contains(label))
        });
        let wildcard = config
            .categories
            .iter()
            .find(|category| category.labels.contains(WILDCARD));
        if let Some(category) = labeled.or(wildcard) {
            entry.category.clone_from(&category.title);
        }
    }
    if config.categories.is_empty() {
        return kept;
    }
    let rank = |entry: &ChangeEntry| {
        config
            .categories
            .iter()
            .position(|category| category.title == entry.category)
            .unwrap_or(usize::MAX)
    };
    let mut ranked: Vec<(usize, usize, ChangeEntry)> = kept
        .into_iter()
        .enumerate()
        .map(|(order, entry)| (rank(&entry), order, entry))
        .collect();
    ranked.sort_by_key(|(rank, order, _)| (*rank, *order));
    ranked.into_iter().map(|(_, _, entry)| entry).collect()
}
