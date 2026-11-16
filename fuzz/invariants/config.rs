//! Properties of the `gleam.toml` parser and of the edits release-glz makes to a manifest.
//!
//! A manifest is configured exactly when it holds a `[tools.release-glz]` table, and that table sets `schema = 2`.
//! An edit must change only the value it names, and initialization must only append configuration.
//! Rendering may regroup interleaved dotted keys, respace their key segments, and end an unterminated final line, as `toml_edit` does.
//! It never adds or drops a line or changes a line beyond its whitespace.
//! Only a configured manifest takes a channel, and an unconfigured one keeps its bytes.

use std::path::PathBuf;

use release_glz::config::{InitializationSettings, Manifest, MissingReleaseConfig, RegistryConfig};
use release_glz::model::PrereleaseChannel;
use semver::Version;
use serde_json::Value;
use toml_edit::{DocumentMut, Item};

const MANIFEST: &str = "gleam.toml";
const DEFAULT_BRANCH: &str = "main";
const INITIALIZED_COMPILER: Version = Version::new(1, 19, 2);
const REPLACEMENT_VERSION: &str = "2.0.0-rc.1+build.7";
const TOOLS: &str = "tools";
const RELEASE_TABLE: &str = "release-glz";
const SCHEMA: &str = "schema";
const RELEASE_CONFIG_SCHEMA: i64 = 2;
const PRERELEASE: &str = "prerelease";
const CHANNELS: [Option<PrereleaseChannel>; 4] = [
    None,
    Some(PrereleaseChannel::Alpha),
    Some(PrereleaseChannel::Beta),
    Some(PrereleaseChannel::Rc),
];

/// A manifest operation that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Parsed,
    Configured,
    Initialized,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let Ok(source) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let Ok(manifest) = Manifest::parse(PathBuf::from(MANIFEST), source.to_owned()) else {
        return Vec::new();
    };
    let original = toml_data(source);
    let release_table = original
        .get(TOOLS)
        .and_then(|tools| tools.get(RELEASE_TABLE));
    assert_eq!(
        manifest.release().is_ok(),
        release_table.is_some(),
        "configuration presence differs from the release table\n{source}"
    );
    if let Some(table) = release_table {
        assert_eq!(
            table.get(SCHEMA).and_then(Value::as_i64),
            Some(RELEASE_CONFIG_SCHEMA),
            "a release table without `schema = 2` was accepted\n{source}"
        );
    }
    let rendered = manifest.render();
    assert_eq!(toml_data(&rendered), original);
    assert_same_lines(source, &rendered);
    for version in replacement_versions(&manifest.version) {
        let rendered = manifest.render_with_version(&version);
        let mut expected = original.clone();
        expected["version"] = Value::String(version.to_string());
        assert_eq!(toml_data(&rendered), expected, "{rendered}");
        let reparsed = reparse(&rendered);
        assert_eq!(reparsed.version, version);
        assert_eq!(reparsed.release(), manifest.release());
    }
    let mut reached = vec![Reached::Parsed];
    if manifest.release().is_ok() {
        edit_channels(&manifest, &original);
        reached.push(Reached::Configured);
    } else {
        refuse_channels(&manifest, source);
        if initialized(&manifest, source, &original) {
            reached.push(Reached::Initialized);
        }
    }
    reached
}

/// Selecting or clearing a channel changes only the `prerelease` key of the release table.
fn edit_channels(manifest: &Manifest, original: &Value) {
    for channel in CHANNELS {
        let mut edited = manifest.clone();
        edited
            .set_prerelease(channel)
            .expect("a configured manifest takes a channel");
        assert_eq!(edited.release().unwrap().prerelease, channel);
        let rendered = edited.render();
        assert_eq!(
            toml_data(&rendered),
            with_prerelease(original.clone(), channel),
            "{rendered}"
        );
        assert_eq!(reparse(&rendered).release(), edited.release());
    }
}

/// An unconfigured manifest refuses every channel and keeps its bytes.
fn refuse_channels(manifest: &Manifest, source: &str) {
    for channel in CHANNELS {
        let mut edited = manifest.clone();
        assert_eq!(edited.set_prerelease(channel), Err(MissingReleaseConfig));
        assert_eq!(edited.render(), manifest.render(), "{source}");
    }
}

/// The values a TOML document holds, without its formatting.
fn toml_data(text: &str) -> Value {
    toml_edit::de::from_str(text)
        .unwrap_or_else(|error| panic!("a rendered manifest isn't valid TOML: {error}\n{text}"))
}

/// The lines of a document without their whitespace, in sorted order.
fn line_contents(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .lines()
        .map(|line| line.split_whitespace().collect())
        .collect();
    lines.sort_unstable();
    lines
}

fn assert_same_lines(source: &str, rendered: &str) {
    assert_eq!(
        line_contents(rendered),
        line_contents(source),
        "rendering rewrote an unedited manifest\n--- source\n{source:?}\n--- rendered\n{rendered:?}"
    );
}

/// The data of a configured manifest after selecting or clearing a channel.
fn with_prerelease(mut data: Value, channel: Option<PrereleaseChannel>) -> Value {
    let release = data[TOOLS][RELEASE_TABLE]
        .as_object_mut()
        .expect("a configured manifest has a release table");
    match channel {
        Some(channel) => {
            release.insert(
                PRERELEASE.to_owned(),
                Value::String(channel.as_str().to_owned()),
            );
        }
        None => {
            release.remove(PRERELEASE);
        }
    }
    data
}

fn replacement_versions(current: &Version) -> Vec<Version> {
    let mut versions = vec![
        current.clone(),
        REPLACEMENT_VERSION
            .parse()
            .expect("the replacement version is valid"),
    ];
    if let Some(patch) = current.patch.checked_add(1) {
        versions.push(Version::new(current.major, current.minor, patch));
    }
    versions
}

fn reparse(rendered: &str) -> Manifest {
    Manifest::parse(PathBuf::from(MANIFEST), rendered.to_owned()).unwrap_or_else(|error| {
        panic!("an edited manifest no longer parses: {error:#}\n{rendered}")
    })
}

/// Initialization refuses only an inline or non-table `tools` value, which it documents.
fn tools_accept_a_new_table(source: &str) -> bool {
    let document = source
        .parse::<DocumentMut>()
        .expect("a parsed manifest is valid TOML");
    matches!(document.get(TOOLS), None | Some(Item::Table(_)))
}

fn initialized(manifest: &Manifest, source: &str, original: &Value) -> bool {
    let settings = InitializationSettings {
        compiler: INITIALIZED_COMPILER,
        default_branch: DEFAULT_BRANCH.to_owned(),
        registry: RegistryConfig::default(),
        allow_version_zero: true,
    };
    let rendered = match manifest.render_initialized(&settings) {
        Ok(rendered) => rendered,
        Err(error) => {
            assert!(
                !tools_accept_a_new_table(source),
                "initialization refused an unconfigured manifest: {error:#}\n{source}"
            );
            return false;
        }
    };
    assert!(rendered.starts_with(source.trim_end()));
    let mut appended = toml_data(&rendered);
    let tools = appended[TOOLS]
        .as_object_mut()
        .expect("initialization writes a tools table");
    let release_table = tools
        .remove(RELEASE_TABLE)
        .expect("initialization writes a release table");
    assert_eq!(release_table[SCHEMA], Value::from(RELEASE_CONFIG_SCHEMA));
    if tools.is_empty() && original.get(TOOLS).is_none() {
        appended
            .as_object_mut()
            .expect("a manifest is a table")
            .remove(TOOLS);
    }
    assert_eq!(&appended, original);
    let reparsed = reparse(&rendered);
    let release = reparsed
        .release()
        .expect("an initialized manifest is configured");
    assert_eq!(release.compiler, INITIALIZED_COMPILER);
    assert_eq!(
        release.approval.manual_refs,
        [format!("refs/heads/{DEFAULT_BRANCH}")]
    );
    true
}
