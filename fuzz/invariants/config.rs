//! Properties of the `gleam.toml` parser and of the edits release-glz makes to a manifest.
//!
//! An edit must change only the value it names, and initialization must only append configuration.
//! Rendering may regroup interleaved dotted keys, respace their key segments, and end an unterminated final line, as `toml_edit` does.
//! It never adds or drops a line or changes a line beyond its whitespace.
//! Clearing a channel may drop a release table that it leaves empty, but it never creates release configuration.

use std::path::PathBuf;

use release_glz::config::{InitializationSettings, Manifest, RegistryConfig};
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
        assert_eq!(reparsed.release, manifest.release);
    }
    for channel in CHANNELS {
        let mut edited = manifest.clone();
        edited.set_prerelease(channel);
        assert_eq!(edited.release.prerelease, channel);
        let rendered = edited.render();
        let reparsed = reparse(&rendered);
        assert_eq!(reparsed.release, edited.release);
        let expected = with_prerelease(original.clone(), channel);
        if channel.is_some() {
            assert_eq!(toml_data(&rendered), expected, "{rendered}");
        } else {
            assert_eq!(
                without_empty_release_table(toml_data(&rendered)),
                without_empty_release_table(expected),
                "{rendered}"
            );
            assert!(
                manifest.has_release_config() || !reparsed.has_release_config(),
                "clearing a channel created release configuration\n{rendered}"
            );
        }
    }
    if initialized(&manifest, source, &original) {
        vec![Reached::Parsed, Reached::Initialized]
    } else {
        vec![Reached::Parsed]
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

/// The data after selecting a channel, which creates the release table only for a channel.
fn with_prerelease(mut data: Value, channel: Option<PrereleaseChannel>) -> Value {
    match channel {
        Some(channel) => {
            data[TOOLS][RELEASE_TABLE][PRERELEASE] = Value::String(channel.as_str().to_owned());
        }
        None => {
            if let Some(release) = data
                .get_mut(TOOLS)
                .and_then(|tools| tools.get_mut(RELEASE_TABLE))
                .and_then(Value::as_object_mut)
            {
                release.remove(PRERELEASE);
            }
        }
    }
    data
}

/// The data without an empty release table, which configures nothing.
///
/// `toml_edit` drops a dotted table whose last key is removed, while a table with a header stays.
fn without_empty_release_table(mut data: Value) -> Value {
    let Some(tools) = data.get_mut(TOOLS).and_then(Value::as_object_mut) else {
        return data;
    };
    if tools
        .get(RELEASE_TABLE)
        .and_then(Value::as_object)
        .is_some_and(serde_json::Map::is_empty)
    {
        tools.remove(RELEASE_TABLE);
    }
    if tools.is_empty() {
        data.as_object_mut()
            .expect("a manifest is a table")
            .remove(TOOLS);
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
    if manifest.has_release_config() {
        return false;
    }
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
    assert!(tools.remove(RELEASE_TABLE).is_some());
    if tools.is_empty() && original.get(TOOLS).is_none() {
        appended
            .as_object_mut()
            .expect("a manifest is a table")
            .remove(TOOLS);
    }
    assert_eq!(&appended, original);
    let reparsed = reparse(&rendered);
    assert!(reparsed.has_release_config());
    assert_eq!(reparsed.release.schema, 2);
    assert_eq!(reparsed.release.compiler, INITIALIZED_COMPILER);
    assert_eq!(
        reparsed.release.approval.manual_refs,
        [format!("refs/heads/{DEFAULT_BRANCH}")]
    );
    true
}
