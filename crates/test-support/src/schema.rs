//! The JSON Schemas published under `docs/`, and checks of real command output with them.
//!
//! Every `format` keyword is asserted, and a schema that names a format the validator doesn't know fails to build instead of passing unchecked.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::fail;

/// The schema of the `command/v2` envelope that wraps every JSON result.
pub const ENVELOPE_SCHEMA: &str = "command-envelope.schema.json";

/// The `schema` identifier of each command result, and the published schema that describes it.
pub const RESULT_SCHEMAS: [(&str, &str); 9] = [
    ("plan/v3", "release-plan.schema.json"),
    ("candidate/v1", "candidate.schema.json"),
    ("verify/v1", "candidate-verification.schema.json"),
    ("status/v1", "candidate-status.schema.json"),
    ("release/v1", "release-report.schema.json"),
    ("release-pr-intent/v1", "release-pr-intent.schema.json"),
    ("doctor/v1", "doctor-report.schema.json"),
    ("init/v1", "init-outcome.schema.json"),
    ("completion/v1", "completion.schema.json"),
];

/// The published schema that describes the result `identifier` names.
#[must_use]
pub fn result_schema(identifier: &str) -> Option<&'static str> {
    RESULT_SCHEMAS
        .iter()
        .find(|(known, _)| *known == identifier)
        .map(|(_, file)| *file)
}

/// The directory that holds the published schemas.
#[must_use]
pub fn schema_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

/// The text of the published schema at `path`.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support reads files in this one place, which names the path in its failure"
)]
fn read_schema(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| fail(format_args!("cannot read {}: {error}", path.display())))
}

/// Every published schema, keyed by its file name.
///
/// # Panics
///
/// When the directory can't be listed or a schema can't be read or parsed.
#[must_use]
pub fn published_schemas() -> BTreeMap<String, Value> {
    let directory = schema_directory();
    std::fs::read_dir(&directory)
        .unwrap_or_else(|error| fail(format_args!("cannot list {}: {error}", directory.display())))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| {
                    fail(format_args!("cannot list {}: {error}", directory.display()))
                })
                .path()
        })
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_owned();
            name.ends_with(".schema.json").then_some((name, path))
        })
        .map(|(name, path)| {
            let schema = serde_json::from_str(&read_schema(&path)).unwrap_or_else(|error| {
                fail(format_args!("{} is not JSON: {error}", path.display()))
            });
            (name, schema)
        })
        .collect()
}

/// Panic unless `envelope` matches the `command/v2` schema and its result matches the schema its own `schema` field names.
pub fn assert_published_envelope(envelope: &Value) {
    assert_matches(ENVELOPE_SCHEMA, envelope);
    if !envelope["result"].is_null() {
        assert_published_result(&envelope["result"]);
    }
}

/// Panic unless `result` matches the published schema its `schema` field names.
///
/// # Panics
///
/// When `result` names no published schema or the schema rejects it.
pub fn assert_published_result(result: &Value) {
    let identifier = result["schema"].as_str().unwrap_or_else(|| {
        fail(format_args!(
            "a command result names no schema: {}",
            excerpt(result)
        ))
    });
    let file = result_schema(identifier)
        .unwrap_or_else(|| fail(format_args!("no published schema describes `{identifier}`")));
    assert_matches(file, result);
}

/// Panic unless `value` matches the published schema `file`.
///
/// # Panics
///
/// When the schema rejects `value`, or `file` isn't a valid published schema.
pub fn assert_matches(file: &str, value: &Value) {
    let violations = violations(file, value);
    assert!(
        violations.is_empty(),
        "docs/{file} rejects {}:\n{}",
        excerpt(value),
        violations.join("\n")
    );
}

/// Characters of a rejected value that a failure message shows.
const EXCERPT_CHARACTERS: usize = 2_000;

/// The start of `value`, short enough that a failure message stays readable.
fn excerpt(value: &Value) -> String {
    let text = value.to_string();
    let mut characters = text.chars();
    let start = characters
        .by_ref()
        .take(EXCERPT_CHARACTERS)
        .collect::<String>();
    if characters.next().is_some() {
        format!("{start}…")
    } else {
        start
    }
}

/// Every reason the published schema `file` rejects `value`, which is empty when the value matches.
///
/// # Panics
///
/// When `file` isn't a published schema, or a published schema isn't a valid one.
#[must_use]
pub fn violations(file: &str, value: &Value) -> Vec<String> {
    let schemas = published_schemas();
    let id = schemas
        .get(file)
        .unwrap_or_else(|| fail(format_args!("docs/{file} is not a published schema")))
        .get("$id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail(format_args!("docs/{file} has no `$id`")))
        .to_owned();
    // Every schema joins one registry under its `$id`, so a reference to another published schema resolves without a network.
    let registry = schemas
        .into_iter()
        .fold(jsonschema::Registry::new(), |registry, (name, schema)| {
            let schema_id = schema
                .get("$id")
                .and_then(Value::as_str)
                .unwrap_or_else(|| fail(format_args!("docs/{name} has no `$id`")))
                .to_owned();
            registry.add(&schema_id, schema).unwrap_or_else(|error| {
                fail(format_args!("docs/{name} has an invalid `$id`: {error}"))
            })
        })
        .prepare()
        .unwrap_or_else(|error| fail(format_args!("the published schemas don't resolve: {error}")));
    let validator = jsonschema::options()
        .with_registry(&registry)
        .offline()
        .should_validate_formats(true)
        .should_ignore_unknown_formats(false)
        .build(&serde_json::json!({ "$ref": id }))
        .unwrap_or_else(|error| fail(format_args!("docs/{file} is not a valid schema: {error}")));
    validator
        .iter_errors(value)
        .map(|error| format!("at `{}`: {error}", error.instance_path()))
        .collect()
}
