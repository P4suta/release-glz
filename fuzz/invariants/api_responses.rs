//! Properties of the readers of registry and GitHub API responses.
//!
//! An accepted response keeps every value that an independent reading of its JSON finds, and its rendering reads back as the same value.
//! The readers accept members they don't know, so the independent reading skips every member that they skip, even one holding a number beyond `f64`.
//! A registry refusal names the typed reason of its response, and a GitHub refusal is one of the two documented errors of a page.
//! An input is read as a registry package response, a registry release response, a page of GitHub Releases, and a page of GitHub pull requests.

use std::cmp::Ordering;
use std::fmt;

use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::forge::{
    GitHubRelease, GitHubReleaseAsset, PullRequest, parse_pull_request_page, parse_release_page,
};
use release_glz::registry::{
    HexRelease, PackageState, RegistryRelease, parse_package_response, parse_release_response,
};
use semver::Version;
use serde::Deserialize;
use serde::de::{DeserializeSeed, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value, json};

/// What the independent reading keeps of a JSON value.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// The whole value, which the typed reader reads whole too.
    Whole,
    /// The named members of an object, each with its own shape, which skips every other member as the typed reader does.
    ///
    /// Serde also reads a struct from a list of its members by position, which this reading keeps as an empty list that no comparison reads.
    Object(&'static [(&'static str, Shape)]),
    /// Each item of a list.
    List(&'static Shape),
}

const WHOLE: Shape = Shape::Whole;
const REGISTRY_ENTRY: Shape = Shape::Object(&[("version", WHOLE), ("has_docs", WHOLE)]);
const PACKAGE: Shape = Shape::Object(&[
    ("releases", Shape::List(&REGISTRY_ENTRY)),
    ("retirements", WHOLE),
]);
const RELEASE: Shape = Shape::Object(&[
    ("version", WHOLE),
    ("checksum", WHOLE),
    ("has_docs", WHOLE),
    ("retirement", WHOLE),
]);
const ASSET: Shape = Shape::Object(&[
    ("id", WHOLE),
    ("name", WHOLE),
    ("state", WHOLE),
    ("content_type", WHOLE),
    ("size", WHOLE),
    ("digest", WHOLE),
]);
const GITHUB_RELEASE: Shape = Shape::Object(&[
    ("id", WHOLE),
    ("html_url", WHOLE),
    ("tag_name", WHOLE),
    ("target_commitish", WHOLE),
    ("body", WHOLE),
    ("draft", WHOLE),
    ("upload_url", WHOLE),
    ("assets", Shape::List(&ASSET)),
]);
const REPOSITORY: Shape = Shape::Object(&[("full_name", WHOLE), ("default_branch", WHOLE)]);
const USER: Shape = Shape::Object(&[("login", WHOLE)]);
const LABEL: Shape = Shape::Object(&[("name", WHOLE)]);
const PULL_REQUEST: Shape = Shape::Object(&[
    ("number", WHOLE),
    ("title", WHOLE),
    ("body", WHOLE),
    ("html_url", WHOLE),
    ("merge_commit_sha", WHOLE),
    ("merged_at", WHOLE),
    ("user", USER),
    ("labels", Shape::List(&LABEL)),
    (
        "head",
        Shape::Object(&[("ref", WHOLE), ("sha", WHOLE), ("repo", REPOSITORY)]),
    ),
    (
        "base",
        Shape::Object(&[("ref", WHOLE), ("repo", REPOSITORY)]),
    ),
]);
const NOTHING: Shape = Shape::Object(&[]);

impl<'de> DeserializeSeed<'de> for Shape {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        match self {
            Self::Whole => Value::deserialize(deserializer),
            Self::Object(_) | Self::List(_) => deserializer.deserialize_any(self),
        }
    }
}

impl<'de> Visitor<'de> for Shape {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a JSON value of shape {self:?}")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut kept = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let member = match self {
                Self::Object(members) => members.iter().find(|(member, _)| *member == name),
                Self::Whole | Self::List(_) => None,
            };
            match member {
                Some((_, shape)) => {
                    let value = map.next_value_seed(*shape)?;
                    kept.insert(name, value);
                }
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Value::Object(kept))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        if let Self::List(item) = self {
            while let Some(value) = seq.next_element_seed(*item)? {
                items.push(value);
            }
        } else {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
        }
        Ok(Value::Array(items))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
}

/// The members of `data` that `shape` keeps, or the error that says why `data` isn't JSON.
fn projected(data: &[u8], shape: Shape) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    let value = shape.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// The members of an accepted response that its typed reader reads, which an independent reader checks the accepted value against.
fn read(data: &[u8], shape: Shape) -> Value {
    projected(data, shape)
        .expect("an accepted response reads with the members that its reader reads")
}

/// The version that a release response is observed for when the input names no valid one.
const FALLBACK_VERSION: Version = Version::new(1, 2, 3);

/// The URL that served a GitHub page, which a refusal names.
const PAGE_URL: &str = "https://api.github.com/repos/acme/widget/releases?per_page=100&page=1";

/// Entries on one page of a GitHub list.
const PAGE_SIZE: usize = 100;

/// The line of a Release body that records the Candidate digest, before the digest.
const DIGEST_LINE: &str = "release-glz-candidate-digest: ";

/// The digits of a SHA-256 digest in hexadecimal.
const DIGEST_DIGITS: usize = 64;

/// A reader that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Package,
    Release,
    GitHubReleases,
    PullRequests,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    [
        (package(data), Reached::Package),
        (release(data), Reached::Release),
        (github_releases(data), Reached::GitHubReleases),
        (pull_requests(data), Reached::PullRequests),
    ]
    .into_iter()
    .filter_map(|(accepted, reader)| accepted.then_some(reader))
    .collect()
}

fn assert_refused(error: &anyhow::Error, reason: RefusalReason) {
    assert_eq!(refusal_reason(error), Some(reason), "{error:#}");
}

fn package(data: &[u8]) -> bool {
    let state = match parse_package_response(data) {
        Ok(state) => state,
        Err(error) => {
            assert_refused(&error, RefusalReason::RegistryPackageInvalid);
            return false;
        }
    };
    let value = read(data, PACKAGE);
    if let Some(members) = object(&value) {
        let listed = list(members, "releases");
        assert_eq!(state.releases.len(), listed.len());
        for (release, entry) in state.releases.iter().zip(listed) {
            let Some(entry) = object(entry) else {
                continue;
            };
            let spelled = text_or(entry, "version", "");
            assert_eq!(release.version.to_string(), spelled);
            assert_eq!(release.has_docs, flag(entry, "has_docs"));
            assert_eq!(
                release.retired,
                members
                    .get("retirements")
                    .is_some_and(|retirements| retirements.get(spelled).is_some())
            );
        }
    }
    let rendered = render_package(&state);
    assert_eq!(
        parse_package_response(&rendered).expect("a rendered package response reads back"),
        state
    );
    assert_highest(&state.releases, state.latest(), |_| true);
    assert_highest(&state.releases, state.latest_stable(), |release| {
        release.version.pre.is_empty()
    });
    true
}

/// The latest release has the highest precedence among the releases that `counts` keeps, or a tie at that precedence refuses it.
fn assert_highest(
    releases: &[HexRelease],
    latest: anyhow::Result<Option<&HexRelease>>,
    counts: impl Fn(&HexRelease) -> bool,
) {
    let counted: Vec<_> = releases.iter().filter(|release| counts(release)).collect();
    match latest {
        Ok(Some(latest)) => {
            assert!(counts(latest));
            for release in &counted {
                let order = release.version.cmp_precedence(&latest.version);
                assert_ne!(
                    order,
                    Ordering::Greater,
                    "{} > {}",
                    release.version,
                    latest.version
                );
                if order == Ordering::Equal {
                    assert_eq!(release.version, latest.version);
                }
            }
        }
        Ok(None) => assert!(counted.is_empty()),
        Err(error) => {
            assert_refused(&error, RefusalReason::RegistryReleasePrecedenceTie);
            let top = counted
                .iter()
                .max_by(|left, right| left.version.cmp_precedence(&right.version))
                .expect("a tie needs releases");
            assert!(counted.iter().any(|release| {
                release.version.cmp_precedence(&top.version) == Ordering::Equal
                    && release.version != top.version
            }));
        }
    }
}

fn render_package(state: &PackageState) -> Vec<u8> {
    let releases: Vec<_> = state
        .releases
        .iter()
        .map(
            |release| json!({"version": release.version.to_string(), "has_docs": release.has_docs}),
        )
        .collect();
    let retirements: serde_json::Map<_, _> = state
        .releases
        .iter()
        .filter(|release| release.retired)
        .map(|release| (release.version.to_string(), json!({"reason": "other"})))
        .collect();
    serde_json::to_vec(&json!({"releases": releases, "retirements": retirements}))
        .expect("a package response serializes")
}

/// The valid version that an object input names, which a release response is observed for so that a valid input can be accepted.
#[expect(
    clippy::disallowed_methods,
    reason = "an input that isn't JSON or names no valid version names none, and the invariant observes it for the fallback version"
)]
fn named_version(data: &[u8]) -> Option<Version> {
    projected(data, RELEASE)
        .ok()?
        .get("version")?
        .as_str()?
        .parse()
        .ok()
}

fn release(data: &[u8]) -> bool {
    let named = named_version(data);
    if let Some(named) = &named {
        let other = if *named == Version::new(0, 0, 0) {
            Version::new(0, 0, 1)
        } else {
            Version::new(0, 0, 0)
        };
        let error = parse_release_response(data, &other)
            .expect_err("a release response describes only the version it names");
        assert_refused(&error, RefusalReason::RegistryReleaseInvalid);
    }
    let observed = named.unwrap_or(FALLBACK_VERSION);
    let release = match parse_release_response(data, &observed) {
        Ok(release) => release,
        Err(error) => {
            assert_refused(&error, RefusalReason::RegistryReleaseInvalid);
            return false;
        }
    };
    assert_eq!(release.version, observed);
    let checksum = release
        .outer_checksum
        .as_ref()
        .expect("an accepted release names its checksum");
    if let Some(members) = object(&read(data, RELEASE)) {
        assert_eq!(
            checksum.as_str(),
            text_or(members, "checksum", "").to_ascii_lowercase()
        );
        assert_eq!(release.has_docs, flag(members, "has_docs"));
        assert_eq!(
            release.retired,
            members
                .get("retirement")
                .is_some_and(|retirement| !retirement.is_null())
        );
    }
    assert_eq!(
        parse_release_response(&render_release(&release, checksum.as_str()), &observed)
            .expect("a rendered release response reads back"),
        release
    );
    true
}

fn render_release(release: &RegistryRelease, checksum: &str) -> Vec<u8> {
    let mut rendered = json!({
        "version": release.version.to_string(),
        "checksum": checksum,
        "has_docs": release.has_docs,
    });
    if release.retired {
        rendered["retirement"] = json!({"reason": "other"});
    }
    serde_json::to_vec(&rendered).expect("a release response serializes")
}

/// A GitHub page refusal is one of its two documented errors, and an oversized page holds more entries than a page.
fn assert_page_refused(error: &anyhow::Error, data: &[u8], oversized: &str) {
    assert_eq!(refusal_reason(error), None, "{error:#}");
    let message = error.to_string();
    if message == oversized {
        let page = read(data, Shape::List(&NOTHING));
        let entries = page.as_array().expect("an oversized page is a list");
        assert!(entries.len() > PAGE_SIZE);
    } else {
        assert_eq!(message, format!("invalid GitHub response from {PAGE_URL}"));
    }
}

/// The members of a JSON object, which an independent reader compares with an accepted value.
///
/// Serde also reads a struct from a list by position, and such an entry is checked only by its round trip.
fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn text_or<'a>(members: &'a Map<String, Value>, name: &str, default: &'a str) -> &'a str {
    members.get(name).map_or(default, |value| {
        value.as_str().expect("an accepted text member is a string")
    })
}

fn number_or_zero(members: &Map<String, Value>, name: &str) -> u64 {
    members.get(name).map_or(0, |value| {
        value.as_u64().expect("an accepted number member is a u64")
    })
}

fn flag(members: &Map<String, Value>, name: &str) -> bool {
    members.get(name).and_then(Value::as_bool) == Some(true)
}

fn optional_text(members: &Map<String, Value>, name: &str) -> Option<String> {
    members.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Whether `text` is a SHA-256 digest in lowercase hexadecimal digits.
fn lowercase_digest(text: &str) -> bool {
    text.len() == DIGEST_DIGITS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The digest on the first line of `body` that, without its surrounding whitespace, records a Candidate digest.
fn recorded_digest(body: &str) -> Option<String> {
    body.split('\n').find_map(|line| {
        line.trim()
            .strip_prefix(DIGEST_LINE)
            .filter(|digest| lowercase_digest(digest))
            .map(str::to_owned)
    })
}

fn github_releases(data: &[u8]) -> bool {
    let releases = match parse_release_page(data, PAGE_URL) {
        Ok(releases) => releases,
        Err(error) => {
            assert_page_refused(&error, data, "GitHub returned an oversized release page");
            return false;
        }
    };
    assert!(releases.len() <= PAGE_SIZE);
    let page = read(data, Shape::List(&GITHUB_RELEASE));
    let entries = page.as_array().expect("an accepted page is a list");
    assert_eq!(releases.len(), entries.len());
    for (release, entry) in releases.iter().zip(entries) {
        if let Some(expected) = object(entry).and_then(expected_release) {
            assert_eq!(release, &expected);
        }
    }
    let rendered = serde_json::to_vec(
        &releases
            .iter()
            .map(render_github_release)
            .collect::<Vec<_>>(),
    )
    .expect("a release page serializes");
    assert_eq!(
        parse_release_page(&rendered, PAGE_URL).expect("a rendered release page reads back"),
        releases
    );
    true
}

/// A list member, or an empty list when it's absent.
fn list<'a>(members: &'a Map<String, Value>, name: &str) -> &'a [Value] {
    members.get(name).map_or(&[][..], |list| {
        list.as_array()
            .expect("an accepted list member is a list")
            .as_slice()
    })
}

/// The Release that an independent reading of one object of a release page finds, unless serde read a nested struct by position.
fn expected_release(members: &Map<String, Value>) -> Option<GitHubRelease> {
    let assets = list(members, "assets")
        .iter()
        .map(|asset| object(asset).map(expected_asset))
        .collect::<Option<Vec<_>>>()?;
    Some(GitHubRelease {
        id: number_or_zero(members, "id"),
        html_url: text_or(members, "html_url", "").to_owned(),
        tag_name: text_or(members, "tag_name", "").to_owned(),
        target_commitish: text_or(members, "target_commitish", "").to_owned(),
        candidate_digest: optional_text(members, "body")
            .as_deref()
            .and_then(recorded_digest),
        draft: flag(members, "draft"),
        upload_url: text_or(members, "upload_url", "").to_owned(),
        assets,
    })
}

fn expected_asset(members: &Map<String, Value>) -> GitHubReleaseAsset {
    GitHubReleaseAsset {
        id: number_or_zero(members, "id"),
        name: text_or(members, "name", "").to_owned(),
        state: text_or(members, "state", "").to_owned(),
        media_type: text_or(members, "content_type", "").to_owned(),
        size: number_or_zero(members, "size"),
        sha256: optional_text(members, "digest").and_then(|digest| {
            digest
                .strip_prefix("sha256:")
                .filter(|digest| lowercase_digest(digest))
                .map(str::to_owned)
        }),
    }
}

fn render_github_release(release: &GitHubRelease) -> Value {
    let assets: Vec<_> = release
        .assets
        .iter()
        .map(|asset| {
            json!({
                "id": asset.id,
                "name": asset.name,
                "state": asset.state,
                "content_type": asset.media_type,
                "size": asset.size,
                "digest": asset.sha256.as_ref().map(|digest| format!("sha256:{digest}")),
            })
        })
        .collect();
    json!({
        "id": release.id,
        "html_url": release.html_url,
        "tag_name": release.tag_name,
        "target_commitish": release.target_commitish,
        "body": release.candidate_digest.as_ref().map(|digest| format!("{DIGEST_LINE}{digest}")),
        "draft": release.draft,
        "upload_url": release.upload_url,
        "assets": assets,
    })
}

fn pull_requests(data: &[u8]) -> bool {
    let pulls = match parse_pull_request_page(data, PAGE_URL) {
        Ok(pulls) => pulls,
        Err(error) => {
            assert_page_refused(
                &error,
                data,
                "GitHub returned an oversized open pull-request page",
            );
            return false;
        }
    };
    assert!(pulls.len() <= PAGE_SIZE);
    let page = read(data, Shape::List(&PULL_REQUEST));
    let entries = page.as_array().expect("an accepted page is a list");
    assert_eq!(pulls.len(), entries.len());
    let rendered: Vec<_> = pulls.iter().map(render_pull_request).collect();
    for (rendered, entry) in rendered.iter().zip(entries) {
        if let Some(expected) = object(entry).and_then(expected_pull_request) {
            assert_eq!(rendered, &expected);
        }
    }
    let reread = parse_pull_request_page(
        &serde_json::to_vec(&rendered).expect("a pull request page serializes"),
        PAGE_URL,
    )
    .expect("a rendered pull request page reads back");
    assert_eq!(
        reread.iter().map(render_pull_request).collect::<Vec<_>>(),
        rendered
    );
    true
}

/// The JSON of every member of a pull request that release-glz reads.
fn render_pull_request(pull: &PullRequest) -> Value {
    let repository = |repository: &release_glz::forge::PullRepository| json!({"full_name": repository.full_name, "default_branch": repository.default_branch});
    json!({
        "number": pull.number,
        "title": pull.title,
        "body": pull.body,
        "html_url": pull.html_url,
        "merge_commit_sha": pull.merge_commit_sha,
        "merged_at": pull.merged_at,
        "user": {"login": pull.user.login},
        "labels": pull.labels.iter().map(|label| json!({"name": label.name})).collect::<Vec<_>>(),
        "head": {
            "ref": pull.head.branch,
            "sha": pull.head.sha,
            "repo": pull.head.repo.as_ref().map(repository),
        },
        "base": pull.base.as_ref().map(|base| json!({"ref": base.branch, "repo": repository(&base.repo)})),
    })
}

/// An optional member, which is null when it's absent.
fn member_or_null(members: &Map<String, Value>, name: &str) -> Value {
    members.get(name).cloned().unwrap_or(Value::Null)
}

/// The rendering of an optional repository member, unless serde read it by position.
fn expected_repository(value: Option<&Value>) -> Option<Value> {
    match value {
        None | Some(Value::Null) => Some(Value::Null),
        Some(value) => {
            let members = object(value)?;
            Some(
                json!({"full_name": members["full_name"], "default_branch": members["default_branch"]}),
            )
        }
    }
}

/// The rendering of the pull request that an independent reading of one object of a pull request page finds, unless serde read a nested struct by position.
fn expected_pull_request(members: &Map<String, Value>) -> Option<Value> {
    let head = object(&members["head"])?;
    let user = object(&members["user"])?;
    let labels = list(members, "labels")
        .iter()
        .map(|label| Some(json!({"name": object(label)?["name"]})))
        .collect::<Option<Vec<_>>>()?;
    let base = match members.get("base") {
        None | Some(Value::Null) => Value::Null,
        Some(base) => {
            let base = object(base)?;
            json!({"ref": base["ref"], "repo": expected_repository(base.get("repo"))?})
        }
    };
    Some(json!({
        "number": members["number"],
        "title": members["title"],
        "body": member_or_null(members, "body"),
        "html_url": members["html_url"],
        "merge_commit_sha": member_or_null(members, "merge_commit_sha"),
        "merged_at": member_or_null(members, "merged_at"),
        "user": {"login": user["login"]},
        "labels": labels,
        "head": {"ref": head["ref"], "sha": head["sha"], "repo": expected_repository(head.get("repo"))?},
        "base": base,
    }))
}
