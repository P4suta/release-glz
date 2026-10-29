//! Properties of the repository slug and prerelease channel parsers.
//!
//! Each parser must accept exactly the language that an independent statement of its rules describes.

use release_glz::forge::GitHubRepository;
use release_glz::model::PrereleaseChannel;

const MAX_OWNER_LENGTH: usize = 39;
const MAX_NAME_LENGTH: usize = 100;
const CHANNELS: [(&str, PrereleaseChannel); 3] = [
    ("alpha", PrereleaseChannel::Alpha),
    ("beta", PrereleaseChannel::Beta),
    ("rc", PrereleaseChannel::Rc),
];

/// A parser that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Repository,
    Channel,
    ChannelJson,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    [
        (repository(text), Reached::Repository),
        (channel(text), Reached::Channel),
        (channel_json(text), Reached::ChannelJson),
    ]
    .into_iter()
    .filter_map(|(accepted, parser)| accepted.then_some(parser))
    .collect()
}

/// GitHub owners are 1 to 39 letters, digits, or single inner hyphens.
fn owner_follows_github_rules(owner: &str) -> bool {
    owner.len() <= MAX_OWNER_LENGTH
        && owner.split('-').all(|segment| {
            !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

/// GitHub repository names are 1 to 100 letters, digits, `-`, `_`, or `.`, other than `.` and `..`.
fn name_follows_github_rules(name: &str) -> bool {
    (1..=MAX_NAME_LENGTH).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        && name != "."
        && name != ".."
}

fn repository(text: &str) -> bool {
    let follows_rules = text.split_once('/').is_some_and(|(owner, name)| {
        owner_follows_github_rules(owner) && name_follows_github_rules(name)
    });
    let parsed = GitHubRepository::parse(text);
    assert_eq!(parsed.is_ok(), follows_rules, "{text:?}: {parsed:?}");
    let Ok(repository) = parsed else {
        return false;
    };
    assert_eq!(repository.full_name(), text);
    assert_eq!(
        GitHubRepository::parse(&repository.full_name()).ok(),
        Some(repository)
    );
    true
}

fn channel(text: &str) -> bool {
    let expected = CHANNELS
        .iter()
        .find(|(name, _)| *name == text)
        .map(|(_, channel)| *channel);
    let parsed = text.parse::<PrereleaseChannel>();
    assert_eq!(parsed.as_ref().ok().copied(), expected, "{text:?}");
    let Ok(channel) = parsed else {
        return false;
    };
    assert_eq!(channel.as_str(), text);
    let json = serde_json::to_string(&channel).expect("a channel serializes");
    assert_eq!(json, format!("\"{text}\""));
    assert_eq!(
        serde_json::from_str::<PrereleaseChannel>(&json).ok(),
        Some(channel)
    );
    true
}

fn channel_json(text: &str) -> bool {
    let Ok(channel) = serde_json::from_str::<PrereleaseChannel>(text) else {
        return false;
    };
    assert_eq!(channel.as_str().parse::<PrereleaseChannel>(), Ok(channel));
    let json = serde_json::to_string(&channel).expect("a channel serializes");
    assert_eq!(
        serde_json::from_str::<PrereleaseChannel>(&json).ok(),
        Some(channel)
    );
    true
}
