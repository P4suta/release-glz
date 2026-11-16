use std::fs;
use std::path::Path;

#[path = "../fuzz/invariants/api_interface.rs"]
mod api_interface;
#[path = "../fuzz/invariants/api_responses.rs"]
mod api_responses;
#[path = "../fuzz/invariants/archive.rs"]
mod archive;
#[path = "../fuzz/invariants/candidate.rs"]
mod candidate;
#[path = "../fuzz/invariants/changelog_notes.rs"]
mod changelog_notes;
#[path = "../fuzz/invariants/config.rs"]
mod config;
#[path = "../fuzz/invariants/git_log.rs"]
mod git_log;
#[path = "../fuzz/invariants/handoff.rs"]
mod handoff;
#[path = "../fuzz/invariants/hook_output.rs"]
mod hook_output;
#[path = "../fuzz/invariants/identifiers.rs"]
mod identifiers;
#[path = "../fuzz/invariants/oidc.rs"]
mod oidc;
#[path = "../fuzz/invariants/pr_marker.rs"]
mod pr_marker;
#[path = "../fuzz/invariants/prerelease.rs"]
mod prerelease;

const REPLAYED_TARGETS: [&str; 13] = [
    "api_interface",
    "api_responses",
    "archive",
    "candidate",
    "changelog_notes",
    "config",
    "git_log",
    "handoff",
    "hook_output",
    "identifiers",
    "oidc",
    "pr_marker",
    "prerelease",
];

fn fuzz_directory() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz"))
}

/// Run every committed seed of one fuzz target through the checks that the target runs.
///
/// Each verdict lists the accepting paths that one seed reached, and an empty verdict is a refusal.
fn replay<T>(target: &str, check: fn(&[u8]) -> Vec<T>) -> Vec<Vec<T>> {
    let corpus = fuzz_directory().join("corpus").join(target);
    let mut verdicts = Vec::new();
    for entry in fs::read_dir(&corpus)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", corpus.display()))
    {
        let path = entry.unwrap().path();
        assert!(path.is_file(), "{} isn't a seed file", path.display());
        verdicts.push(check(&fs::read(&path).unwrap()));
    }
    assert!(!verdicts.is_empty(), "the {target} corpus has no seed");
    verdicts
}

fn reached<T: PartialEq>(verdicts: &[Vec<T>], path: T) -> bool {
    verdicts.iter().any(|reached| reached.contains(&path))
}

fn refused<T>(verdicts: &[Vec<T>]) -> bool {
    verdicts.iter().any(Vec::is_empty)
}

#[test]
fn every_fuzz_target_runs_shared_invariants_that_this_suite_replays() {
    let manifest = fs::read_to_string(fuzz_directory().join("Cargo.toml"))
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let mut targets: Vec<_> = manifest["bin"]
        .as_array_of_tables()
        .expect("the fuzz manifest declares its targets")
        .iter()
        .map(|target| target["name"].as_str().unwrap().to_owned())
        .collect();
    targets.sort();
    assert_eq!(targets, REPLAYED_TARGETS);
    for target in REPLAYED_TARGETS {
        let source =
            fs::read_to_string(fuzz_directory().join(format!("fuzz_targets/{target}.rs"))).unwrap();
        assert!(
            source.contains(&format!("invariants::{target}::check(data)")),
            "the {target} target doesn't run its shared invariants through the fuzz library"
        );
        assert!(
            !source.contains("#[path"),
            "the {target} target includes a module by path"
        );
        assert!(
            fuzz_directory()
                .join(format!("invariants/{target}.rs"))
                .is_file()
        );
    }
}

#[test]
fn manifest_seeds_reach_parsing_configuration_initialization_and_refusal() {
    let verdicts = replay("config", config::check);
    assert!(reached(&verdicts, config::Reached::Parsed));
    assert!(reached(&verdicts, config::Reached::Configured));
    assert!(reached(&verdicts, config::Reached::Initialized));
    assert!(refused(&verdicts));
}

#[test]
fn identifier_seeds_reach_every_parser_and_refusal() {
    let verdicts = replay("identifiers", identifiers::check);
    assert!(reached(&verdicts, identifiers::Reached::Repository));
    assert!(reached(&verdicts, identifiers::Reached::Channel));
    assert!(reached(&verdicts, identifiers::Reached::ChannelJson));
    assert!(refused(&verdicts));
}

#[test]
fn archive_seeds_reach_both_validators_and_refusal() {
    let verdicts = replay("archive", archive::check);
    assert!(reached(&verdicts, archive::Reached::HexPackage));
    assert!(reached(&verdicts, archive::Reached::DocsArchive));
    assert!(refused(&verdicts));
}

/// Archive seeds that this suite builds, one for each path form that some supported OS can't represent.
fn unportable_archive_seeds() -> [(&'static str, Vec<u8>); 5] {
    [
        ("docs-colon-path", docs_seed(&[("a:b.html", b"stream")])),
        ("docs-device-name", docs_seed(&[("aux.html", b"device")])),
        ("docs-trailing-dot", docs_seed(&[("index.", b"dot")])),
        (
            "docs-windows-character",
            docs_seed(&[("what?.html", b"query")]),
        ),
        (
            "docs-case-collision",
            docs_seed(&[("README.md", b"upper"), ("readme.md", b"lower")]),
        ),
    ]
}

/// A gzip-compressed tar archive whose bytes depend only on `files`.
fn docs_seed(files: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(&mut header, path, *contents).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap()
}

#[test]
fn the_archive_corpus_holds_a_built_seed_for_each_unportable_path_form() {
    for (name, bytes) in unportable_archive_seeds() {
        let path = fuzz_directory().join("corpus/archive").join(name);
        if std::env::var_os("RELEASE_GLZ_WRITE_CORPUS").is_some() {
            fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(
            fs::read(&path).unwrap_or_default(),
            bytes,
            "{name} differs from its builder; rebuild it with RELEASE_GLZ_WRITE_CORPUS=1"
        );
        assert!(archive::check(&bytes).is_empty(), "{name} is accepted");
    }
}

#[test]
fn marker_seeds_reach_managed_and_unmanaged_bodies() {
    let verdicts = replay("pr_marker", pr_marker::check);
    assert!(reached(&verdicts, pr_marker::Reached::Managed));
    assert!(refused(&verdicts));
}

#[test]
fn prerelease_seeds_reach_trains_text_comparison_and_refusal() {
    let verdicts = replay("prerelease", prerelease::check);
    assert!(reached(&verdicts, prerelease::Reached::Train));
    assert!(reached(&verdicts, prerelease::Reached::Text));
    assert!(reached(&verdicts, prerelease::Reached::Compared));
    assert!(refused(&verdicts));
}

#[test]
fn api_response_seeds_reach_every_registry_and_github_reader_and_refusal() {
    let verdicts = replay("api_responses", api_responses::check);
    for reader in [
        api_responses::Reached::Package,
        api_responses::Reached::Release,
        api_responses::Reached::GitHubReleases,
        api_responses::Reached::PullRequests,
    ] {
        assert!(reached(&verdicts, reader), "no seed reaches {reader:?}");
    }
    assert!(refused(&verdicts));
}

#[test]
fn candidate_seeds_reach_a_sealed_manifest_and_refusal() {
    let verdicts = replay("candidate", candidate::check);
    assert!(reached(&verdicts, candidate::Reached::Manifest));
    assert!(refused(&verdicts));
}

#[test]
fn changelog_note_seeds_reach_notes_the_release_notes_configuration_and_refusal() {
    let verdicts = replay("changelog_notes", changelog_notes::check);
    assert!(reached(&verdicts, changelog_notes::Reached::Note));
    assert!(reached(
        &verdicts,
        changelog_notes::Reached::ReleaseNotesConfig
    ));
    assert!(refused(&verdicts));
}

#[test]
fn git_log_seeds_reach_commits_and_refusal() {
    let verdicts = replay("git_log", git_log::check);
    assert!(reached(&verdicts, git_log::Reached::Commits));
    assert!(refused(&verdicts));
}

#[test]
fn handoff_seeds_reach_a_plan_and_refusal() {
    let verdicts = replay("handoff", handoff::check);
    assert!(reached(&verdicts, handoff::Reached::Plan));
    assert!(refused(&verdicts));
}

#[test]
fn hook_output_seeds_reach_reports_sidecar_artifacts_and_refusal() {
    let verdicts = replay("hook_output", hook_output::check);
    assert!(reached(&verdicts, hook_output::Reached::Report));
    assert!(reached(&verdicts, hook_output::Reached::Artifacts));
    assert!(refused(&verdicts));
}

#[test]
fn oidc_seeds_reach_every_reader_and_refusal() {
    let verdicts = replay("oidc", oidc::check);
    for reader in [
        oidc::Reached::TokenResponse,
        oidc::Reached::Discovery,
        oidc::Reached::KeySet,
        oidc::Reached::Claims,
        oidc::Reached::Token,
    ] {
        assert!(reached(&verdicts, reader), "no seed reaches {reader:?}");
    }
    assert!(refused(&verdicts));
}

/// One `git log` record in the format that the reader reads.
fn git_record(sha: &str, subject: &str, body: &str) -> String {
    format!("{sha}\0Ada Lovelace\0ada@example.test\0{subject}\0{body}\0\n")
}

/// The sealed manifest seed with two sidecars whose sizes add up past the largest number.
fn overflowing_sidecars_seed() -> Vec<u8> {
    let sealed = fs::read(fuzz_directory().join("corpus/candidate/sealed-manifest")).unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    let sidecar = |name: &str, size: u64| {
        serde_json::json!({
            "hook_id": "sbom",
            "name": name,
            "path": format!("sidecars/sbom/{name}"),
            "media_type": "application/json",
            "sha256": "7".repeat(64),
            "size": size,
            "public": true,
        })
    };
    manifest["sidecars"] =
        serde_json::json!([sidecar("first.json", 1), sidecar("second.json", u64::MAX)]);
    release_glz::canonical::canonical_json_bytes(&manifest).unwrap()
}

/// Seeds that hold NUL bytes, a signature, or a canonical spelling, which this suite builds so that a reader can review their builder.
///
/// Each new target also starts from the empty input, which libFuzzer runs first.
fn built_seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let sha = "0123456789abcdef0123456789abcdef01234567";
    let log = |records: &[String]| records.concat().into_bytes();
    let mut seeds: Vec<_> = [
        "api_responses",
        "candidate",
        "changelog_notes",
        "handoff",
        "hook_output",
        "oidc",
    ]
    .into_iter()
    .map(|target| (target, "empty", Vec::new()))
    .collect();
    seeds.push((
        "candidate",
        "sidecar-sizes-overflow",
        overflowing_sidecars_seed(),
    ));
    seeds.extend([
        (
            "git_log",
            "two-commits",
            log(&[
                git_record(
                    sha,
                    "feat(api)!: replace the gadget",
                    "Replaces the gadget.\n\nBREAKING CHANGE: the old gadget is gone",
                ),
                git_record(&"89abcdef".repeat(5), "fix: crash", ""),
            ]),
        ),
        (
            "git_log",
            "body-with-surrounding-whitespace",
            log(&[git_record(sha, "docs: explain", "\n  explained  \n\n")]),
        ),
        ("git_log", "empty-log", Vec::new()),
        (
            "git_log",
            "uppercase-commit-id",
            log(&[git_record(&sha.to_ascii_uppercase(), "fix: x", "")]),
        ),
        (
            "git_log",
            "sha256-object-id",
            log(&[git_record(&"b".repeat(64), "fix: x", "")]),
        ),
        (
            "git_log",
            "record-without-body",
            format!("{sha}\0Ada Lovelace\0ada@example.test\0fix: x").into_bytes(),
        ),
        (
            "oidc",
            "signed-token",
            oidc::signed_token(oidc::valid_claims().to_string().as_bytes()).into_bytes(),
        ),
    ]);
    seeds
}

/// The checks of one fuzz target, which drop the paths that an input reached.
type Invariant = fn(&[u8]);

/// Every invariant holds on every committed seed of every target, since the seeds of one target are well-formed input of another shape for the rest.
#[test]
fn every_invariant_holds_on_the_seeds_of_every_target() {
    let checks: [(&str, Invariant); 13] = [
        ("api_interface", |data| drop(api_interface::check(data))),
        ("api_responses", |data| drop(api_responses::check(data))),
        ("archive", |data| drop(archive::check(data))),
        ("candidate", |data| drop(candidate::check(data))),
        ("changelog_notes", |data| drop(changelog_notes::check(data))),
        ("config", |data| drop(config::check(data))),
        ("git_log", |data| drop(git_log::check(data))),
        ("handoff", |data| drop(handoff::check(data))),
        ("hook_output", |data| drop(hook_output::check(data))),
        ("identifiers", |data| drop(identifiers::check(data))),
        ("oidc", |data| drop(oidc::check(data))),
        ("pr_marker", |data| drop(pr_marker::check(data))),
        ("prerelease", |data| drop(prerelease::check(data))),
    ];
    for target in REPLAYED_TARGETS {
        for entry in fs::read_dir(fuzz_directory().join("corpus").join(target)).unwrap() {
            let path = entry.unwrap().path();
            let seed = fs::read(&path).unwrap();
            for (invariant, check) in checks {
                let held = std::panic::catch_unwind(|| check(&seed));
                assert!(
                    held.is_ok(),
                    "the {invariant} invariant fails on {}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn every_built_seed_matches_its_builder() {
    for (target, name, bytes) in built_seeds() {
        let path = fuzz_directory().join("corpus").join(target).join(name);
        if std::env::var_os("RELEASE_GLZ_WRITE_CORPUS").is_some() {
            fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(
            fs::read(&path).unwrap_or_default(),
            bytes,
            "{target}/{name} differs from its builder; rebuild it with RELEASE_GLZ_WRITE_CORPUS=1"
        );
    }
}

/// The OIDC invariants keep their own copy of the RFC 7515 key, since the fuzz workspace doesn't build the test support crate.
#[test]
fn the_oidc_invariants_sign_with_the_key_that_the_test_support_signs_with() {
    use release_glz_test_support::oidc as support;

    assert_eq!(oidc::rfc7515::KEY_ID, support::KEY_ID);
    assert_eq!(oidc::rfc7515::MODULUS, support::MODULUS);
    assert_eq!(oidc::rfc7515::EXPONENT, support::EXPONENT);
    let claims = oidc::valid_claims();
    assert_eq!(
        oidc::signed_token(&serde_json::to_vec(&claims).unwrap()),
        support::sign_rs256(&claims)
    );
}

#[test]
fn interface_seeds_reach_changed_unchanged_and_refused_comparisons() {
    let verdicts = replay("api_interface", api_interface::check);
    assert!(reached(&verdicts, api_interface::Reached::Changed));
    assert!(
        verdicts
            .iter()
            .any(|reached| reached == &[api_interface::Reached::Compared])
    );
    assert!(refused(&verdicts));
}
