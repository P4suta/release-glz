use std::fs;
use std::path::Path;

#[path = "../fuzz/invariants/api_interface.rs"]
mod api_interface;
#[path = "../fuzz/invariants/archive.rs"]
mod archive;
#[path = "../fuzz/invariants/config.rs"]
mod config;
#[path = "../fuzz/invariants/identifiers.rs"]
mod identifiers;
#[path = "../fuzz/invariants/pr_marker.rs"]
mod pr_marker;

const REPLAYED_TARGETS: [&str; 5] = [
    "api_interface",
    "archive",
    "config",
    "identifiers",
    "pr_marker",
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
fn manifest_seeds_reach_parsing_initialization_and_refusal() {
    let verdicts = replay("config", config::check);
    assert!(reached(&verdicts, config::Reached::Parsed));
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
