//! The map in `docs/assurance.md` from each release property to the proofs, models, and tests that check it.
//!
//! The check refuses a reference that names nothing, a property without evidence, and a harness, theorem, invariant, model test, or fuzz target that no property cites.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::container::Failure;
use crate::inventory::HARNESSES;
use crate::lean::{MODEL_THEOREMS, REFINEMENT_THEOREMS};

/// The map, relative to the repository.
const MAP: &str = "docs/assurance.md";

/// The Quint model, relative to the repository.
const QUINT_MODEL: &str = "verification/quint/release_run.qnt";

/// The fuzz targets, relative to the repository.
const FUZZ_TARGETS: &str = "fuzz/fuzz_targets";

/// The heading that starts a property.
const PROPERTY: &str = "### ";

/// The kinds of evidence that the map cites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Kani,
    Lean,
    Quint,
    Fuzz,
    Test,
}

impl Kind {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "Kani" => Self::Kani,
            "Lean" => Self::Lean,
            "Quint" => Self::Quint,
            "Fuzz" => Self::Fuzz,
            "Test" => Self::Test,
            _ => return None,
        })
    }
}

/// One citation of evidence under a property.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Citation {
    kind: Kind,
    name: String,
    property: String,
}

/// The citations of the map, refusing a property without any and a list line that names no known kind.
fn citations(map: &str) -> Result<Vec<Citation>, Failure> {
    let mut citations = Vec::new();
    let mut property: Option<(String, usize)> = None;
    let finish = |property: Option<(String, usize)>, count: usize| match property {
        Some((name, before)) if count == before => Err(Failure::new(format!(
            "the property \"{name}\" cites no evidence"
        ))),
        _ => Ok(()),
    };
    for line in map.lines() {
        if let Some(heading) = line.strip_prefix(PROPERTY) {
            finish(property.take(), citations.len())?;
            property = Some((heading.trim().to_owned(), citations.len()));
            continue;
        }
        if line.starts_with("## ") || line.starts_with("# ") {
            finish(property.take(), citations.len())?;
            continue;
        }
        let Some(item) = line.strip_prefix("- ") else {
            continue;
        };
        let Some((kind, rest)) = item.split_once(": ") else {
            continue;
        };
        let Some(kind) = Kind::named(kind) else {
            continue;
        };
        let (name, _) = property
            .as_ref()
            .ok_or_else(|| Failure::new(format!("\"{line}\" cites evidence outside a property")))?;
        let cited = rest
            .strip_prefix('`')
            .and_then(|rest| rest.strip_suffix('`'))
            .filter(|cited| !cited.is_empty() && !cited.contains('`'))
            .ok_or_else(|| {
                Failure::new(format!(
                    "\"{line}\" must name exactly one identifier in backticks"
                ))
            })?;
        citations.push(Citation {
            kind,
            name: cited.to_owned(),
            property: name.clone(),
        });
    }
    finish(property, citations.len())?;
    Ok(citations)
}

/// The invariants that the model's `safe` combines, and its tests.
fn quint_names(model: &str) -> Result<BTreeSet<String>, Failure> {
    let invariant = model
        .lines()
        .find_map(|line| line.trim().strip_prefix("val safe = "))
        .ok_or_else(|| Failure::new("the Quint model defines no invariant `safe`"))?;
    let mut names = invariant
        .split(" and ")
        .map(|name| name.trim().to_owned())
        .collect::<BTreeSet<_>>();
    names.extend(model.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("run ")
            .and_then(|rest| rest.split_once(' '))
            .map(|(name, _)| name.to_owned())
    }));
    Ok(names)
}

/// The fuzz targets in `directory`.
fn fuzz_targets(directory: &Path) -> Result<BTreeSet<String>, Failure> {
    let mut targets = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(Failure::io)? {
        let path = entry.map_err(Failure::io)?.path();
        if path.extension().is_some_and(|extension| extension == "rs")
            && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
        {
            targets.insert(stem.to_owned());
        }
    }
    Ok(targets)
}

/// Whether `source` defines the test `name`: a function with a test attribute between it and the item before it.
fn defines_test(source: &str, name: &str) -> bool {
    let signature = format!("fn {name}(");
    source.match_indices(&signature).any(|(position, _)| {
        let before = &source[..position];
        let item = before.rfind('}').map_or(before, |end| &before[end..]);
        item.contains("#[test]") || item.contains("#[tokio::test]")
    })
}

/// What the check found.
#[derive(Debug)]
pub struct Summary {
    properties: usize,
    citations: usize,
}

/// Check the map of the repository at `root`.
pub fn check(root: &Path) -> Result<Summary, Failure> {
    let map = fs::read_to_string(root.join(MAP)).map_err(Failure::io)?;
    let model = fs::read_to_string(root.join(QUINT_MODEL)).map_err(Failure::io)?;
    let fuzz = fuzz_targets(&root.join(FUZZ_TARGETS))?;
    verify(&map, &model, &fuzz, |file| {
        fs::read_to_string(root.join(file)).ok()
    })
}

/// Check `map` with the Quint `model`, the `fuzz` targets, and the sources that `read` returns for a path in the repository.
fn verify(
    map: &str,
    model: &str,
    fuzz: &BTreeSet<String>,
    read: impl Fn(&str) -> Option<String>,
) -> Result<Summary, Failure> {
    let citations = citations(map)?;
    let kani = HARNESSES
        .iter()
        .map(|harness| harness.name.to_owned())
        .collect::<BTreeSet<_>>();
    let lean = MODEL_THEOREMS
        .iter()
        .chain(REFINEMENT_THEOREMS.iter())
        .map(|theorem| (*theorem).to_owned())
        .collect::<BTreeSet<_>>();
    let quint = quint_names(model)?;

    for citation in &citations {
        let known = match citation.kind {
            Kind::Kani => kani.contains(&citation.name),
            Kind::Lean => lean.contains(&citation.name),
            Kind::Quint => quint.contains(&citation.name),
            Kind::Fuzz => fuzz.contains(&citation.name),
            Kind::Test => {
                let (file, name) = citation.name.rsplit_once("::").ok_or_else(|| {
                    Failure::new(format!(
                        "the test `{}` must name a file and a function",
                        citation.name
                    ))
                })?;
                read(file).is_some_and(|source| defines_test(&source, name))
            }
        };
        if !known {
            return Err(Failure::new(format!(
                "\"{}\" cites {:?} `{}`, which doesn't exist",
                citation.property, citation.kind, citation.name
            )));
        }
    }
    for (kind, existing) in [
        (Kind::Kani, &kani),
        (Kind::Lean, &lean),
        (Kind::Quint, &quint),
        (Kind::Fuzz, fuzz),
    ] {
        let cited = citations
            .iter()
            .filter(|citation| citation.kind == kind)
            .map(|citation| &citation.name)
            .collect::<BTreeSet<_>>();
        if let Some(missing) = existing.iter().find(|name| !cited.contains(name)) {
            return Err(Failure::new(format!(
                "{MAP} maps no property to {kind:?} `{missing}`"
            )));
        }
    }
    let properties = citations
        .iter()
        .map(|citation| &citation.property)
        .collect::<BTreeSet<_>>()
        .len();
    Ok(Summary {
        properties,
        citations: citations.len(),
    })
}

/// Check the map and report what it covers.
pub fn run(root: &Path) -> Result<(), Failure> {
    let summary = check(root)?;
    println!(
        "{MAP} maps {} properties to {} citations, each of which resolves, and cites every harness, theorem, invariant, model test, and fuzz target",
        summary.properties, summary.citations
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        FUZZ_TARGETS, Kind, MAP, QUINT_MODEL, check, citations, defines_test, fuzz_targets,
        quint_names, verify,
    };

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    /// The map of the repository with `edit` applied, checked with the repository's model, fuzz targets, and sources.
    fn verify_edited(edit: impl Fn(String) -> String) -> Result<(), String> {
        let root = repository();
        let map = edit(fs::read_to_string(root.join(MAP)).unwrap());
        let model = fs::read_to_string(root.join(QUINT_MODEL)).unwrap();
        let fuzz = fuzz_targets(&root.join(FUZZ_TARGETS)).unwrap();
        verify(&map, &model, &fuzz, |file| {
            fs::read_to_string(root.join(file)).ok()
        })
        .map(|_| ())
        .map_err(|failure| failure.to_string())
    }

    /// The fast gate runs this on every pull request, so a new harness, theorem, invariant, model test, or fuzz target needs a property in the map before it merges.
    #[test]
    fn the_assurance_map_resolves_and_covers_every_check() {
        check(&repository()).unwrap();
    }

    #[test]
    fn an_uncited_check_or_an_unresolved_citation_is_refused() {
        for (line, kind) in [
            (
                "- Kani: `version::proofs::the_join_of_two_bumps_is_the_larger_one`\n",
                "Kani",
            ),
            ("- Lean: `ReleaseGlz.no_effect_without_approval`\n", "Lean"),
            ("- Quint: `skipsAheadTest`\n", "Quint"),
            ("- Fuzz: `pr_marker`\n", "Fuzz"),
        ] {
            let error = verify_edited(|map| map.replacen(line, "", 1)).unwrap_err();
            assert!(
                error.contains(&format!("maps no property to {kind}")),
                "{error}"
            );
        }
        for (from, to) in [
            (
                "proofs::advancing_is_transitive`",
                "proofs::advancing_is_reflexive`",
            ),
            (
                "`ReleaseGlz.conflict_iff_differs`",
                "`ReleaseGlz.conflict_if_differs`",
            ),
            ("`ordered`", "`unordered`"),
            ("Fuzz: `archive`", "Fuzz: `archives`"),
            (
                "::archive_paths_reject_every_ambiguous_or_traversing_form`",
                "::archive_paths_accept_everything`",
            ),
            ("`tests/v1_domain.rs::", "`tests/v1_domains.rs::"),
        ] {
            let error = verify_edited(|map| map.replacen(from, to, 1)).unwrap_err();
            assert!(error.contains("which doesn't exist"), "{from}: {error}");
        }
    }

    #[test]
    fn a_property_without_evidence_or_a_malformed_citation_is_refused() {
        let map = "# Map\n\n### Covered\n\n- Kani: `a`\n- Test: `tests/x.rs::b`\n\n### Next\n\n- Fuzz: `c`\n";
        let found = citations(map).unwrap();
        assert_eq!(found.len(), 3);
        assert_eq!(found[1].kind, Kind::Test);
        assert_eq!(found[2].property, "Next");
        assert!(citations("### Empty\n\nNothing cited.\n\n### Other\n\n- Kani: `a`\n").is_err());
        assert!(citations("### Last\n").is_err());
        assert!(citations("### Bad\n\n- Kani: a\n").is_err());
        assert!(citations("### Bad\n\n- Kani: `a` and `b`\n").is_err());
        assert!(citations("- Kani: `a`\n").is_err());
    }

    #[test]
    fn a_test_resolves_only_to_a_function_under_a_test_attribute() {
        let source =
            "fn helper() {}\n\n#[test]\nfn real() {}\n\n#[tokio::test]\nasync fn later() {}\n";
        assert!(defines_test(source, "real"));
        assert!(defines_test(source, "later"));
        assert!(!defines_test(source, "helper"));
        assert!(!defines_test(source, "missing"));
    }

    #[test]
    fn the_quint_names_are_the_invariants_of_safe_and_the_tests() {
        let model =
            "  val safe = ordered and approvalFirst\n  run aTest =\n    init\n  run bTest = init\n";
        let names = quint_names(model).unwrap();
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            ["aTest", "approvalFirst", "bTest", "ordered"]
        );
        assert!(quint_names("  run aTest = init\n").is_err());
    }
}
