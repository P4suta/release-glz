//! Mutants of the core crates, each run through the Kani harnesses, so a harness that leaves a decision unconstrained shows up as a survivor.
//!
//! The campaign runs on an owner machine and writes a receipt, and the release gate checks that receipt against the core sources without running Kani.

use std::collections::BTreeSet;
use std::fs;
use std::ops::RangeInclusive;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::container::{Container, Exit, Failure, Mounts};
use crate::inventory::HARNESSES;
use crate::proof_report::{KANI_VERSION, ProofReport};
use crate::proofs::{Module, TARGET_DIRECTORY, admit_every_harness, keep_logs, read_report};
use crate::source_snapshot::{SourceSnapshot, copy_roots, digest_of, roots};

/// The cargo-mutants release that `verification/kani.Dockerfile` installs.
const MUTANTS_VERSION: &str = "27.1.0";

/// The core crates, whose sources the mutants change and the receipt binds.
const CORE: [&str; 2] = ["crates/release-glz-core", "crates/assurance-core"];

/// The packages of the core crates, as cargo-mutants names them.
const CORE_PACKAGES: [&str; 2] = ["release-glz-core", "assurance-core"];

/// The mutants that no harness can detect because they change no decision, each with its reason.
const EQUIVALENT: &str = "verification/equivalent-mutants.json";

/// The committed receipt of the newest campaign.
const RECEIPT: &str = "verification/proof-mutants.json";

/// The attribute line that puts a module out of every build but Kani's.
const KANI_ONLY: &str = "#[cfg(kani)]";

/// The prefix of the functions that hold the negative controls, which only their own features compile.
const NEGATIVE_CONTROL: &str = "negative_control_";

/// A position in a source file, with a line and a column in characters that both count from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct Position {
    line: usize,
    column: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct Span {
    start: Position,
    end: Position,
}

#[derive(Debug, Clone, Deserialize)]
struct Function {
    function_name: String,
}

/// One mutant as cargo-mutants lists it.
#[derive(Debug, Clone, Deserialize)]
struct Listed {
    file: String,
    package: String,
    span: Span,
    replacement: String,
    function: Option<Function>,
    name: String,
}

/// A mutant's identity without line numbers, which edits elsewhere in its file leave unchanged.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Key {
    file: String,
    function: String,
    original: String,
    replacement: String,
}

/// What became of one mutant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    /// A harness refused the mutated core.
    Detected,
    /// The mutated core doesn't compile.
    Unviable,
    /// Every harness admitted the mutated core, which the equivalent list has to explain.
    Survived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Verdict {
    #[serde(flatten)]
    key: Key,
    outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detected_by: Option<String>,
}

/// The result of a campaign over the core sources with the digest `core`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Receipt {
    core: String,
    kani: String,
    cargo_mutants: String,
    mutants: Vec<Verdict>,
}

#[derive(Debug, Clone, Deserialize)]
struct EquivalentMutant {
    #[serde(flatten)]
    key: Key,
    reason: String,
}

#[derive(Debug, Clone, Deserialize)]
struct EquivalentList {
    equivalent: Vec<EquivalentMutant>,
}

/// What one Kani run showed about a mutant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Run {
    Detected(String),
    Proved,
    Unviable,
    Inconclusive(String),
}

/// The byte offset of `position` in `text`.
fn offset(text: &str, position: Position) -> Result<usize, Failure> {
    let invalid = || {
        Failure::new(format!(
            "cargo-mutants named a position outside its file: {position:?}"
        ))
    };
    let mut start = 0;
    let mut lines = text.split_inclusive('\n');
    for _ in 1..position.line {
        start += lines.next().ok_or_else(invalid)?.len();
    }
    let line = lines.next().unwrap_or("");
    let column = position.column.checked_sub(1).ok_or_else(invalid)?;
    let within = line
        .char_indices()
        .map(|(index, _)| index)
        .chain([line.len()])
        .nth(column)
        .ok_or_else(invalid)?;
    Ok(start + within)
}

/// The mutated text, and the original text that the mutant replaces.
fn apply(text: &str, span: Span, replacement: &str) -> Result<(String, String), Failure> {
    let start = offset(text, span.start)?;
    let end = offset(text, span.end)?;
    let original = text.get(start..end).ok_or_else(|| {
        Failure::new(format!(
            "cargo-mutants named an empty or reversed span: {span:?}"
        ))
    })?;
    Ok((
        format!("{}{replacement}{}", &text[..start], &text[end..]),
        original.to_owned(),
    ))
}

/// A top-level inline module that only Kani compiles, such as the harnesses or their symbolic inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KaniModule<'a> {
    name: &'a str,
    /// The lines from its attribute to its closing brace, counting from one.
    lines: RangeInclusive<usize>,
}

/// The modules of `text` that only Kani compiles, and the number of Kani-only attributes in it.
///
/// rustfmt closes a top-level inline module with a `}` alone at the start of a line, which is where each module ends.
/// An attribute that the scan can't place on such a module counts as well, so a caller can refuse it.
fn kani_modules(text: &str) -> (Vec<KaniModule<'_>>, usize) {
    let lines = text.lines().collect::<Vec<_>>();
    let attributes = lines.iter().filter(|line| **line == KANI_ONLY).count();
    let mut modules = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index] != KANI_ONLY {
            index += 1;
            continue;
        }
        let mut declaration = index + 1;
        while lines
            .get(declaration)
            .is_some_and(|line| line.starts_with("#["))
        {
            declaration += 1;
        }
        let name = lines.get(declaration).and_then(|line| {
            line.trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ")
                .strip_prefix("mod ")?
                .strip_suffix(" {")
        });
        let close = lines
            .iter()
            .skip(declaration)
            .position(|line| *line == "}")
            .map(|offset| declaration + offset);
        match (name, close) {
            (Some(name), Some(close)) => {
                modules.push(KaniModule {
                    name,
                    lines: index + 1..=close + 1,
                });
                index = close + 1;
            }
            _ => index += 1,
        }
    }
    (modules, attributes)
}

/// Whether the campaign mutates `listed` in `text`: never inside a module that only Kani compiles, and never a negative control.
fn mutable(listed: &Listed, text: &str) -> bool {
    let (modules, _) = kani_modules(text);
    let in_kani_module = modules
        .iter()
        .any(|module| module.lines.contains(&listed.span.start.line));
    let in_control = listed
        .function
        .as_ref()
        .is_some_and(|function| function.function_name.contains(NEGATIVE_CONTROL));
    !in_kani_module && !in_control
}

/// The filter that selects the harnesses of the module that `file` holds.
fn module_harnesses(file: &str) -> String {
    match Path::new(file).file_stem().and_then(|stem| stem.to_str()) {
        Some("lib") | None => "proofs::".to_owned(),
        Some(module) => format!("{module}::proofs::"),
    }
}

/// The harness filters that a mutant of `package` in `file` runs through, one bounded run each: its own module's first, then every other module of its package.
fn filters_for(modules: &[Module], package: &str, file: &str) -> Vec<String> {
    let own = module_harnesses(file);
    let mut filters = modules
        .iter()
        .filter(|module| module.package == package)
        .map(|module| module.filter.clone())
        .collect::<Vec<_>>();
    filters.sort_by_key(|filter| *filter != own);
    filters
}

/// What a Kani run with the exit `exit` and the export `report` showed.
fn classify(exit: &Exit, report: Option<&ProofReport>) -> Run {
    let Some(report) = report else {
        return if exit.stderr.contains("could not compile")
            || exit.stdout.contains("could not compile")
        {
            Run::Unviable
        } else {
            Run::Inconclusive(format!("no report after exit {:?}", exit.code))
        };
    };
    if let Some(harness) = report.unproved(&HARNESSES).into_iter().next() {
        return Run::Detected(harness);
    }
    if report.executed() == 0 {
        return Run::Inconclusive("the run executed no harness".to_owned());
    }
    match exit.code {
        Some(0) => Run::Proved,
        code => Run::Inconclusive(format!("exit {code:?} although every harness proved")),
    }
}

/// Run Kani for one mutant of `package`, from the work copy, with the harness `filter`, and read what it showed.
fn try_mutant(
    container: &Container,
    mounts: &Mounts<'_>,
    package: &str,
    filter: &str,
    name: &str,
) -> Result<Run, Failure> {
    let reports = mounts.evidence.join("mutants");
    let export = format!("/evidence/mutants/{name}.json");
    let command = [
        "cargo",
        "kani",
        "--package",
        package,
        "--fail-fast",
        "--harness",
        filter,
        "-Z",
        "unstable-options",
        "--export-json",
        &export,
    ];
    let exit = match container.run(mounts, &[("CARGO_TARGET_DIR", TARGET_DIRECTORY)], &command) {
        Ok(exit) => exit,
        Err(failure) => return Ok(Run::Inconclusive(failure.to_string())),
    };
    keep_logs(&reports, name, &exit.stdout, &exit.stderr)?;
    let report = read_report(&reports, name).ok();
    Ok(classify(&exit, report.as_ref()))
}

/// One part of a campaign: the mutants whose position in the campaign's listing leaves `index` after division by `count`.
///
/// Shards run side by side in their own containers, and `merge` joins their verdicts into one receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shard {
    index: usize,
    count: usize,
}

impl Shard {
    /// The shard with `index` among `count` shards, which needs `index` below `count`.
    pub fn new(index: usize, count: usize) -> Result<Self, Failure> {
        if index >= count {
            return Err(Failure::new(format!(
                "a campaign of {count} shards has no shard {index}"
            )));
        }
        Ok(Self { index, count })
    }

    /// Whether this shard tries the mutant at `position` of the listing.
    fn holds(self, position: usize) -> bool {
        position % self.count == self.index
    }
}

/// The verdict on the mutant at `position` of the campaign's listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Placed {
    position: usize,
    #[serde(flatten)]
    verdict: Verdict,
}

/// What one shard of a campaign found, which `merge` joins with the other shards' findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Partial {
    core: String,
    kani: String,
    cargo_mutants: String,
    shard: Shard,
    /// How many mutants the whole campaign tries.
    mutants: usize,
    /// The digest of their names in listing order, so every shard tried the same listing.
    listing: String,
    verdicts: Vec<Placed>,
}

/// The digest of mutant `names` in order, each framed by its length.
fn listing_digest<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for name in names {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Run every mutant of the core crates through the harnesses, or the mutants of one shard, and write the receipt of the campaign or of the shard.
pub fn run(root: &Path, shard: Option<Shard>) -> Result<(), Failure> {
    let evidence = crate::container::evidence_directory(root, "proof-mutants")?;
    println!("mutation evidence: {}", evidence.display());
    let source = SourceSnapshot::capture(root, &evidence)?;
    let core = digest_of(source.path(), &CORE)?;
    let container = Container::build(root, &evidence, "verification/kani.Dockerfile")?;
    let snapshot = Mounts {
        workspace: source.path(),
        evidence: &evidence,
        network: true,
    };
    let version = container.output(source.path(), &evidence, &["cargo", "mutants", "--version"])?;
    if !version.contains(MUTANTS_VERSION) {
        return Err(Failure::new(format!(
            "the image runs another cargo-mutants release: {version}"
        )));
    }
    let mut list = vec!["cargo", "mutants", "--list", "--json"];
    for package in CORE_PACKAGES {
        list.extend(["--package", package]);
    }
    let listed = container.run(&snapshot, &[], &list)?;
    let listed: Vec<Listed> = serde_json::from_str(&listed.stdout)
        .map_err(|error| Failure::new(format!("cargo-mutants listed no JSON: {error}")))?;

    // The campaign means nothing unless the unmutated core proves.
    let modules = admit_every_harness(&container, &snapshot, &source, root, "baseline")?;
    println!("the unmutated core proves; {} mutants listed", listed.len());

    let work = evidence.join("work");
    copy_roots(source.path(), &roots(), &work)?;
    fs::create_dir(evidence.join("mutants")).map_err(Failure::io)?;
    let working = Mounts {
        workspace: &work,
        evidence: &evidence,
        network: true,
    };
    let mut candidates = Vec::new();
    for mutant in &listed {
        let text = fs::read_to_string(source.path().join(&mutant.file)).map_err(Failure::io)?;
        if mutable(mutant, &text) {
            candidates.push((mutant, text));
        }
    }
    let listing = listing_digest(candidates.iter().map(|(mutant, _)| mutant.name.as_str()));
    let mut verdicts = Vec::new();
    let mut inconclusive = Vec::new();
    for (position, (mutant, text)) in candidates.iter().enumerate() {
        if shard.is_some_and(|shard| !shard.holds(position)) {
            continue;
        }
        let path = work.join(&mutant.file);
        let (mutated, original) = apply(text, mutant.span, &mutant.replacement)?;
        let key = Key {
            file: mutant.file.clone(),
            function: mutant
                .function
                .as_ref()
                .map_or_else(String::new, |function| function.function_name.clone()),
            original,
            replacement: mutant.replacement.clone(),
        };
        fs::write(&path, mutated).map_err(Failure::io)?;
        let filters = filters_for(&modules, &mutant.package, &mutant.file);
        let mut outcome = Run::Inconclusive("its package has no harness".to_owned());
        for (attempt, filter) in filters.iter().enumerate() {
            outcome = try_mutant(
                &container,
                &working,
                &mutant.package,
                filter,
                &format!("{position:03}-{attempt:02}"),
            )?;
            if outcome != Run::Proved {
                break;
            }
        }
        fs::write(&path, text).map_err(Failure::io)?;
        println!("{}: {outcome:?}", mutant.name);
        let verdict = |outcome, detected_by| Verdict {
            key,
            outcome,
            detected_by,
        };
        match outcome {
            Run::Detected(harness) => verdicts.push(Placed {
                position,
                verdict: verdict(Outcome::Detected, Some(harness)),
            }),
            Run::Unviable => verdicts.push(Placed {
                position,
                verdict: verdict(Outcome::Unviable, None),
            }),
            Run::Proved => verdicts.push(Placed {
                position,
                verdict: verdict(Outcome::Survived, None),
            }),
            Run::Inconclusive(reason) => inconclusive.push(format!("{}: {reason}", mutant.name)),
        }
        // The verdicts so far stay in the evidence, so a campaign that stops early still shows what it found.
        let progress = serde_json::json!({ "mutants": &verdicts, "inconclusive": &inconclusive });
        write_json(&evidence.join("verdicts.json"), &progress)?;
    }
    if !inconclusive.is_empty() {
        return Err(Failure::new(format!(
            "{} mutants ended without a verdict, so the campaign proves nothing about them:\n{}",
            inconclusive.len(),
            inconclusive.join("\n")
        )));
    }
    if !source.matches(root)? {
        return Err(Failure::new("the sources changed during the campaign"));
    }
    let partial = Partial {
        core,
        kani: KANI_VERSION.to_owned(),
        cargo_mutants: MUTANTS_VERSION.to_owned(),
        shard: shard.unwrap_or(Shard { index: 0, count: 1 }),
        mutants: candidates.len(),
        listing,
        verdicts,
    };
    if let Some(shard) = shard {
        let written = evidence.join(format!(
            "proof-mutants-shard-{}-of-{}.json",
            shard.index, shard.count
        ));
        write_json(&written, &partial)?;
        println!(
            "shard {}/{} tried {} of {} mutants; merge the receipts of every shard with `cargo xtask proof-mutants merge`: {}",
            shard.index,
            shard.count,
            partial.verdicts.len(),
            partial.mutants,
            written.display()
        );
        return Ok(());
    }
    let receipt = combine(vec![partial], &digest_of(root, &CORE)?)?;
    finish(root, &evidence, &receipt)
}

/// Join the receipts of every shard of one campaign, read from `paths`, into the receipt of the campaign.
pub fn merge(root: &Path, paths: &[&str]) -> Result<(), Failure> {
    let mut partials = Vec::new();
    for path in paths {
        let text = fs::read_to_string(path).map_err(Failure::io)?;
        partials.push(
            serde_json::from_str::<Partial>(&text)
                .map_err(|error| Failure::new(format!("{path} is no shard receipt: {error}")))?,
        );
    }
    let receipt = combine(partials, &digest_of(root, &CORE)?)?;
    let evidence = crate::container::evidence_directory(root, "proof-mutants")?;
    finish(root, &evidence, &receipt)
}

/// The receipt of a campaign over the core sources with the digest `core`, from the findings of all its shards.
///
/// Every shard has to come from the same sources, tools, and listing, each shard exactly once, and together they have to try every mutant exactly once.
fn combine(partials: Vec<Partial>, core: &str) -> Result<Receipt, Failure> {
    let first = partials
        .first()
        .ok_or_else(|| Failure::new("name the receipt of every shard"))?;
    let (count, mutants, listing) = (first.shard.count, first.mutants, first.listing.clone());
    let (kani, cargo_mutants) = (first.kani.clone(), first.cargo_mutants.clone());
    let mut shards = BTreeSet::new();
    let mut placed = vec![None; mutants];
    for partial in partials {
        if partial.core != core {
            return Err(Failure::new(
                "a shard covers other core sources than these, so its campaign has to run again",
            ));
        }
        if (&partial.kani, &partial.cargo_mutants) != (&kani, &cargo_mutants)
            || (partial.shard.count, partial.mutants, &partial.listing)
                != (count, mutants, &listing)
        {
            return Err(Failure::new(
                "the shards come from different tools or listings",
            ));
        }
        if !shards.insert(partial.shard.index) {
            return Err(Failure::new(format!(
                "shard {}/{count} appears twice",
                partial.shard.index
            )));
        }
        for Placed { position, verdict } in partial.verdicts {
            let slot = placed
                .get_mut(position)
                .filter(|slot| partial.shard.holds(position) && slot.is_none())
                .ok_or_else(|| {
                    Failure::new(format!(
                        "shard {}/{count} names mutant {position}, which isn't its own or appears twice",
                        partial.shard.index
                    ))
                })?;
            *slot = Some(verdict);
        }
    }
    if shards.len() != count {
        return Err(Failure::new(format!(
            "the campaign has {count} shards, but only {} receipts",
            shards.len()
        )));
    }
    let mutants = placed
        .into_iter()
        .enumerate()
        .map(|(position, verdict)| {
            verdict.ok_or_else(|| Failure::new(format!("no shard tried mutant {position}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Receipt {
        core: core.to_owned(),
        kani,
        cargo_mutants,
        mutants,
    })
}

/// Write the campaign's receipt into `evidence`, report its outcomes, and check it against the equivalent list.
fn finish(root: &Path, evidence: &Path, receipt: &Receipt) -> Result<(), Failure> {
    let written = evidence.join("proof-mutants.json");
    write_json(&written, receipt)?;
    let count = |outcome| {
        receipt
            .mutants
            .iter()
            .filter(|verdict| verdict.outcome == outcome)
            .count()
    };
    println!(
        "a harness detected {} mutants, {} didn't compile, and {} survived; the receipt is {}",
        count(Outcome::Detected),
        count(Outcome::Unviable),
        count(Outcome::Survived),
        written.display()
    );
    // The receipt holds every outcome either way, so a survivor that the list later explains needs no new campaign.
    verify_receipt(receipt, &receipt.core, &equivalent_keys(root)?)?;
    println!("commit the receipt as {RECEIPT}");
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), Failure> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| Failure::new(error.to_string()))?,
    )
    .map_err(Failure::io)
}

/// The keys of the committed equivalent list, refusing an entry without a reason.
fn equivalent_keys(root: &Path) -> Result<BTreeSet<Key>, Failure> {
    let text = fs::read_to_string(root.join(EQUIVALENT)).map_err(Failure::io)?;
    let list: EquivalentList = serde_json::from_str(&text)
        .map_err(|error| Failure::new(format!("{EQUIVALENT} is unreadable: {error}")))?;
    if let Some(entry) = list
        .equivalent
        .iter()
        .find(|entry| entry.reason.trim().is_empty())
    {
        return Err(Failure::new(format!(
            "{EQUIVALENT} lists {:?} without a reason",
            entry.key
        )));
    }
    Ok(list.equivalent.into_iter().map(|entry| entry.key).collect())
}

/// Check that the committed receipt covers the core sources of the repository at `root` and leaves no mutant unexplained.
pub fn check(root: &Path) -> Result<(), Failure> {
    let text = fs::read_to_string(root.join(RECEIPT)).map_err(Failure::io)?;
    let receipt: Receipt = serde_json::from_str(&text)
        .map_err(|error| Failure::new(format!("{RECEIPT} is unreadable: {error}")))?;
    verify_receipt(&receipt, &digest_of(root, &CORE)?, &equivalent_keys(root)?)?;
    println!(
        "{RECEIPT} covers the core sources: {} mutants, each detected by a harness, unviable, or explained",
        receipt.mutants.len()
    );
    Ok(())
}

fn verify_receipt(
    receipt: &Receipt,
    core: &str,
    equivalent: &BTreeSet<Key>,
) -> Result<(), Failure> {
    if receipt.core != core {
        return Err(Failure::new(format!(
            "{RECEIPT} covers other core sources than these; run `cargo xtask proof-mutants` and commit its receipt"
        )));
    }
    if receipt.kani != KANI_VERSION || receipt.cargo_mutants != MUTANTS_VERSION {
        return Err(Failure::new(format!(
            "{RECEIPT} comes from Kani {} and cargo-mutants {}, not the pinned releases",
            receipt.kani, receipt.cargo_mutants
        )));
    }
    if !receipt
        .mutants
        .iter()
        .any(|verdict| verdict.outcome == Outcome::Detected)
    {
        return Err(Failure::new(format!("{RECEIPT} shows no detected mutant")));
    }
    let survived = receipt
        .mutants
        .iter()
        .filter(|verdict| verdict.outcome == Outcome::Survived)
        .map(|verdict| verdict.key.clone())
        .collect::<BTreeSet<_>>();
    if &survived != equivalent {
        let unexplained = survived.difference(equivalent).collect::<Vec<_>>();
        let stale = equivalent.difference(&survived).collect::<Vec<_>>();
        return Err(Failure::new(format!(
            "every harness admitted {} mutants that {EQUIVALENT} doesn't explain: {unexplained:#?}\nand it lists {} that don't survive: {stale:#?}",
            unexplained.len(),
            stale.len()
        )));
    }
    if receipt
        .mutants
        .iter()
        .any(|verdict| (verdict.outcome == Outcome::Detected) != verdict.detected_by.is_some())
    {
        return Err(Failure::new(format!(
            "{RECEIPT} names a detecting harness only for some detected mutants"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use std::fs;
    use std::path::Path;

    use super::{
        CORE, Function, KaniModule, Key, Listed, Module, Outcome, Partial, Placed, Position,
        Receipt, Run, Shard, Span, Verdict, apply, classify, combine, filters_for, kani_modules,
        listing_digest, module_harnesses, mutable, verify_receipt,
    };
    use crate::container::Exit;
    use crate::proof_report::{KANI_VERSION, ProofReport};

    const TEXT: &str = "fn decide(a: bool) -> bool {\n    a && true\n}\n\n#[cfg(kani)]\nmod proofs {\n    const N: usize = 1 + 2;\n}\n";

    /// Symbolic inputs for the harnesses, ahead of a decision that the campaign mutates.
    const SYMBOLIC: &str = "#[cfg(kani)]\n#[allow(dead_code)]\npub(crate) mod symbolic {\n    pub(crate) fn any() -> u8 {\n        1 + 2\n    }\n}\n\nfn after(a: u8) -> u8 {\n    a + 1\n}\n";

    fn span(start: (usize, usize), end: (usize, usize)) -> Span {
        Span {
            start: Position {
                line: start.0,
                column: start.1,
            },
            end: Position {
                line: end.0,
                column: end.1,
            },
        }
    }

    fn listed(span: Span, function: Option<&str>) -> Listed {
        Listed {
            file: "crates/release-glz-core/src/run.rs".to_owned(),
            package: "release-glz-core".to_owned(),
            span,
            replacement: "||".to_owned(),
            function: function.map(|name| Function {
                function_name: name.to_owned(),
            }),
            name: "a mutant".to_owned(),
        }
    }

    #[test]
    fn a_mutant_replaces_exactly_its_span() {
        let (mutated, original) = apply(TEXT, span((2, 7), (2, 9)), "||").unwrap();
        assert_eq!(original, "&&");
        assert!(mutated.contains("    a || true\n"));
        assert_eq!(mutated.len(), TEXT.len());

        let (mutated, original) = apply(TEXT, span((1, 28), (3, 1)), "{ false ").unwrap();
        assert_eq!(original, "{\n    a && true\n");
        assert!(mutated.starts_with("fn decide(a: bool) -> bool { false }"));

        assert!(apply(TEXT, span((2, 9), (2, 7)), "").is_err());
        assert!(apply(TEXT, span((40, 1), (40, 2)), "").is_err());
    }

    #[test]
    fn the_campaign_leaves_out_harnesses_and_negative_controls() {
        assert!(mutable(&listed(span((2, 7), (2, 9)), Some("decide")), TEXT));
        assert!(!mutable(&listed(span((7, 24), (7, 25)), None), TEXT));
        assert!(!mutable(
            &listed(span((2, 7), (2, 9)), Some("negative_control_skip_ahead")),
            TEXT
        ));
    }

    #[test]
    fn a_module_that_only_kani_compiles_ends_at_its_closing_brace() {
        assert_eq!(
            kani_modules(SYMBOLIC),
            (
                vec![KaniModule {
                    name: "symbolic",
                    lines: 1..=7,
                }],
                1
            )
        );
        assert!(!mutable(
            &listed(span((5, 11), (5, 12)), Some("symbolic::any")),
            SYMBOLIC
        ));
        assert!(mutable(
            &listed(span((10, 7), (10, 8)), Some("after")),
            SYMBOLIC
        ));
        let item = "#[cfg(kani)]\nfn helper() {}\n";
        assert_eq!(kani_modules(item), (Vec::new(), 1));
    }

    /// A test build never compiles a module that only Kani compiles, so cargo-mutants has to leave each of them out.
    #[test]
    fn the_mutation_config_leaves_out_every_module_that_only_kani_compiles() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let config = fs::read_to_string(root.join(".cargo/mutants.toml")).unwrap();
        let mut names = BTreeSet::new();
        for core in CORE {
            for entry in fs::read_dir(root.join(core).join("src")).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_none_or(|extension| extension != "rs") {
                    continue;
                }
                let text = fs::read_to_string(&path).unwrap();
                let (modules, attributes) = kani_modules(&text);
                assert_eq!(
                    modules.len(),
                    attributes,
                    "{} puts `#[cfg(kani)]` on something other than a top-level inline module",
                    path.display()
                );
                names.extend(modules.iter().map(|module| module.name.to_owned()));
            }
        }
        assert!(names.contains("proofs") && names.contains("symbolic"));
        for name in names {
            assert!(
                config.contains(&format!("\"{name}::\"")),
                ".cargo/mutants.toml leaves the Kani-only module `{name}` among the mutants of a test build"
            );
        }
    }

    #[test]
    fn each_mutant_runs_the_harnesses_of_its_own_module() {
        assert_eq!(
            module_harnesses("crates/release-glz-core/src/run.rs"),
            "run::proofs::"
        );
        assert_eq!(
            module_harnesses("crates/assurance-core/src/lib.rs"),
            "proofs::"
        );
    }

    #[test]
    fn a_mutant_runs_its_own_module_first_and_then_every_other_module_of_its_package() {
        let module = |package, filter: &str| Module {
            package,
            filter: filter.to_owned(),
            harnesses: Vec::new(),
        };
        let modules = [
            module("assurance-core", "proofs::"),
            module("release-glz-core", "approval::proofs::"),
            module("release-glz-core", "run::proofs::"),
            module("release-glz-core", "version::proofs::"),
        ];
        assert_eq!(
            filters_for(
                &modules,
                "release-glz-core",
                "crates/release-glz-core/src/run.rs"
            ),
            ["run::proofs::", "approval::proofs::", "version::proofs::"]
        );
        assert_eq!(
            filters_for(
                &modules,
                "release-glz-core",
                "crates/release-glz-core/src/lib.rs"
            ),
            ["approval::proofs::", "run::proofs::", "version::proofs::"]
        );
        assert_eq!(
            filters_for(
                &modules,
                "assurance-core",
                "crates/assurance-core/src/lib.rs"
            ),
            ["proofs::"]
        );
        assert!(filters_for(&modules, "other", "crates/other/src/lib.rs").is_empty());
    }

    fn exit(code: Option<i32>, stderr: &str) -> Exit {
        Exit {
            code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }

    #[test]
    fn an_outcome_comes_from_the_report_and_never_from_the_exit_alone() {
        let proved: ProofReport =
            serde_json::from_str(include_str!("../tests/fixtures/kani.json")).unwrap();
        let failed: ProofReport =
            serde_json::from_str(include_str!("../tests/fixtures/kani-control.json")).unwrap();
        assert!(matches!(
            classify(&exit(Some(1), ""), Some(&failed)),
            Run::Detected(_)
        ));
        assert_eq!(
            classify(
                &exit(Some(1), "error: could not compile `release-glz-core`"),
                None
            ),
            Run::Unviable
        );
        assert!(matches!(
            classify(&exit(Some(137), ""), None),
            Run::Inconclusive(_)
        ));
        assert!(matches!(
            classify(&exit(Some(1), ""), Some(&proved)),
            Run::Inconclusive(_)
        ));
    }

    fn key(original: &str) -> Key {
        Key {
            file: "crates/release-glz-core/src/run.rs".to_owned(),
            function: "decide".to_owned(),
            original: original.to_owned(),
            replacement: "||".to_owned(),
        }
    }

    fn receipt(outcomes: &[(Outcome, &str)]) -> Receipt {
        Receipt {
            core: "digest".to_owned(),
            kani: KANI_VERSION.to_owned(),
            cargo_mutants: "27.1.0".to_owned(),
            mutants: outcomes
                .iter()
                .map(|(outcome, original)| Verdict {
                    key: key(original),
                    outcome: *outcome,
                    detected_by: (*outcome == Outcome::Detected).then(|| "a harness".to_owned()),
                })
                .collect(),
        }
    }

    #[test]
    fn the_gate_refuses_a_stale_or_unexplained_receipt() {
        let equivalent = BTreeSet::from([key("&&")]);
        let good = receipt(&[(Outcome::Detected, "=="), (Outcome::Survived, "&&")]);
        verify_receipt(&good, "digest", &equivalent).unwrap();
        assert!(verify_receipt(&good, "other", &equivalent).is_err());
        assert!(verify_receipt(&good, "digest", &BTreeSet::new()).is_err());
        let unexplained = receipt(&[(Outcome::Detected, "=="), (Outcome::Survived, "!")]);
        assert!(verify_receipt(&unexplained, "digest", &equivalent).is_err());
        let nothing_detected = receipt(&[(Outcome::Unviable, "==")]);
        assert!(verify_receipt(&nothing_detected, "digest", &BTreeSet::new()).is_err());
        let mut old = good.clone();
        old.cargo_mutants = "26.0.0".to_owned();
        assert!(verify_receipt(&old, "digest", &equivalent).is_err());
    }

    #[test]
    fn a_shard_names_its_part_of_the_mutants_and_every_mutant_falls_in_one_shard() {
        assert_eq!(Shard::new(0, 1).unwrap(), Shard { index: 0, count: 1 });
        assert_eq!(Shard::new(2, 3).unwrap(), Shard { index: 2, count: 3 });
        for (index, count) in [(3, 3), (1, 0), (0, 0)] {
            assert!(Shard::new(index, count).is_err(), "{index}/{count}");
        }
        for position in 0..20 {
            let holders = (0..4)
                .filter(|index| {
                    Shard {
                        index: *index,
                        count: 4,
                    }
                    .holds(position)
                })
                .count();
            assert_eq!(holders, 1, "{position}");
        }
    }

    /// The findings of a shard of `count` over `mutants` mutants, with the outcome of each of its positions.
    fn partial(index: usize, count: usize, mutants: usize, core: &str) -> Partial {
        let shard = Shard { index, count };
        Partial {
            core: core.to_owned(),
            kani: KANI_VERSION.to_owned(),
            cargo_mutants: "27.1.0".to_owned(),
            shard,
            mutants,
            listing: listing_digest(["a", "b", "c"].into_iter()),
            verdicts: (0..mutants)
                .filter(|position| shard.holds(*position))
                .map(|position| Placed {
                    position,
                    verdict: Verdict {
                        key: key(&position.to_string()),
                        outcome: Outcome::Detected,
                        detected_by: Some("a harness".to_owned()),
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn the_shards_of_a_campaign_join_into_its_receipt_only_when_they_try_each_mutant_once() {
        let joined = combine(
            vec![partial(1, 2, 5, "digest"), partial(0, 2, 5, "digest")],
            "digest",
        )
        .unwrap();
        let originals = joined
            .mutants
            .iter()
            .map(|verdict| verdict.key.original.as_str())
            .collect::<Vec<_>>();
        assert_eq!(originals, ["0", "1", "2", "3", "4"]);

        let missing = combine(vec![partial(0, 2, 5, "digest")], "digest");
        assert!(missing.is_err());
        let twice = combine(
            vec![partial(0, 2, 5, "digest"), partial(0, 2, 5, "digest")],
            "digest",
        );
        assert!(twice.is_err());
        let stale = combine(
            vec![partial(0, 2, 5, "old"), partial(1, 2, 5, "old")],
            "digest",
        );
        assert!(stale.is_err());
        let mut other_listing = partial(1, 2, 5, "digest");
        other_listing.listing = listing_digest(["a", "b"].into_iter());
        assert!(combine(vec![partial(0, 2, 5, "digest"), other_listing], "digest").is_err());
        let mut foreign = partial(1, 2, 5, "digest");
        foreign.verdicts[0].position = 0;
        assert!(combine(vec![partial(0, 2, 5, "digest"), foreign], "digest").is_err());
        let mut short = partial(1, 2, 5, "digest");
        short.verdicts.pop();
        assert!(combine(vec![partial(0, 2, 5, "digest"), short], "digest").is_err());
        assert!(combine(Vec::new(), "digest").is_err());
    }

    #[test]
    fn the_listing_digest_frames_each_name() {
        assert_ne!(
            listing_digest(["ab", "c"].into_iter()),
            listing_digest(["a", "bc"].into_iter())
        );
    }
}
