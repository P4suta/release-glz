use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use release_glz_test_support::fs;

/// The one compiler release whose Windows Hex export the compatibility fallback recovers from, which shipping assurance keeps running natively.
const WINDOWS_HEX_TARBALL_REGRESSION: &str = "1.18.1";

fn pinned_tool(tool: &str) -> String {
    let manifest = fs::read_to_string("mise.toml")
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let pin = &manifest["tools"][tool];
    pin.as_str()
        .or_else(|| pin.get("version").and_then(toml_edit::Item::as_str))
        .unwrap_or_else(|| panic!("mise.toml pins no {tool}"))
        .to_owned()
}

#[test]
fn routine_ci_uses_one_selected_linux_gate_without_shipping_campaigns() {
    let yaml = fs::read_to_string(".github/workflows/ci.yml");
    let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    let triggers = parsed["on"].as_mapping().unwrap();
    assert!(triggers.contains_key("pull_request"));
    assert!(triggers.contains_key("merge_group"));
    assert!(!triggers.contains_key("push"));
    assert!(!triggers.contains_key("schedule"));
    assert_eq!(
        parsed["concurrency"]["cancel-in-progress"].as_bool(),
        Some(true)
    );
    assert_eq!(
        parsed["jobs"]["checks"]["runs-on"].as_str(),
        Some("ubuntu-24.04")
    );
    assert!(parsed["jobs"]["checks"]["strategy"].is_null());
    for campaign in ["cargo mutants", "cargo fuzz", "cargo llvm-cov"] {
        assert!(!yaml.contains(campaign), "routine CI starts {campaign}");
    }
}

#[test]
fn assurance_workflow_has_fixed_fail_closed_shipping_gates() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml");
    serde_norway::from_str::<serde_norway::Value>(&yaml).unwrap();
    for required in [
        "cargo-deny --version 0.20.2",
        "cargo-audit --version 0.22.2",
        "cargo-machete --version 0.9.2",
        "cargo-mutants --version 27.1.0",
        "cargo-nextest-0.9.140-x86_64-unknown-linux-gnu.tar.gz",
        "4ee9aaa0d0171a985a5d0eb735b87355894c1c455972e9674fb9fdbd1387c9a3",
        "cargo-llvm-cov --version 0.9.0",
        "cargo-fuzz --version 0.13.2",
        "run: cargo xtask proofs",
        "run: cargo xtask lean",
        "run: cargo xtask quint",
        "run: cargo xtask trace",
        "run: cargo xtask proof-mutants check",
        "cargo deny check -D warnings",
        "cargo audit -D warnings",
        "cargo audit -D warnings --file fuzz/Cargo.lock",
        "cargo machete",
        "cargo llvm-cov",
        "--branch --json",
        "scripts/check-coverage.js --lines 90 --branches 85",
        "cargo mutants --in-place --test-tool nextest",
        "src/version.rs",
        "src/registry.rs",
        "src/artifact.rs",
        "src/reconciler.rs",
        "--test-workspace=true",
        "actionlint",
        "zizmor",
        "rustup toolchain install 1.97.0 --profile minimal",
        "cargo +1.97.0 install --locked zizmor --version",
        "run: cargo xtask check --workflows",
    ] {
        assert!(
            yaml.contains(required),
            "missing assurance gate: {required}"
        );
    }
    assert!(yaml.contains("nightly-2026-08-22"));
    assert!(!yaml.contains("nightly-2026-07-15"));
    assert!(yaml.contains("permissions: {}"));
    assert!(!yaml.contains("cargo mutants --jobs"));
    assert!(!yaml.contains("RELEASE_GLZ_ACTION_SHA"));
    assert!(!yaml.contains("cargo install --locked zizmor --version"));
    assert!(!yaml.contains("continue-on-error: true"));
    // The proof, model, and theorem jobs run audited tasks, so nothing in the workflow reads a verifier's text output.
    for text_check in [
        "cargo kani",
        "Failed Checks",
        "cover properties satisfied",
        "depends on axioms",
        "negative-control-",
        "quint verify",
        "lean -",
    ] {
        assert!(!yaml.contains(text_check), "the gate parses {text_check}");
    }
    // Without --workspace, cargo-mutants mutates no file of another workspace member, so listing one claims coverage that never runs.
    assert!(
        !yaml.contains("--file crates/"),
        "the mutation job lists a file it can't mutate"
    );
    assert!(fs::is_file(Path::new("tests/fixtures/workflow/gleam.toml")));

    let triggers = yaml
        .split_once("permissions:")
        .expect("assurance workflow must declare permissions")
        .0;
    assert!(triggers.contains("workflow_dispatch:"));
    assert!(triggers.contains("workflow_call:"));
    assert!(!triggers.contains("push:"));
    assert!(!triggers.contains("schedule:"));
    assert!(
        !triggers.contains("pull_request:"),
        "expensive assurance must run on demand or for a release candidate"
    );

    for line in yaml.lines().filter(|line| {
        line.trim_start()
            .trim_start_matches("- ")
            .starts_with("uses:")
    }) {
        let reference = line
            .split_once('@')
            .unwrap_or_else(|| panic!("missing immutable pin: {line}"))
            .1
            .split_whitespace()
            .next()
            .unwrap();
        assert_eq!(reference.len(), 40, "mutable action reference: {line}");
        assert!(reference.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn mutation_gate_uses_four_explicit_fail_closed_shards() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml");
    let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    let mutation = &parsed["jobs"]["mutation"];
    let shards = mutation["strategy"]["matrix"]["shard"]
        .as_sequence()
        .expect("mutation gate must declare an explicit shard matrix")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(shards, ["0/4", "1/4", "2/4", "3/4"]);
    assert_eq!(mutation["strategy"]["fail-fast"].as_bool(), Some(false));
    assert!(
        mutation["name"]
            .as_str()
            .is_some_and(|name| name.contains("matrix.shard"))
    );

    let command = mutation["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|step| step["run"].as_str())
        .find(|run| run.contains("cargo mutants"))
        .expect("mutation command is missing");
    assert!(command.contains("--in-place --test-tool nextest"));
    assert_eq!(
        mutation["env"]["MUTATION_SHARD"].as_str(),
        Some("${{ matrix.shard }}")
    );
    assert!(command.contains("--shard \"$MUTATION_SHARD\""));
    assert!(!command.contains("continue-on-error"));
}

fn fuzz_targets() -> Vec<String> {
    fs::read_to_string("fuzz/Cargo.toml")
        .parse::<toml_edit::DocumentMut>()
        .unwrap()["bin"]
        .as_array_of_tables()
        .expect("the fuzz manifest declares its targets")
        .iter()
        .map(|target| target["name"].as_str().unwrap().to_owned())
        .collect()
}

/// CI runs the same fast gate that `just check` and the push hook run, and no copy of its steps.
#[test]
fn routine_ci_runs_the_one_fast_gate() {
    let parsed: serde_norway::Value =
        serde_norway::from_str(&fs::read_to_string(".github/workflows/ci.yml")).unwrap();
    let commands: Vec<_> = parsed["jobs"]["checks"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|step| step["run"].as_str())
        .collect();
    assert_eq!(commands, ["cargo xtask check"]);
    assert!(
        parsed["jobs"]["checks"]["if"].is_null(),
        "every change can break spelling or formatting, so the gate runs on every change"
    );
}

/// The calls that turn bytes from outside release-glz into a typed value.
const DESERIALIZERS: [&str; 7] = [
    "serde_json::from_slice",
    "serde_json::from_str",
    "serde_json::from_reader",
    "serde_json::from_value",
    "serde_norway::from_",
    "toml_edit::de::from_",
    "DocumentMut>()",
];

/// The parser inventory of the fuzz manifest, which names each function as `file::function`.
#[derive(Debug, Default)]
struct ParserInventory {
    /// The functions whose untrusted input each fuzz target's invariants reach.
    fuzzed: BTreeMap<String, Vec<String>>,
    /// The deserializing functions that need no fuzz target, each with the reason.
    exempt: BTreeMap<String, String>,
}

impl ParserInventory {
    fn of(manifest: &toml_edit::DocumentMut) -> Self {
        let parsers = manifest
            .get("package")
            .and_then(|package| package.get("metadata"))
            .and_then(|metadata| metadata.get("parsers"))
            .expect("the fuzz manifest holds [package.metadata.parsers]");
        let table = |name: &str| {
            parsers
                .get(name)
                .and_then(toml_edit::Item::as_table)
                .unwrap_or_else(|| {
                    panic!("the fuzz manifest holds [package.metadata.parsers.{name}]")
                })
        };
        let fuzzed = table("fuzzed")
            .iter()
            .map(|(target, functions)| {
                let functions = functions
                    .as_array()
                    .unwrap_or_else(|| panic!("`{target}` lists its parsers"))
                    .iter()
                    .map(|function| function.as_str().unwrap().to_owned())
                    .collect();
                (target.to_owned(), functions)
            })
            .collect();
        let exempt = table("exempt")
            .iter()
            .map(|(function, reason)| (function.to_owned(), reason.as_str().unwrap().to_owned()))
            .collect();
        Self { fuzzed, exempt }
    }
}

/// The name of the function that `line` declares, if it declares one.
fn declared_function(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    if let Some(after) = ["pub(crate) ", "pub(super) ", "pub "]
        .iter()
        .find_map(|visibility| rest.strip_prefix(visibility))
    {
        rest = after;
    }
    while let Some(after) = ["const ", "async ", "unsafe "]
        .iter()
        .find_map(|qualifier| rest.strip_prefix(qualifier))
    {
        rest = after;
    }
    let name = rest
        .strip_prefix("fn ")?
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .next()?;
    (!name.is_empty()).then_some(name)
}

/// The modules whose `from_` functions deserialize.
const DESERIALIZING_MODULES: [&str; 3] = ["serde_json", "serde_norway", "toml_edit::de"];

/// The type whose `parse` deserializes a TOML document.
const DOCUMENT: &str = "toml_edit::DocumentMut";

/// The lines of `source` outside `mod tests`.
fn code_lines(source: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut tests_end: Option<String> = None;
    for line in source.lines() {
        if let Some(end) = &tests_end {
            if line == end {
                tests_end = None;
            }
            continue;
        }
        if line.trim() == "mod tests {" {
            let indent = line.len() - line.trim_start().len();
            tests_end = Some(format!("{}}}", " ".repeat(indent)));
            continue;
        }
        lines.push(line);
    }
    lines
}

/// Whether `code` starts a `use` item.
fn starts_use(code: &str) -> bool {
    ["use ", "pub use ", "pub(crate) use "]
        .iter()
        .any(|start| code.starts_with(start))
}

/// The items of a brace group, split at its outermost commas.
fn group_items(group: &str) -> Vec<String> {
    let mut items = vec![String::new()];
    let mut depth = 0_usize;
    for character in group.chars() {
        match character {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(item) = items.last_mut() {
            item.push(character);
        }
    }
    items
}

fn joined(prefix: &str, path: &str) -> String {
    match (prefix.is_empty(), path.is_empty()) {
        (true, _) => path.to_owned(),
        (false, true) => prefix.to_owned(),
        (false, false) => format!("{prefix}::{path}"),
    }
}

/// Each path that the `use` tree `tree` imports below `prefix`, with the name that it takes in the file.
fn imports(prefix: &str, tree: &str) -> Vec<(String, String)> {
    let tree = tree.trim();
    if let Some((head, group)) = tree.split_once('{') {
        let base = joined(prefix, head.trim().trim_end_matches("::"));
        let group = group.trim_end();
        let group = group.strip_suffix('}').unwrap_or(group);
        return group_items(group)
            .iter()
            .flat_map(|item| imports(&base, item))
            .collect();
    }
    if tree.is_empty() {
        return Vec::new();
    }
    let (path, alias) = match tree.split_once(" as ") {
        Some((path, alias)) => (path.trim(), Some(alias.trim())),
        None => (tree, None),
    };
    let path = if path == "self" {
        prefix.to_owned()
    } else {
        joined(prefix, path)
    };
    let name = alias
        .or_else(|| path.rsplit("::").next())
        .unwrap_or_default()
        .to_owned();
    vec![(path, name)]
}

/// A spelling of a deserializer call, which a name imported by a `use` item spells only where no path or method call comes before it.
#[derive(Debug)]
struct Spelling {
    text: String,
    bounded: bool,
}

/// Every spelling of a deserializer call in `lines`: each qualified path, and each name that a `use` item gives a deserializer.
fn spellings(lines: &[&str]) -> Vec<Spelling> {
    let mut spellings: Vec<_> = DESERIALIZERS
        .iter()
        .map(|text| Spelling {
            text: (*text).to_owned(),
            bounded: false,
        })
        .collect();
    let mut item: Option<String> = None;
    for line in lines {
        let code = line.trim();
        let current = match item.take() {
            Some(open) => format!("{open} {code}"),
            None if starts_use(code) => code.to_owned(),
            None => continue,
        };
        if !current.contains(';') {
            item = Some(current);
            continue;
        }
        let tree = current
            .split_once("use ")
            .map_or(current.as_str(), |(_, tree)| tree);
        let tree = tree.split(';').next().unwrap_or_default();
        for (path, name) in imports("", tree) {
            let imported = if DESERIALIZING_MODULES.contains(&path.as_str()) {
                vec![format!("{name}::from_")]
            } else if path == DOCUMENT {
                vec![format!("{name}>()")]
            } else if path == "toml_edit" {
                vec![
                    format!("{name}::de::from_"),
                    format!("{name}::DocumentMut>()"),
                ]
            } else if path.rsplit_once("::").is_some_and(|(module, function)| {
                DESERIALIZING_MODULES.contains(&module) && function.starts_with("from_")
            }) {
                vec![format!("{name}(")]
            } else {
                Vec::new()
            };
            spellings.extend(imported.into_iter().map(|text| Spelling {
                text,
                bounded: true,
            }));
        }
    }
    spellings
}

/// Whether `code` calls a deserializer that one of `spellings` spells.
fn calls_deserializer(code: &str, spellings: &[Spelling]) -> bool {
    spellings.iter().any(|spelling| {
        code.match_indices(&spelling.text).any(|(start, _)| {
            !spelling.bounded
                || code
                    .get(..start)
                    .and_then(|before| before.chars().next_back())
                    .is_none_or(|before| {
                        !(before.is_ascii_alphanumeric() || matches!(before, '_' | ':' | '.'))
                    })
        })
    })
}

/// The part of `text` after the generic parameters that it starts with, if it starts with any.
fn after_generics(text: &str) -> &str {
    if !text.starts_with('<') {
        return text;
    }
    let mut depth = 0_usize;
    let mut previous = ' ';
    for (index, character) in text.char_indices() {
        match character {
            '<' => depth += 1,
            '>' if previous != '-' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return text.get(index + 1..).unwrap_or_default();
                }
            }
            _ => {}
        }
        previous = character;
    }
    ""
}

/// The name of the type or module whose block `code` opens, if it opens an `impl` or a `mod` block.
fn opened_scope(code: &str) -> Option<String> {
    let header = code.strip_prefix("unsafe ").unwrap_or(code);
    if let Some(rest) = header.strip_prefix("impl")
        && (rest.starts_with('<') || rest.starts_with(' '))
    {
        let rest = after_generics(rest.trim_start());
        let rest = rest.split(" where").next().unwrap_or_default();
        let rest = rest.trim_end_matches('{').trim();
        let self_type = rest
            .rsplit_once(" for ")
            .map_or(rest, |(_, type_name)| type_name);
        let name = self_type
            .split('<')
            .next()
            .and_then(|path| path.rsplit("::").next())
            .unwrap_or_default()
            .trim();
        return (!name.is_empty()).then(|| name.to_owned());
    }
    let module = ["mod ", "pub mod ", "pub(crate) mod "]
        .iter()
        .find_map(|start| code.strip_prefix(start))?;
    let name = module.strip_suffix('{')?.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// The functions that a source declares and the functions in it that deserialize, each named by the `mod` and `impl` blocks around it.
#[derive(Debug, Default)]
struct Scan {
    declared: BTreeSet<String>,
    deserializing: BTreeSet<String>,
}

/// The functions that `source` declares and the ones that deserialize, outside comments, `use` items, and `mod tests`.
///
/// A call outside every function counts as `<module>`.
fn scan(source: &str) -> Scan {
    let lines = code_lines(source);
    let spellings = spellings(&lines);
    let mut scan = Scan::default();
    let mut scopes: Vec<(usize, String)> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    let mut function = "<module>".to_owned();
    let mut in_use = false;
    for line in lines {
        let indent = line.len() - line.trim_start().len();
        let code = line.trim();
        if in_use || starts_use(code) {
            in_use = !code.contains(';');
            continue;
        }
        if code.starts_with("//") {
            continue;
        }
        if code.starts_with('}') && scopes.last().is_some_and(|(open, _)| *open == indent) {
            scopes.pop();
        }
        if let Some(name) = opened_scope(code) {
            if code.ends_with('{') {
                scopes.push((indent, name));
            } else {
                pending = Some((indent, name));
            }
            continue;
        }
        if code == "{" && pending.as_ref().is_some_and(|(open, _)| *open == indent) {
            scopes.extend(pending.take());
            continue;
        }
        if let Some(name) = declared_function(line) {
            function = scopes
                .iter()
                .map(|(_, scope)| scope.as_str())
                .chain([name])
                .collect::<Vec<_>>()
                .join("::");
            scan.declared.insert(function.clone());
        }
        if calls_deserializer(code, &spellings) {
            scan.deserializing.insert(function.clone());
        }
    }
    scan
}

/// The `file::function` of each function in `sources` that deserializes, where `function` names the `mod` and `impl` blocks around it.
fn deserializing_functions(sources: &BTreeMap<String, String>) -> BTreeSet<String> {
    sources
        .iter()
        .flat_map(|(file, source)| {
            scan(source)
                .deserializing
                .into_iter()
                .map(move |function| format!("{file}::{function}"))
        })
        .collect()
}

/// What the parser inventory gets wrong about the fuzz `targets` and the `sources` of `src`, in sorted order.
///
/// `read` returns the text of a file in the repository, and `complete` tells whether a target has an invariant module and a seed.
fn inventory_findings(
    inventory: &ParserInventory,
    targets: &BTreeSet<String>,
    sources: &BTreeMap<String, String>,
    read: impl Fn(&str) -> Option<String>,
    complete: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut findings = Vec::new();
    for target in targets {
        if inventory.fuzzed.get(target).is_none_or(Vec::is_empty) {
            findings.push(format!(
                "fuzz target `{target}` names no parser in [package.metadata.parsers.fuzzed]"
            ));
        }
        if !complete(target) {
            findings.push(format!(
                "fuzz target `{target}` lacks an invariant module or a seed"
            ));
        }
    }
    let fuzzed: BTreeSet<&String> = inventory.fuzzed.values().flatten().collect();
    for target in inventory
        .fuzzed
        .keys()
        .filter(|target| !targets.contains(*target))
    {
        findings.push(format!(
            "[package.metadata.parsers.fuzzed] names `{target}`, which isn't a fuzz target"
        ));
    }
    for entry in fuzzed.iter().copied().chain(inventory.exempt.keys()) {
        let declared = entry.split_once(".rs::").is_some_and(|(file, function)| {
            read(&format!("{file}.rs"))
                .is_some_and(|source| scan(&source).declared.contains(function))
        });
        if !declared {
            findings.push(format!("`{entry}` names no function in its file"));
        }
    }
    let sites = deserializing_functions(sources);
    for site in &sites {
        if !fuzzed.contains(site) && !inventory.exempt.contains_key(site) {
            findings.push(format!(
                "`{site}` deserializes bytes without a fuzz target: add a target whose invariants reach it to [package.metadata.parsers.fuzzed], or give the reason it needs none in [package.metadata.parsers.exempt]"
            ));
        }
    }
    for (entry, reason) in &inventory.exempt {
        if !sites.contains(entry) {
            findings.push(format!(
                "the exemption of `{entry}` matches no deserializing call"
            ));
        }
        if reason.trim().is_empty() {
            findings.push(format!("the exemption of `{entry}` gives no reason"));
        }
        if fuzzed.contains(entry) {
            findings.push(format!("`{entry}` is both fuzzed and exempt"));
        }
    }
    findings.sort();
    findings
}

/// Every source file below `src`, by its path relative to the repository.
fn src_sources() -> BTreeMap<String, String> {
    let mut sources = BTreeMap::new();
    let mut pending = vec![Path::new("src").to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if fs::is_dir(&path) {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let shown = path.to_str().unwrap().replace('\\', "/");
                sources.insert(shown, fs::read_to_string(&path));
            }
        }
    }
    sources
}

/// Whether a fuzz target has its invariant module and at least one seed.
fn target_is_complete(target: &str) -> bool {
    let seeds = Path::new("fuzz/corpus").join(target);
    fs::is_file(format!("fuzz/invariants/{target}.rs"))
        && fs::is_dir(&seeds)
        && std::fs::read_dir(&seeds).unwrap().next().is_some()
}

fn parser_inventory() -> ParserInventory {
    ParserInventory::of(&fs::read_to_string("fuzz/Cargo.toml").parse().unwrap())
}

/// Every function in `src` that deserializes bytes has a fuzz target, or an exemption that says why it needs none.
///
/// A new parser fails this test until `fuzz/Cargo.toml` names it, and a removed target fails it for the parsers that the target covered.
#[test]
fn every_untrusted_parser_has_a_fuzz_target_with_invariants_and_seeds() {
    let inventory = parser_inventory();
    let targets: BTreeSet<_> = fuzz_targets().into_iter().collect();
    let sources = src_sources();
    let read = |file: &str| fs::read_to_string_if_present(file);
    let findings = inventory_findings(&inventory, &targets, &sources, read, target_is_complete);
    assert!(findings.is_empty(), "{}", findings.join("\n"));

    let mut without_handoff = targets.clone();
    without_handoff.remove("handoff");
    assert_eq!(
        inventory_findings(
            &inventory,
            &without_handoff,
            &sources,
            read,
            target_is_complete
        ),
        ["[package.metadata.parsers.fuzzed] names `handoff`, which isn't a fuzz target"]
    );
    let mut with_a_new_parser = sources.clone();
    with_a_new_parser.insert(
        "src/notes.rs".to_owned(),
        "pub fn parse_note(text: &str) -> anyhow::Result<Note> {\n    Ok(toml_edit::de::from_str(text)?)\n}\n".to_owned(),
    );
    assert_eq!(
        inventory_findings(
            &inventory,
            &targets,
            &with_a_new_parser,
            read,
            target_is_complete
        ),
        [
            "`src/notes.rs::parse_note` deserializes bytes without a fuzz target: add a target whose invariants reach it to [package.metadata.parsers.fuzzed], or give the reason it needs none in [package.metadata.parsers.exempt]"
        ]
    );
}

#[test]
fn the_parser_inventory_refuses_each_gap_between_targets_parsers_and_seeds() {
    let inventory = ParserInventory {
        fuzzed: BTreeMap::from([
            (
                "notes".to_owned(),
                vec!["src/notes.rs::parse_note".to_owned()],
            ),
            (
                "gone".to_owned(),
                vec!["src/gone.rs::parse_gone".to_owned()],
            ),
        ]),
        exempt: BTreeMap::from([
            (
                "src/cache.rs::read_cache".to_owned(),
                "release-glz wrote the entry".to_owned(),
            ),
            (
                "src/notes.rs::parse_note".to_owned(),
                "duplicated".to_owned(),
            ),
            ("src/stale.rs::old".to_owned(), " ".to_owned()),
        ]),
    };
    let sources = BTreeMap::from([
        (
            "src/notes.rs".to_owned(),
            [
                "pub fn parse_note(text: &str) -> Note {",
                "    toml_edit::de::from_str(text).unwrap()",
                "}",
                "",
                "pub(crate) async fn parse_label(text: &str) -> Label {",
                "    // A comment that names serde_json::from_str isn't a call.",
                "    serde_json::from_str(text).unwrap()",
                "}",
                "",
                "#[cfg(test)]",
                "mod tests {",
                "    fn fixture() -> Note {",
                "        serde_json::from_slice(b\"{}\").unwrap()",
                "    }",
                "}",
            ]
            .join("\n"),
        ),
        (
            "src/cache.rs".to_owned(),
            "use serde_json::from_slice;\n\nfn read_cache(bytes: &[u8]) -> Option<Cache> {\n    serde_json::from_slice(bytes).ok()\n}\n".to_owned(),
        ),
    ]);
    let targets = BTreeSet::from(["notes".to_owned(), "hooks".to_owned()]);
    let findings = inventory_findings(
        &inventory,
        &targets,
        &sources,
        |file| sources.get(file).cloned(),
        |target| target == "notes",
    );
    let unfuzzed = |site: &str| {
        format!(
            "`{site}` deserializes bytes without a fuzz target: add a target whose invariants reach it to [package.metadata.parsers.fuzzed], or give the reason it needs none in [package.metadata.parsers.exempt]"
        )
    };
    let mut expected = vec![
        "fuzz target `hooks` names no parser in [package.metadata.parsers.fuzzed]".to_owned(),
        "fuzz target `hooks` lacks an invariant module or a seed".to_owned(),
        "[package.metadata.parsers.fuzzed] names `gone`, which isn't a fuzz target".to_owned(),
        "`src/gone.rs::parse_gone` names no function in its file".to_owned(),
        "`src/stale.rs::old` names no function in its file".to_owned(),
        unfuzzed("src/notes.rs::parse_label"),
        "the exemption of `src/stale.rs::old` matches no deserializing call".to_owned(),
        "the exemption of `src/stale.rs::old` gives no reason".to_owned(),
        "`src/notes.rs::parse_note` is both fuzzed and exempt".to_owned(),
    ];
    expected.sort();
    assert_eq!(findings, expected);
}

/// A deserializer called through a name that a `use` item gives it is still a call, and a method is named with its type, so two `parse` methods in one file stay apart.
#[test]
fn the_parser_inventory_follows_imported_names_and_tells_methods_of_two_types_apart() {
    let inventory = ParserInventory {
        fuzzed: BTreeMap::from([(
            "candidate".to_owned(),
            vec![
                "src/candidate.rs::CandidateManifest::parse".to_owned(),
                "src/candidate.rs::parse".to_owned(),
            ],
        )]),
        exempt: BTreeMap::new(),
    };
    let sources = BTreeMap::from([(
        "src/candidate.rs".to_owned(),
        [
            "use serde_json as json;",
            "use serde_json::{Value, from_str as parse_json};",
            "use toml_edit::de as toml;",
            "use toml_edit::{",
            "    DocumentMut as Document,",
            "    Item,",
            "};",
            "",
            "impl CandidateManifest {",
            "    pub fn parse(bytes: &[u8]) -> Result<Self> {",
            "        Ok(json::from_slice(bytes)?)",
            "    }",
            "}",
            "",
            "impl<'a> Read for OtherInput<'a>",
            "where",
            "    Self: Sized,",
            "{",
            "    fn parse(text: &str) -> Result<Self> {",
            "        Ok(parse_json(text)?)",
            "    }",
            "}",
            "",
            "mod notes {",
            "    pub(crate) fn note(text: &str) -> Result<Note> {",
            "        Ok(toml::from_str(text)?)",
            "    }",
            "}",
            "",
            "fn manifest(text: &str) -> Result<Item> {",
            "    let document = text.parse::<Document>()?;",
            "    Ok(document.as_item().clone())",
            "}",
            "",
            "fn unrelated(text: &str) -> Version {",
            "    Version::from_str(text).unwrap_or(fallback_json::from_slice(text))",
            "}",
        ]
        .join("\n"),
    )]);
    let targets = BTreeSet::from(["candidate".to_owned()]);
    let findings = inventory_findings(
        &inventory,
        &targets,
        &sources,
        |file| sources.get(file).cloned(),
        |_| true,
    );
    let unfuzzed = |site: &str| {
        format!(
            "`{site}` deserializes bytes without a fuzz target: add a target whose invariants reach it to [package.metadata.parsers.fuzzed], or give the reason it needs none in [package.metadata.parsers.exempt]"
        )
    };
    let mut expected = vec![
        "`src/candidate.rs::parse` names no function in its file".to_owned(),
        unfuzzed("src/candidate.rs::OtherInput::parse"),
        unfuzzed("src/candidate.rs::notes::note"),
        unfuzzed("src/candidate.rs::manifest"),
    ];
    expected.sort();
    assert_eq!(findings, expected);
}

#[test]
fn fuzz_smoke_uses_fixed_run_counts_and_seeds() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml");
    let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    let steps = parsed["jobs"]["fuzz"]["steps"].as_sequence().unwrap();
    for target in fuzz_targets() {
        let prefix = format!("cargo fuzz run {target} -- ");
        let command = steps
            .iter()
            .filter_map(|step| step["run"].as_str())
            .find(|run| run.starts_with(&prefix))
            .unwrap_or_else(|| panic!("missing fuzz command for {target}"));
        for flag in ["-runs=", "-seed="] {
            let value = command
                .split_whitespace()
                .find_map(|word| word.strip_prefix(flag));
            assert!(
                value.is_some_and(|value| value.parse::<u32>().is_ok_and(|value| value > 0)),
                "{target} requires a fixed positive {flag}"
            );
        }
        assert!(!command.contains("-max_total_time="));
    }
}

#[test]
fn dependency_policy_is_explicit_and_deny_by_default() {
    let policy = fs::read_to_string("deny.toml");
    assert!(policy.contains("unknown-registry = \"deny\""));
    assert!(policy.contains("unknown-git = \"deny\""));
    assert!(policy.contains("wildcards = \"deny\""));
    assert!(policy.contains("confidence-threshold = 0.8"));
}

/// A dependency that breaks the license, ban, or source policy fails the pull request that adds it, with the cargo-deny release the release gate runs.
#[test]
fn the_fast_gate_enforces_the_dependency_policy_that_the_release_gate_enforces() {
    let assurance = fs::read_to_string(".github/workflows/assurance.yml");
    let version = assurance
        .split_once("cargo install --locked cargo-deny --version ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .expect("the release gate installs a fixed cargo-deny");
    assert_eq!(pinned_tool("aqua:EmbarkStudios/cargo-deny"), version);
    assert!(assurance.contains("cargo deny check -D warnings"));
}

#[test]
fn release_assurance_covers_native_platforms_and_gleam_versions() {
    let yaml = fs::read_to_string(".github/workflows/ci.yml");
    let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    let assurance = fs::read_to_string(".github/workflows/assurance.yml");
    let shipping: serde_norway::Value = serde_norway::from_str(&assurance).unwrap();
    let current = parsed["jobs"]["checks"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find_map(|step| step["with"]["gleam-version"].as_str())
        .expect("the fast gate must use a fixed Gleam version");
    let matrix = shipping["jobs"]["compatibility"]["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| {
            (
                value["os"].as_str().unwrap(),
                value["gleam"].as_str().unwrap(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        matrix,
        std::collections::BTreeSet::from([
            ("ubuntu-24.04", "1.9.0"),
            ("ubuntu-24.04", "1.12.0"),
            ("ubuntu-24.04", current),
            ("macos-15", current),
            ("windows-2025", current),
            ("windows-2025", WINDOWS_HEX_TARBALL_REGRESSION),
        ])
    );
    assert!(assurance.contains("gleam-version: ${{ matrix.gleam }}"));
    assert!(
        shipping["jobs"]["compatibility"]["steps"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|step| step["run"].as_str()
                == Some("cargo test --workspace --all-targets --locked"))
    );
    assert!(
        parsed["env"]["RUST_TEST_THREADS"].is_null(),
        "the fast gate runs tests in parallel, as developers do"
    );
    let required = &parsed["jobs"]["required"];
    assert_eq!(required["name"].as_str(), Some("required"));
    assert_eq!(required["if"].as_str(), Some("always()"));
    assert_eq!(
        required["needs"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        ["checks"]
    );
    let required_run = required["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find_map(|step| step["run"].as_str())
        .unwrap();
    assert!(required_run.contains("'include \"required\"; required'"));
    assert!(
        shipping["env"]["RUST_TEST_THREADS"].is_null(),
        "shipping assurance runs tests in parallel, as developers do"
    );
}

#[test]
fn every_job_that_runs_compiler_tests_installs_the_pinned_gleam() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml");
    let parsed: serde_norway::Value = serde_norway::from_str(&yaml).unwrap();
    for job in ["coverage", "mutation"] {
        let steps = parsed["jobs"][job]["steps"].as_sequence().unwrap();
        let setup = steps
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("erlef/setup-beam@"))
            })
            .unwrap_or_else(|| {
                panic!("the {job} job must install Gleam, because compiler tests fail without it")
            });

        let reference = setup["uses"].as_str().unwrap().split_once('@').unwrap().1;
        assert_eq!(reference.len(), 40, "Gleam setup action must be immutable");
        assert_eq!(
            setup["with"]["otp-version"].as_str(),
            Some(pinned_tool("erlang").as_str())
        );
        assert_eq!(
            setup["with"]["gleam-version"].as_str(),
            Some(pinned_tool("gleam").as_str())
        );
    }
}

#[test]
fn local_tool_pins_match_the_versions_ci_installs() {
    let pin = pinned_tool;
    let ci = fs::read_to_string(".github/workflows/ci.yml");
    let parsed: serde_norway::Value = serde_norway::from_str(&ci).unwrap();
    let steps = |job: &str| parsed["jobs"][job]["steps"].as_sequence().unwrap().clone();
    let with = |job: &str, action: &str, input: &str| {
        steps(job)
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|value| value.starts_with(action))
            })
            .and_then(|step| step["with"][input].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("{job} sets no {action} {input}"))
    };

    let installed = with("checks", "jdx/mise-action@", "install_args");
    let installed = installed.split_whitespace().collect::<Vec<_>>();
    for tool in [
        "rust",
        "node",
        "taplo",
        "typos",
        "actionlint",
        "jq",
        "aqua:zizmorcore/zizmor",
        "aqua:EmbarkStudios/cargo-deny",
        "aqua:nextest-rs/nextest/cargo-nextest",
    ] {
        pin(tool);
        assert!(
            installed.contains(&tool),
            "the fast gate runs {tool}, which CI doesn't install from mise.toml"
        );
    }
    let rust = pin("rust");
    let manifest = fs::read_to_string("Cargo.toml")
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let minimum = manifest["package"]["rust-version"].as_str().unwrap();
    assert!(
        rust.starts_with(&format!("{minimum}.")),
        "Rust {rust} is not the declared minimum {minimum}"
    );
    assert_eq!(
        with("checks", "erlef/setup-beam@", "gleam-version"),
        pin("gleam")
    );
    assert_eq!(
        with("checks", "erlef/setup-beam@", "otp-version"),
        pin("erlang")
    );
    let assurance = fs::read_to_string(".github/workflows/assurance.yml");
    assert!(
        assurance.contains(&format!(
            "install --locked zizmor --version {}",
            pin("aqua:zizmorcore/zizmor")
        )),
        "shipping assurance must install the pinned zizmor"
    );
}

#[test]
fn every_repository_workflow_is_valid_yaml_and_includes_assurance() {
    let paths = std::fs::read_dir(".github/workflows")
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let mut names = Vec::new();
    for entry in paths {
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "yml") {
            let source = fs::read_to_string(&path);
            serde_norway::from_str::<serde_norway::Value>(&source)
                .unwrap_or_else(|error| panic!("invalid {}: {error}", path.display()));
            names.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    names.sort();
    assert_eq!(names, ["assurance.yml", "ci.yml", "distribute.yml"]);
}

#[test]
fn local_assurance_outputs_cannot_be_committed_accidentally() {
    let ignore = fs::read_to_string(".gitignore");
    let patterns = ignore.lines().collect::<std::collections::HashSet<_>>();

    for required in ["/coverage.json", "/mutants.out*/"] {
        assert!(
            patterns.contains(required),
            "missing assurance output ignore: {required}"
        );
    }
}
