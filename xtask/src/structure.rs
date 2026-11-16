//! The structure gate: every release decision stays in the proved core, and every crate keeps its place.
//!
//! Each finding names the file, the rule, and the item that breaks it, and the report adds the fix.
//! [`DEBT`] holds the findings of the tree that the gate first met, and an entry that no longer fires fails the gate until a change deletes it.

use crate::container::Failure;
use crate::fs;
use proc_macro2::{TokenStream, TokenTree};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use syn::punctuated::Punctuated;
use syn::visit::Visit;
use toml_edit::{DocumentMut, Item, TableLike};

/// The proved crate that holds every release decision.
const CORE: &str = "release-glz-core";
/// The proved crate that decides whether the release gate may rely on a recorded verification run.
const ASSURANCE: &str = "assurance-core";
/// The unproved crate that holds the owned checked types, once it exists.
const DOMAIN: &str = "release-glz-domain";
/// The release engine, which is the workspace's root package.
const SHELL: &str = "release-glz";
/// The fixtures that the integration tests share.
const TEST_SUPPORT: &str = "release-glz-test-support";

/// The proved crates, each with the only dependency it may name.
const PROVED_CRATES: [(&str, &[&str]); 2] = [(CORE, &["serde"]), (ASSURANCE, &[])];

/// The crates whose sources may not copy a core rule.
const SHELL_CRATES: [&str; 2] = [SHELL, TEST_SUPPORT];

/// The members that one workspace member may depend on.
#[derive(Debug, Clone, Copy)]
struct Edges {
    member: &'static str,
    /// The members it may name in any dependency table.
    normal: &'static [&'static str],
    /// The members it may name in `dev-dependencies` alone.
    dev: &'static [&'static str],
}

/// Every allowed dependency edge among the workspace members.
const EDGES: [Edges; 6] = [
    Edges {
        member: CORE,
        normal: &[],
        dev: &[],
    },
    Edges {
        member: ASSURANCE,
        normal: &[],
        dev: &[],
    },
    Edges {
        member: DOMAIN,
        normal: &[CORE],
        dev: &[],
    },
    Edges {
        member: SHELL,
        normal: &[CORE, DOMAIN],
        dev: &[TEST_SUPPORT],
    },
    Edges {
        member: TEST_SUPPORT,
        normal: &[DOMAIN, CORE],
        dev: &[],
    },
    Edges {
        member: "xtask",
        normal: &[ASSURANCE, CORE],
        dev: &[],
    },
];

/// The owned types that the core names only in its proofs and negative controls.
const OWNED: [&str; 11] = [
    "String",
    "Vec",
    "Box",
    "BTreeMap",
    "BTreeSet",
    "VecDeque",
    "BinaryHeap",
    "LinkedList",
    "Rc",
    "Arc",
    "Cow",
];

/// The macros that build an owned value.
const OWNED_MACROS: [&str; 2] = ["vec", "format"];

/// The core crate as Rust code names it.
const CORE_CRATE: &str = "release_glz_core";

/// The core predicates that only the domain crate's constructors may call.
const CORE_RULES: [&str; 4] = [
    "is_sha256_hex",
    "is_object_id",
    "is_commit_id",
    "lowercase_hex",
];

/// The standard method that repeats the core's hexadecimal check.
const HEX_DIGIT: &str = "is_ascii_hexdigit";

/// The suffix of a constant that repeats a digest length.
const HEX_LEN: &str = "_HEX_LEN";

/// The spellings of policy values that a fact enum owns.
const POLICY_TEXTS: [&str; 2] = ["workflow-dispatch-digest", "uploaded"];

/// The prefix of the functions that hold the negative controls.
const NEGATIVE_CONTROL: &str = "negative_control_";

/// The one lint the workspace manifest may allow, which its comment explains.
const WORKSPACE_ALLOWED: (&str, &str) = ("clippy", "multiple_crate_versions");

/// The dependency tables of a manifest and the kind of edge each one adds.
const DEPENDENCY_TABLES: [(&str, Kind); 3] = [
    ("dependencies", Kind::Normal),
    ("dev-dependencies", Kind::Dev),
    ("build-dependencies", Kind::Build),
];

/// The lints each proved crate's root denies in its own `#![deny(...)]`, so no build but Kani's panics or leaks.
pub const DENIED: [&str; 8] = [
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::panic",
    "clippy::todo",
    "clippy::unimplemented",
    "clippy::unreachable",
    "clippy::exit",
    "clippy::mem_forget",
];

/// The findings of the tree that the gate first met, each group with the change that removes it.
pub const DEBT: &[&str] = &[
    // The proved crates deny the panic lints in their roots.
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::exit)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::expect_used)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::mem_forget)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::panic)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::todo)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::unimplemented)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::unreachable)]",
    "crates/assurance-core/src/lib.rs: core-root: lacks #![deny(clippy::unwrap_used)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::exit)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::expect_used)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::mem_forget)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::panic)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::todo)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::unimplemented)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::unreachable)]",
    "crates/release-glz-core/src/lib.rs: core-root: lacks #![deny(clippy::unwrap_used)]",
    // The identity types move into the domain crate.
    "src/authorization.rs: core-rule-copy: `is_full_sha` calls release_glz_core::is_object_id",
    "src/candidate.rs: core-rule-copy: `validate_sha256` calls release_glz_core::is_sha256_hex",
    "src/candidate.rs: core-rule-copy: `validate_source` calls release_glz_core::is_commit_id",
    "src/canonical.rs: core-rule-copy: the module defines SHA256_HEX_LEN",
    "src/forge.rs: core-rule-copy: `valid_object_id` calls release_glz_core::is_object_id",
    "src/forge.rs: core-rule-copy: `valid_sha256` calls release_glz_core::is_sha256_hex",
    "src/git.rs: core-rule-copy: `parse_commit_log` calls is_ascii_hexdigit",
    "src/git.rs: core-rule-copy: `parse_commit_log` names OBJECT_HEX_LEN",
    "src/git.rs: core-rule-copy: the module defines OBJECT_HEX_LEN",
    "src/registry.rs: core-rule-copy: `validate_checksum` calls is_ascii_hexdigit",
    "src/registry.rs: core-rule-copy: `validate_checksum` names SHA256_HEX_LEN",
    "src/rehearse.rs: core-rule-copy: `validate_full_sha` calls release_glz_core::is_commit_id",
    "src/release.rs: core-rule-copy: `is_sha256` calls is_ascii_hexdigit",
    "src/release.rs: core-rule-copy: `is_sha256` names SHA256_HEX_LEN",
    "src/workflow.rs: core-rule-copy: `validate_action_sha` calls release_glz_core::is_object_id",
    // The approval source fallback becomes a fact enum of the core.
    "src/candidate.rs: core-rule-copy: `validate_approval` spells \"workflow-dispatch-digest\"",
    "src/config.rs: core-rule-copy: `validate_release_config` spells \"workflow-dispatch-digest\"",
    "src/doctor.rs: core-rule-copy: `assess_approval` spells \"workflow-dispatch-digest\"",
    // The release asset state becomes a fact enum of the core.
    "src/forge.rs: core-rule-copy: `GitHubClient::delete_unfinished_release_asset` spells \"uploaded\"",
    "src/forge.rs: core-rule-copy: `GitHubClient::upload_release_asset` spells \"uploaded\"",
    "src/release.rs: core-rule-copy: `LiveReleaseTarget::apply` spells \"uploaded\"",
    "src/release.rs: core-rule-copy: `LiveReleaseTarget::observe` spells \"uploaded\"",
    // The root crate adopts the lint baseline.
    "Cargo.toml: lint-exception: [lints.clippy] allows disallowed_methods",
    "Cargo.toml: lint-exception: [lints.clippy] allows disallowed_types",
    "Cargo.toml: lint-exception: [lints.clippy] allows enum_variant_names",
    "Cargo.toml: lint-exception: [lints.clippy] allows too_many_arguments",
    // The core adopts the lint baseline together with the Kani harnesses it moves.
    "crates/release-glz-core/Cargo.toml: lint-exception: [lints.clippy] allows disallowed_methods",
    "crates/release-glz-core/Cargo.toml: lint-exception: [lints.clippy] allows too_many_arguments",
];

/// The rule that a finding breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    CoreDependency,
    CoreRoot,
    CoreStd,
    CoreOwned,
    CoreUnproved,
    CoreRuleCopy,
    DomainOpen,
    CrateEdge,
    UnmappedCrate,
    LintException,
}

impl Rule {
    const fn tag(self) -> &'static str {
        match self {
            Self::CoreDependency => "core-dependency",
            Self::CoreRoot => "core-root",
            Self::CoreStd => "core-std",
            Self::CoreOwned => "core-owned",
            Self::CoreUnproved => "core-unproved",
            Self::CoreRuleCopy => "core-rule-copy",
            Self::DomainOpen => "domain-open",
            Self::CrateEdge => "crate-edge",
            Self::UnmappedCrate => "unmapped-crate",
            Self::LintException => "lint-exception",
        }
    }

    const fn fix(self) -> &'static str {
        match self {
            Self::CoreDependency => {
                "the core takes borrowed bytes or fact enums, so move the need into release-glz-domain or the shell, and keep serde optional with default-features = false"
            }
            Self::CoreRoot => {
                "put the attribute in the crate root outside `cfg_attr`, so every build but Kani's carries it"
            }
            Self::CoreStd => "name `core` instead, and leave the effect to the shell",
            Self::CoreOwned => {
                "take `&[u8]` or a fact enum and return an enum, and put the owned checked type in release-glz-domain"
            }
            Self::CoreUnproved => {
                "prove the module's decision in a `#[cfg(kani)] mod proofs` in the same file, and tie each harness to a negative control in xtask/src/inventory.rs"
            }
            Self::CoreRuleCopy => {
                "construct the checked type in release-glz-domain, whose constructor calls the core predicate"
            }
            Self::DomainOpen => {
                "keep the fields private, and construct the type only through a checked constructor that calls the core predicate"
            }
            Self::CrateEdge => {
                "keep to EDGES in xtask/src/structure.rs: put a shared decision in release-glz-core and a shared owned type in release-glz-domain"
            }
            Self::UnmappedCrate => "add a row for the crate to EDGES in xtask/src/structure.rs",
            Self::LintException => "meet the lint and delete the entry",
        }
    }
}

/// One breach of the structure, which its rule's fix removes.
///
/// Its text names the path, the rule, and the item without a line number, so an unrelated edit leaves [`DEBT`] alone.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    path: String,
    rule: Rule,
    item: String,
}

impl Finding {
    fn new(path: &str, rule: Rule, item: impl Into<String>) -> Self {
        Self {
            path: path.to_owned(),
            rule,
            item: item.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}: {}",
            self.path,
            self.rule.tag(),
            self.item
        )
    }
}

/// The findings outside [`DEBT`] and the entries of [`DEBT`] that no longer fire.
#[derive(Debug, Default)]
pub struct Verdict {
    /// The findings that no entry of the debt covers.
    pub unexpected: Vec<Finding>,
    /// The entries of the debt that no finding matches.
    pub stale: Vec<String>,
}

impl Verdict {
    /// Whether the findings equal the debt.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.unexpected.is_empty() && self.stale.is_empty()
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the structure differs from DEBT in xtask/src/structure.rs"
        )?;
        for finding in &self.unexpected {
            write!(formatter, "\n{finding}\n    fix: {}", finding.rule.fix())?;
        }
        for entry in &self.stale {
            write!(
                formatter,
                "\n{entry}\n    fix: this DEBT entry no longer fires, so remove this entry"
            )?;
        }
        Ok(())
    }
}

/// Every way the workspace at `root` breaks its structure, in sorted order.
///
/// # Errors
///
/// Returns a failure when a manifest or a source can't be read or parsed, or a proved or shell crate is missing.
pub fn findings(root: &Path) -> Result<Vec<Finding>, Failure> {
    let workspace = Workspace::read(root)?;
    let mut found = Vec::new();
    for (name, allowed) in PROVED_CRATES {
        let member = workspace.required(name)?;
        core_dependencies(member, allowed, &mut found);
        core_sources(&workspace, member, &mut found)?;
    }
    for name in SHELL_CRATES {
        let member = workspace.required(name)?;
        scan_sources(&workspace, &member.directory, Place::Shell, &mut found)?;
    }
    if let Some(domain) = workspace.member(DOMAIN) {
        scan_sources(&workspace, &domain.directory, Place::Domain, &mut found)?;
    }
    edges(&workspace, &mut found);
    lint_exceptions(&workspace, &mut found);
    found.sort();
    Ok(found)
}

/// The findings that `debt` doesn't cover, and the entries of `debt` that no finding matches.
///
/// An entry covers one finding, so a repeated finding needs a repeated entry.
#[must_use]
pub fn judge(found: &[Finding], debt: &[&str]) -> Verdict {
    let mut remaining = BTreeMap::<&str, usize>::new();
    for entry in debt {
        let count = remaining.entry(entry).or_default();
        *count = count.saturating_add(1);
    }
    let mut unexpected = Vec::new();
    for finding in found {
        let key = finding.to_string();
        match remaining.get_mut(key.as_str()).filter(|count| **count > 0) {
            Some(count) => *count = count.saturating_sub(1),
            None => unexpected.push(finding.clone()),
        }
    }
    let stale = remaining
        .into_iter()
        .flat_map(|(entry, count)| std::iter::repeat_n(entry.to_owned(), count))
        .collect();
    Verdict { unexpected, stale }
}

/// Refuses a workspace whose findings differ from [`DEBT`], naming each finding with its fix and each stale entry.
///
/// # Errors
///
/// Returns a failure listing every unexpected finding and stale entry, or when the workspace can't be read.
pub fn run(root: &Path) -> Result<(), Failure> {
    let verdict = judge(&findings(root)?, DEBT);
    if verdict.is_clean() {
        eprintln!(
            "structure: the proved core keeps its boundary, and {} DEBT entries remain",
            DEBT.len()
        );
        Ok(())
    } else {
        Err(Failure::new(verdict.to_string()))
    }
}

/// One member of the workspace and its manifest.
#[derive(Debug)]
struct Member {
    directory: PathBuf,
    /// The manifest's path in the workspace, with `/` between components.
    manifest_path: String,
    name: String,
    manifest: DocumentMut,
}

impl Member {
    fn new(
        directory: PathBuf,
        manifest_path: String,
        manifest: DocumentMut,
    ) -> Result<Self, Failure> {
        let name = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(Item::as_str)
            .ok_or_else(|| Failure::new(format!("{manifest_path} names no package")))?
            .to_owned();
        Ok(Self {
            directory,
            manifest_path,
            name,
            manifest,
        })
    }
}

fn manifest_at(directory: &Path, shown: &str) -> Result<DocumentMut, Failure> {
    fs::read_to_string(directory.join("Cargo.toml"))?
        .parse()
        .map_err(|error| Failure::new(format!("parsing {shown} failed: {error}")))
}

/// The workspace: its root manifest and every member, the root package first.
#[derive(Debug)]
struct Workspace {
    root: PathBuf,
    manifest: DocumentMut,
    members: Vec<Member>,
}

impl Workspace {
    fn read(root: &Path) -> Result<Self, Failure> {
        let manifest = manifest_at(root, "Cargo.toml")?;
        let mut members = Vec::new();
        if manifest.contains_key("package") {
            members.push(Member::new(
                root.to_path_buf(),
                "Cargo.toml".to_owned(),
                manifest.clone(),
            )?);
        }
        let listed = manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("members"))
            .and_then(Item::as_array);
        for entry in listed.into_iter().flat_map(toml_edit::Array::iter) {
            let relative = entry.as_str().ok_or_else(|| {
                Failure::new("Cargo.toml lists a workspace member that isn't a string")
            })?;
            let shown = format!("{relative}/Cargo.toml");
            let directory = root.join(relative);
            let member_manifest = manifest_at(&directory, &shown)?;
            members.push(Member::new(directory, shown, member_manifest)?);
        }
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            members,
        })
    }

    fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|member| member.name == name)
    }

    fn required(&self, name: &str) -> Result<&Member, Failure> {
        self.member(name).ok_or_else(|| {
            Failure::new(format!(
                "the workspace has no member {name}, which xtask/src/structure.rs reads"
            ))
        })
    }

    /// The path of `path` in the workspace, with `/` between components on every host.
    fn shown(&self, path: &Path) -> Result<String, Failure> {
        let relative = path.strip_prefix(&self.root).map_err(|error| {
            Failure::new(format!(
                "{} lies outside the workspace: {error}",
                path.display()
            ))
        })?;
        Ok(relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"))
    }
}

/// How a dependency table relates two crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Normal,
    Dev,
    Build,
}

/// One entry of a dependency table.
#[derive(Debug)]
struct Dependency {
    /// The package it names, which a `package` key may rename.
    package: String,
    kind: Kind,
    optional: bool,
    default_features: bool,
}

impl Dependency {
    fn read(key: &str, entry: &Item, kind: Kind) -> Self {
        Self {
            package: entry
                .get("package")
                .and_then(Item::as_str)
                .unwrap_or(key)
                .to_owned(),
            kind,
            optional: entry
                .get("optional")
                .and_then(Item::as_bool)
                .unwrap_or(false),
            default_features: entry
                .get("default-features")
                .and_then(Item::as_bool)
                .unwrap_or(true),
        }
    }
}

/// Every entry of every dependency table of `manifest`, the per-target ones included.
fn dependencies(manifest: &DocumentMut) -> Vec<Dependency> {
    let mut tables: Vec<&dyn TableLike> = vec![manifest.as_table()];
    if let Some(targets) = manifest.get("target").and_then(Item::as_table_like) {
        tables.extend(
            targets
                .iter()
                .filter_map(|(_, target)| target.as_table_like()),
        );
    }
    let mut found = Vec::new();
    for table in tables {
        for (name, kind) in DEPENDENCY_TABLES {
            if let Some(entries) = table.get(name).and_then(Item::as_table_like) {
                found.extend(
                    entries
                        .iter()
                        .map(|(key, entry)| Dependency::read(key, entry, kind)),
                );
            }
        }
    }
    found
}

/// A proved crate names no dependency but those `allowed` in `[dependencies]`, each optional and without default features.
fn core_dependencies(member: &Member, allowed: &[&str], found: &mut Vec<Finding>) {
    for dependency in dependencies(&member.manifest) {
        let package = &dependency.package;
        let item = if dependency.kind != Kind::Normal || !allowed.contains(&package.as_str()) {
            format!("depends on {package}")
        } else if dependency.optional && !dependency.default_features {
            continue;
        } else {
            format!("depends on {package} without optional = true and default-features = false")
        };
        found.push(Finding::new(
            &member.manifest_path,
            Rule::CoreDependency,
            item,
        ));
    }
}

fn parse(path: &Path) -> Result<syn::File, Failure> {
    syn::parse_file(&fs::read_to_string(path)?)
        .map_err(|error| Failure::new(format!("parsing {} failed: {error}", path.display())))
}

/// The root attributes, the proofs, and the syntax of each source of a proved crate.
fn core_sources(
    workspace: &Workspace,
    member: &Member,
    found: &mut Vec<Finding>,
) -> Result<(), Failure> {
    let library = member.directory.join("src").join("lib.rs");
    for path in fs::files_with_suffix(&member.directory.join("src"), ".rs")? {
        let shown = workspace.shown(&path)?;
        let file = parse(&path)?;
        if path == library {
            root_findings(&shown, &file, found);
        } else if !has_proofs(&file) {
            found.push(Finding::new(
                &shown,
                Rule::CoreUnproved,
                "holds no #[cfg(kani)] mod proofs with a #[kani::proof] harness",
            ));
        }
        found.extend(
            Scan::hits(&file, Place::Core)
                .into_iter()
                .map(|(rule, item)| Finding::new(&shown, rule, item)),
        );
    }
    Ok(())
}

/// The syntax findings of every source of the crate in `directory` for the rules of `place`.
fn scan_sources(
    workspace: &Workspace,
    directory: &Path,
    place: Place,
    found: &mut Vec<Finding>,
) -> Result<(), Failure> {
    for path in fs::files_with_suffix(&directory.join("src"), ".rs")? {
        let shown = workspace.shown(&path)?;
        let file = parse(&path)?;
        found.extend(
            Scan::hits(&file, place)
                .into_iter()
                .map(|(rule, item)| Finding::new(&shown, rule, item)),
        );
    }
    Ok(())
}

fn rendered(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// The lints that the root attributes at `level` name.
fn lint_names(attributes: &[syn::Attribute], level: &str) -> Vec<String> {
    let mut names = Vec::new();
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident(level))
    {
        if let Ok(lints) =
            attribute.parse_args_with(Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)
        {
            names.extend(lints.iter().map(rendered));
        }
    }
    names
}

/// A proved crate's root is `no_std`, forbids unsafe code, and denies every lint of [`DENIED`], each outside `cfg_attr`.
fn root_findings(shown: &str, file: &syn::File, found: &mut Vec<Finding>) {
    let forbidden = lint_names(&file.attrs, "forbid");
    let denied = lint_names(&file.attrs, "deny");
    let mut missing = Vec::new();
    if !file
        .attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("no_std"))
    {
        missing.push("#![no_std]".to_owned());
    }
    if !forbidden.iter().any(|lint| lint == "unsafe_code") {
        missing.push("#![forbid(unsafe_code)]".to_owned());
    }
    for lint in DENIED {
        if !denied.iter().chain(&forbidden).any(|name| name == lint) {
            missing.push(format!("#![deny({lint})]"));
        }
    }
    found.extend(
        missing
            .into_iter()
            .map(|attribute| Finding::new(shown, Rule::CoreRoot, format!("lacks {attribute}"))),
    );
}

fn is_cfg(attribute: &syn::Attribute, name: &str) -> bool {
    attribute.path().is_ident("cfg")
        && attribute
            .parse_args::<syn::Ident>()
            .is_ok_and(|ident| ident == name)
}

fn is_test(attribute: &syn::Attribute) -> bool {
    is_cfg(attribute, "test")
        || attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
}

fn is_harness(item: &syn::Item) -> bool {
    let syn::Item::Fn(function) = item else {
        return false;
    };
    function
        .attrs
        .iter()
        .any(|attribute| rendered(attribute.path()) == "kani::proof")
}

/// Whether a module holds a `#[cfg(kani)] mod proofs` with a `#[kani::proof]` harness.
fn has_proofs(file: &syn::File) -> bool {
    file.items.iter().any(|item| {
        let syn::Item::Mod(module) = item else {
            return false;
        };
        module.ident == "proofs"
            && module
                .attrs
                .iter()
                .any(|attribute| is_cfg(attribute, "kani"))
            && module
                .content
                .as_ref()
                .is_some_and(|(_, items)| items.iter().any(is_harness))
    })
}

/// Each member depends on other members only along [`EDGES`], and every member has a row there.
fn edges(workspace: &Workspace, found: &mut Vec<Finding>) {
    let known: Vec<&str> = workspace
        .members
        .iter()
        .map(|member| member.name.as_str())
        .chain(EDGES.iter().map(|row| row.member))
        .collect();
    for member in &workspace.members {
        let Some(row) = EDGES.iter().find(|row| row.member == member.name) else {
            found.push(Finding::new(
                &member.manifest_path,
                Rule::UnmappedCrate,
                format!("{} has no row in EDGES", member.name),
            ));
            continue;
        };
        for dependency in dependencies(&member.manifest) {
            let to = dependency.package.as_str();
            let dev = dependency.kind == Kind::Dev && row.dev.contains(&to);
            if !known.contains(&to) || row.normal.contains(&to) || dev {
                continue;
            }
            let place = if row.dev.contains(&to) {
                " outside dev-dependencies"
            } else {
                ""
            };
            found.push(Finding::new(
                &member.manifest_path,
                Rule::CrateEdge,
                format!("{} depends on {to}{place}", member.name),
            ));
        }
    }
}

/// The lints that the `[section.*]` tables of `lints` allow, except `exempt`.
fn allowed_lints(lints: Option<&Item>, section: &str, exempt: Option<(&str, &str)>) -> Vec<String> {
    let mut items = Vec::new();
    let tools = lints.and_then(Item::as_table_like);
    for (tool, table) in tools.into_iter().flat_map(|tools| tools.iter()) {
        let Some(table) = table.as_table_like() else {
            continue;
        };
        for (lint, level) in table.iter() {
            let level = level
                .as_str()
                .or_else(|| level.get("level").and_then(Item::as_str));
            if level == Some("allow") && exempt != Some((tool, lint)) {
                items.push(format!("[{section}.{tool}] allows {lint}"));
            }
        }
    }
    items
}

/// No manifest allows a lint, except the documented workspace entry.
fn lint_exceptions(workspace: &Workspace, found: &mut Vec<Finding>) {
    for member in &workspace.members {
        found.extend(
            allowed_lints(member.manifest.get("lints"), "lints", None)
                .into_iter()
                .map(|item| Finding::new(&member.manifest_path, Rule::LintException, item)),
        );
    }
    let workspace_lints = workspace
        .manifest
        .get("workspace")
        .and_then(|section| section.get("lints"));
    found.extend(
        allowed_lints(workspace_lints, "workspace.lints", Some(WORKSPACE_ALLOWED))
            .into_iter()
            .map(|item| Finding::new("Cargo.toml", Rule::LintException, item)),
    );
}

/// The crate whose sources a scan reads, which decides the rules it applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    Core,
    Shell,
    Domain,
}

/// The items around a piece of syntax that exempt it from a rule.
#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    /// Inside a `#[cfg(kani)]` item, which only the proofs compile.
    kani: bool,
    /// Inside a test item, which may spell values.
    test: bool,
    /// Inside a negative control, which only its own feature compiles.
    control: bool,
}

impl Flags {
    fn within(self, attributes: &[syn::Attribute], name: &str) -> Self {
        Self {
            kani: self.kani || attributes.iter().any(|attribute| is_cfg(attribute, "kani")),
            test: self.test || attributes.iter().any(is_test),
            control: self.control || name.starts_with(NEGATIVE_CONTROL),
        }
    }
}

impl Place {
    const fn keeps(self, rule: Rule, flags: Flags) -> bool {
        match (self, rule) {
            (Self::Core, Rule::CoreStd) => true,
            (Self::Core, Rule::CoreOwned) => !flags.kani && !flags.control,
            (Self::Shell, Rule::CoreRuleCopy) | (Self::Domain, Rule::DomainOpen) => !flags.test,
            _ => false,
        }
    }
}

/// One name that a `use` item brings into scope.
#[derive(Debug)]
struct Leaf {
    path: Vec<String>,
    /// The name it binds, or `None` for a glob.
    local: Option<String>,
}

fn use_leaves(tree: &syn::UseTree, prefix: &[String], leaves: &mut Vec<Leaf>) {
    let joined = |ident: &syn::Ident| {
        let mut path = prefix.to_vec();
        path.push(ident.to_string());
        path
    };
    match tree {
        syn::UseTree::Path(path) => use_leaves(&path.tree, &joined(&path.ident), leaves),
        syn::UseTree::Name(name) => leaves.push(Leaf {
            path: joined(&name.ident),
            local: Some(name.ident.to_string()),
        }),
        syn::UseTree::Rename(rename) => leaves.push(Leaf {
            path: joined(&rename.ident),
            local: Some(rename.rename.to_string()),
        }),
        syn::UseTree::Glob(_) => leaves.push(Leaf {
            path: prefix.to_vec(),
            local: None,
        }),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                use_leaves(item, prefix, leaves);
            }
        }
    }
}

/// The local names of a file's core predicates, each with the path of the predicate.
#[derive(Debug, Default)]
struct Imports(BTreeMap<String, String>);

impl Visit<'_> for Imports {
    fn visit_item_use(&mut self, node: &syn::ItemUse) {
        let mut leaves = Vec::new();
        use_leaves(&node.tree, &[], &mut leaves);
        for leaf in leaves {
            let from_core = leaf.path.first().is_some_and(|first| first == CORE_CRATE);
            match leaf.local {
                Some(local) if from_core => {
                    if let Some(rule) = leaf
                        .path
                        .last()
                        .filter(|last| CORE_RULES.contains(&last.as_str()))
                    {
                        self.0.insert(local, format!("{CORE_CRATE}::{rule}"));
                    }
                }
                None if from_core && leaf.path.len() == 1 => {
                    for rule in CORE_RULES {
                        self.0
                            .insert(rule.to_owned(), format!("{CORE_CRATE}::{rule}"));
                    }
                }
                Some(_) | None => {}
            }
        }
    }
}

/// The name of the type an `impl` block is for.
fn type_name(ty: &syn::Type) -> String {
    if let syn::Type::Path(path) = ty
        && let Some(last) = path.path.segments.last()
    {
        last.ident.to_string()
    } else {
        "impl".to_owned()
    }
}

/// The text type of a `From<String>` or `From<&str>` trait.
fn from_text(path: &syn::Path) -> Option<&'static str> {
    let last = path.segments.last().filter(|last| last.ident == "From")?;
    let syn::PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return None;
    };
    let Some(syn::GenericArgument::Type(source)) = arguments.args.first() else {
        return None;
    };
    if let syn::Type::Reference(reference) = source
        && let syn::Type::Path(text) = &*reference.elem
        && text.path.is_ident("str")
    {
        return Some("&str");
    }
    let syn::Type::Path(text) = source else {
        return None;
    };
    text.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "String")
        .then_some("String")
}

/// The integer that a comparison of a field named `schema` with an integer literal names.
fn schema_number(field: &syn::Expr, value: &syn::Expr) -> Option<String> {
    let syn::Expr::Field(field) = field else {
        return None;
    };
    let syn::Member::Named(name) = &field.member else {
        return None;
    };
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Int(number),
        ..
    }) = value
    else {
        return None;
    };
    (name == "schema").then(|| number.to_string())
}

/// One walk over a file's syntax that records each hit the rules of its place keep, with the item around it.
#[derive(Debug)]
struct Scan {
    place: Place,
    imports: BTreeMap<String, String>,
    /// The names of the items around the current one, outermost first.
    context: Vec<String>,
    flags: Flags,
    /// How many types enclose the current syntax.
    typed: usize,
    hits: Vec<(Rule, String)>,
}

impl Scan {
    fn hits(file: &syn::File, place: Place) -> Vec<(Rule, String)> {
        let mut imports = Imports::default();
        imports.visit_file(file);
        let mut scan = Self {
            place,
            imports: imports.0,
            context: Vec::new(),
            flags: Flags::default().within(&file.attrs, ""),
            typed: 0,
            hits: Vec::new(),
        };
        scan.visit_file(file);
        scan.hits
    }

    fn record(&mut self, rule: Rule, item: String) {
        if self.place.keeps(rule, self.flags) {
            self.hits.push((rule, item));
        }
    }

    fn context(&self) -> String {
        if self.context.is_empty() {
            "the module".to_owned()
        } else {
            format!("`{}`", self.context.join("::"))
        }
    }

    /// Walks an item with the flags its attributes and name add, and its name around the hits inside it.
    fn enter(
        &mut self,
        attributes: &[syn::Attribute],
        name: Option<String>,
        walk: impl FnOnce(&mut Self),
    ) {
        let outer = self.flags;
        self.flags = outer.within(attributes, name.as_deref().unwrap_or_default());
        let named = name.is_some();
        self.context.extend(name);
        walk(self);
        if named {
            self.context.pop();
        }
        self.flags = outer;
    }

    fn check_path(&mut self, names: &[String]) {
        let (Some(first), Some(last)) = (names.first(), names.last()) else {
            return;
        };
        let shown = names.join("::");
        let context = self.context();
        if first == "std" {
            self.record(Rule::CoreStd, format!("{context} names {shown}"));
        }
        let owned = OWNED.contains(&first.as_str()) && (names.len() > 1 || self.typed > 0);
        if first == "alloc" || owned {
            self.record(Rule::CoreOwned, format!("{context} names {shown}"));
        }
        let called = if first == CORE_CRATE && CORE_RULES.contains(&last.as_str()) {
            Some(shown.clone())
        } else if names.len() == 1 {
            self.imports.get(first).cloned()
        } else {
            None
        };
        if let Some(called) = called {
            self.record(Rule::CoreRuleCopy, format!("{context} calls {called}"));
        }
        if last == HEX_DIGIT {
            self.record(Rule::CoreRuleCopy, format!("{context} calls {shown}"));
        }
        if last.ends_with(HEX_LEN) {
            self.record(Rule::CoreRuleCopy, format!("{context} names {shown}"));
        }
    }

    fn check_text(&mut self, text: &str) {
        if POLICY_TEXTS.contains(&text) {
            let item = format!("{} spells \"{text}\"", self.context());
            self.record(Rule::CoreRuleCopy, item);
        }
    }

    /// The names and string literals of a macro body that doesn't parse as expressions.
    fn walk_tokens(&mut self, tokens: TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.walk_tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if CORE_RULES.contains(&name.as_str()) {
                        self.check_path(&[CORE_CRATE.to_owned(), name]);
                    } else {
                        self.check_path(&[name]);
                    }
                }
                TokenTree::Literal(literal) => {
                    if let syn::Lit::Str(text) = syn::Lit::new(literal) {
                        self.check_text(&text.value());
                    }
                }
                TokenTree::Punct(_) => {}
            }
        }
    }

    fn use_hits(&mut self, node: &syn::ItemUse) {
        let mut leaves = Vec::new();
        use_leaves(&node.tree, &[], &mut leaves);
        let context = self.context();
        for leaf in leaves {
            let shown = leaf.path.join("::");
            let first = leaf.path.first().map(String::as_str);
            if first == Some("std") {
                self.record(Rule::CoreStd, format!("{context} imports {shown}"));
            } else if first == Some("alloc") {
                self.record(Rule::CoreOwned, format!("{context} imports {shown}"));
            }
        }
    }
}

impl Visit<'_> for Scan {
    fn visit_attribute(&mut self, _attribute: &syn::Attribute) {}

    fn visit_item_mod(&mut self, node: &syn::ItemMod) {
        self.enter(&node.attrs, Some(node.ident.to_string()), |scan| {
            syn::visit::visit_item_mod(scan, node);
        });
    }

    fn visit_item_fn(&mut self, node: &syn::ItemFn) {
        self.enter(&node.attrs, Some(node.sig.ident.to_string()), |scan| {
            syn::visit::visit_item_fn(scan, node);
        });
    }

    fn visit_impl_item_fn(&mut self, node: &syn::ImplItemFn) {
        self.enter(&node.attrs, Some(node.sig.ident.to_string()), |scan| {
            syn::visit::visit_impl_item_fn(scan, node);
        });
    }

    fn visit_trait_item_fn(&mut self, node: &syn::TraitItemFn) {
        self.enter(&node.attrs, Some(node.sig.ident.to_string()), |scan| {
            syn::visit::visit_trait_item_fn(scan, node);
        });
    }

    fn visit_item_trait(&mut self, node: &syn::ItemTrait) {
        self.enter(&node.attrs, Some(node.ident.to_string()), |scan| {
            syn::visit::visit_item_trait(scan, node);
        });
    }

    fn visit_item_enum(&mut self, node: &syn::ItemEnum) {
        self.enter(&node.attrs, Some(node.ident.to_string()), |scan| {
            syn::visit::visit_item_enum(scan, node);
        });
    }

    fn visit_item_static(&mut self, node: &syn::ItemStatic) {
        self.enter(&node.attrs, Some(node.ident.to_string()), |scan| {
            syn::visit::visit_item_static(scan, node);
        });
    }

    fn visit_item_const(&mut self, node: &syn::ItemConst) {
        let name = node.ident.to_string();
        let defines = format!("{} defines {name}", self.context());
        self.enter(&node.attrs, Some(name.clone()), |scan| {
            if name.ends_with(HEX_LEN) {
                scan.record(Rule::CoreRuleCopy, defines);
            }
            syn::visit::visit_item_const(scan, node);
        });
    }

    fn visit_item_struct(&mut self, node: &syn::ItemStruct) {
        let name = node.ident.to_string();
        self.enter(&node.attrs, Some(name.clone()), |scan| {
            for (index, field) in node.fields.iter().enumerate() {
                if matches!(field.vis, syn::Visibility::Public(_)) {
                    let field_name = field
                        .ident
                        .as_ref()
                        .map_or_else(|| index.to_string(), ToString::to_string);
                    scan.record(
                        Rule::DomainOpen,
                        format!("`{name}` has the pub field `{field_name}`"),
                    );
                }
            }
            syn::visit::visit_item_struct(scan, node);
        });
    }

    fn visit_item_impl(&mut self, node: &syn::ItemImpl) {
        let name = type_name(&node.self_ty);
        self.enter(&node.attrs, Some(name.clone()), |scan| {
            if let Some((_, path, _)) = &node.trait_
                && let Some(text) = from_text(path)
            {
                scan.record(Rule::DomainOpen, format!("impl From<{text}> for `{name}`"));
            }
            syn::visit::visit_item_impl(scan, node);
        });
    }

    fn visit_item_use(&mut self, node: &syn::ItemUse) {
        self.enter(&node.attrs, None, |scan| scan.use_hits(node));
    }

    fn visit_item_extern_crate(&mut self, node: &syn::ItemExternCrate) {
        if node.ident == "std" {
            let item = format!("{} declares extern crate std", self.context());
            self.enter(&node.attrs, None, |scan| scan.record(Rule::CoreStd, item));
        }
    }

    fn visit_type(&mut self, node: &syn::Type) {
        self.typed = self.typed.saturating_add(1);
        syn::visit::visit_type(self, node);
        self.typed = self.typed.saturating_sub(1);
    }

    fn visit_path(&mut self, node: &syn::Path) {
        let names = node
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.check_path(&names);
        syn::visit::visit_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
        if node.method == HEX_DIGIT {
            let item = format!("{} calls {HEX_DIGIT}", self.context());
            self.record(Rule::CoreRuleCopy, item);
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &syn::ExprBinary) {
        let compares = matches!(
            node.op,
            syn::BinOp::Eq(_)
                | syn::BinOp::Ne(_)
                | syn::BinOp::Lt(_)
                | syn::BinOp::Le(_)
                | syn::BinOp::Gt(_)
                | syn::BinOp::Ge(_)
        );
        let number = schema_number(&node.left, &node.right)
            .or_else(|| schema_number(&node.right, &node.left));
        if compares && let Some(number) = number {
            let item = format!("{} compares schema with {number}", self.context());
            self.record(Rule::CoreRuleCopy, item);
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_lit_str(&mut self, node: &syn::LitStr) {
        self.check_text(&node.value());
    }

    /// A macro body that parses as expressions gets the same checks as code, and any other body is read token by token.
    fn visit_macro(&mut self, node: &syn::Macro) {
        let names = node
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let context = self.context();
        if names.first().is_some_and(|first| first == "std") {
            self.record(
                Rule::CoreStd,
                format!("{context} names {}", names.join("::")),
            );
        }
        if let Some(last) = names
            .last()
            .filter(|last| OWNED_MACROS.contains(&last.as_str()))
        {
            self.record(Rule::CoreOwned, format!("{context} calls {last}!"));
        }
        match node.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
            Ok(arguments) => {
                for argument in &arguments {
                    self.visit_expr(argument);
                }
            }
            Err(_) => self.walk_tokens(node.tokens.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEBT, DENIED, findings, judge};
    use crate::fs;
    use std::path::Path;

    const ROOT_MANIFEST: &str = r#"[package]
name = "release-glz"

[dependencies]
release-glz-core = { path = "crates/release-glz-core" }

[dev-dependencies]
release-glz-test-support = { path = "crates/test-support" }

[workspace]
members = ["crates/assurance-core", "crates/release-glz-core", "crates/test-support", "xtask"]

[workspace.lints.clippy]
multiple_crate_versions = "allow"
"#;

    const CORE_MANIFEST: &str = r#"[package]
name = "release-glz-core"

[dependencies]
serde = { version = "1", default-features = false, optional = true }
"#;

    const TEST_SUPPORT_MANIFEST: &str = r#"[package]
name = "release-glz-test-support"

[dependencies]
release-glz-core = { path = "../release-glz-core" }

[lints]
workspace = true
"#;

    const XTASK_MANIFEST: &str = r#"[package]
name = "xtask"

[dependencies]
assurance-core = { path = "../crates/assurance-core" }
release-glz-core = { path = "../crates/release-glz-core" }
"#;

    const DOMAIN_MANIFEST: &str = r#"[package]
name = "release-glz-domain"

[dependencies]
release-glz-core = { path = "../release-glz-core" }
"#;

    /// A core module that decides from borrowed bytes and proves its decision.
    const PROVED: &str = "pub enum Channel {
    Rc,
}

pub fn admit(value: &[u8]) -> Option<Channel> {
    (!value.is_empty()).then_some(Channel::Rc)
}

fn negative_control_admit() -> Option<String> {
    Some(format!(\"broken\"))
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn admits() {
        let _ = alloc::vec![0_u8];
    }
}
";

    const RULE: &str = "crates/release-glz-core/src/rule.rs";

    fn core_root() -> String {
        format!(
            "#![no_std]\n#![forbid(unsafe_code)]\n#![deny({})]\n#![cfg_attr(kani, allow(clippy::panic))]\n",
            DENIED.join(", ")
        )
    }

    fn put(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
    }

    /// A workspace with the members of the current tree, which keeps every rule.
    fn clean() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let files = [
            ("Cargo.toml", ROOT_MANIFEST),
            (
                "src/lib.rs",
                "pub fn shell(value: &str) -> String { value.to_owned() }\n",
            ),
            ("tests/contract.rs", "const DIGEST_HEX_LEN: usize = 64;\n"),
            ("crates/release-glz-core/Cargo.toml", CORE_MANIFEST),
            (RULE, PROVED),
            (
                "crates/assurance-core/Cargo.toml",
                "[package]\nname = \"assurance-core\"\n",
            ),
            ("crates/test-support/Cargo.toml", TEST_SUPPORT_MANIFEST),
            ("crates/test-support/src/lib.rs", ""),
            ("xtask/Cargo.toml", XTASK_MANIFEST),
            ("xtask/src/lib.rs", "const DIGEST_HEX_LEN: usize = 64;\n"),
        ];
        for (relative, contents) in files {
            put(root.path(), relative, contents);
        }
        let core_root = core_root();
        put(
            root.path(),
            "crates/release-glz-core/src/lib.rs",
            &format!("{core_root}extern crate alloc;\nmod rule;\n"),
        );
        put(root.path(), "crates/assurance-core/src/lib.rs", &core_root);
        root
    }

    fn keys(root: &Path) -> Vec<String> {
        findings(root)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// What the gate finds in a clean workspace once `contents` replaces the file at `relative`.
    fn planted(relative: &str, contents: &str) -> Vec<String> {
        let root = clean();
        put(root.path(), relative, contents);
        keys(root.path())
    }

    /// A clean workspace that also holds the domain crate, with `source` as its library.
    fn with_domain(source: &str) -> Vec<String> {
        let root = clean();
        put(
            root.path(),
            "Cargo.toml",
            &ROOT_MANIFEST
                .replace(
                    "\"xtask\"]",
                    "\"crates/release-glz-domain\", \"xtask\"]",
                )
                .replace(
                    "\n[dev-dependencies]",
                    "release-glz-domain = { path = \"crates/release-glz-domain\" }\n\n[dev-dependencies]",
                ),
        );
        put(
            root.path(),
            "crates/test-support/Cargo.toml",
            &TEST_SUPPORT_MANIFEST.replace(
                "\n[lints]",
                "release-glz-domain = { path = \"../release-glz-domain\" }\n\n[lints]",
            ),
        );
        put(
            root.path(),
            "crates/release-glz-domain/Cargo.toml",
            DOMAIN_MANIFEST,
        );
        put(root.path(), "crates/release-glz-domain/src/lib.rs", source);
        keys(root.path())
    }

    #[test]
    fn a_clean_workspace_has_no_findings() {
        let root = clean();
        assert_eq!(keys(root.path()), Vec::<String>::new());
        assert!(judge(&findings(root.path()).unwrap(), &[]).is_clean());
        assert_eq!(
            with_domain("pub struct Digest(String);\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_core_depends_on_nothing_but_optional_serde_without_default_features() {
        let manifest = "crates/release-glz-core/Cargo.toml";
        assert_eq!(
            planted(manifest, &format!("{CORE_MANIFEST}anyhow = \"1\"\n")),
            [format!("{manifest}: core-dependency: depends on anyhow")]
        );
        assert_eq!(
            planted(
                manifest,
                &CORE_MANIFEST.replace(" default-features = false,", "")
            ),
            [format!(
                "{manifest}: core-dependency: depends on serde without optional = true and default-features = false"
            )]
        );
        let assurance = "crates/assurance-core/Cargo.toml";
        assert_eq!(
            planted(
                assurance,
                "[package]\nname = \"assurance-core\"\n\n[target.'cfg(unix)'.dev-dependencies]\nserde = \"1\"\n"
            ),
            [format!("{assurance}: core-dependency: depends on serde")]
        );
    }

    #[test]
    fn a_core_root_carries_its_attributes_outside_cfg_attr() {
        let library = "crates/assurance-core/src/lib.rs";
        let cases = [
            (
                core_root().replace("clippy::panic, ", ""),
                "lacks #![deny(clippy::panic)]",
            ),
            (
                core_root().replace("#![no_std]", "#![cfg_attr(not(kani), no_std)]"),
                "lacks #![no_std]",
            ),
            (
                core_root().replace("forbid(unsafe_code)", "deny(unsafe_code)"),
                "lacks #![forbid(unsafe_code)]",
            ),
        ];
        for (source, item) in cases {
            assert_eq!(
                planted(library, &source),
                [format!("{library}: core-root: {item}")]
            );
        }
    }

    #[test]
    fn a_core_names_no_standard_library() {
        let cases = [
            (
                "pub fn read() { let _ = std::env::args(); }\n",
                "`read` names std::env::args",
            ),
            ("use std::fmt;\n", "the module imports std::fmt"),
            (
                "extern crate std;\n",
                "the module declares extern crate std",
            ),
        ];
        for (source, item) in cases {
            assert_eq!(
                planted(RULE, &format!("{PROVED}{source}")),
                [format!("{RULE}: core-std: {item}")]
            );
        }
    }

    #[test]
    fn a_core_holds_no_owned_type_outside_its_proofs_and_negative_controls() {
        let cases = [
            (
                "pub fn label(value: &[u8]) -> Box<[u8]> { value.into() }\n",
                "`label` names Box",
            ),
            (
                "pub fn bytes() -> alloc::vec::Vec<u8> { todo() }\n",
                "`bytes` names alloc::vec::Vec",
            ),
            (
                "pub fn words() { let _ = format!(\"x\"); }\n",
                "`words` calls format!",
            ),
            (
                "use alloc::string::String;\n",
                "the module imports alloc::string::String",
            ),
        ];
        for (source, item) in cases {
            assert_eq!(
                planted(RULE, &format!("{PROVED}{source}")),
                [format!("{RULE}: core-owned: {item}")]
            );
        }
    }

    #[test]
    fn every_core_module_proves_its_decision() {
        let module = "crates/release-glz-core/src/unproved.rs";
        let unproved = format!(
            "{module}: core-unproved: holds no #[cfg(kani)] mod proofs with a #[kani::proof] harness"
        );
        assert_eq!(
            planted(module, "pub fn admit() -> bool { true }\n"),
            std::slice::from_ref(&unproved)
        );
        assert_eq!(
            planted(
                module,
                "mod proofs {\n    #[kani::proof]\n    fn admits() {}\n}\n"
            ),
            [unproved]
        );
    }

    #[test]
    fn the_shell_copies_no_core_rule() {
        let cases = [
            (
                "fn digest(value: &str) -> bool { release_glz_core::is_sha256_hex(value.as_bytes()) }\n",
                "`digest` calls release_glz_core::is_sha256_hex",
            ),
            (
                "use release_glz_core::{is_object_id as object};\nfn pin(value: &str) -> bool { object(value.as_bytes()) }\n",
                "`pin` calls release_glz_core::is_object_id",
            ),
            (
                "fn hex(value: &str) -> bool { value.bytes().all(|byte| byte.is_ascii_hexdigit()) }\n",
                "`hex` calls is_ascii_hexdigit",
            ),
            (
                "const DIGEST_HEX_LEN: usize = 64;\n",
                "the module defines DIGEST_HEX_LEN",
            ),
            (
                "fn long(value: &str) -> bool { value.len() == release_glz_core::SHA256_HEX_LEN }\n",
                "`long` names release_glz_core::SHA256_HEX_LEN",
            ),
            (
                "fn current(config: &Config) -> bool { config.schema == 2 }\n",
                "`current` compares schema with 2",
            ),
            (
                "impl Asset {\n    fn ready(&self) -> bool { self.state == \"uploaded\" }\n}\n",
                "`Asset::ready` spells \"uploaded\"",
            ),
            (
                "fn fallback(name: &str) -> bool { matches!(name, \"workflow-dispatch-digest\") }\n",
                "`fallback` spells \"workflow-dispatch-digest\"",
            ),
            (
                "macro_rules! state { () => { \"uploaded\" }; }\n",
                "the module spells \"uploaded\"",
            ),
        ];
        for (source, item) in cases {
            assert_eq!(
                planted("src/copy.rs", source),
                [format!("src/copy.rs: core-rule-copy: {item}")]
            );
        }
        assert_eq!(
            planted(
                "crates/test-support/src/copy.rs",
                "const DIGEST_HEX_LEN: usize = 64;\n"
            ),
            ["crates/test-support/src/copy.rs: core-rule-copy: the module defines DIGEST_HEX_LEN"]
        );
    }

    #[test]
    fn tests_may_spell_core_values() {
        let source = "#[cfg(test)]
mod tests {
    const DIGEST_HEX_LEN: usize = 64;

    fn hex(value: &str) -> bool {
        value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

#[test]
fn uploaded() {
    assert_eq!(state(), \"uploaded\");
}
";
        assert_eq!(planted("src/copy.rs", source), Vec::<String>::new());
    }

    #[test]
    fn a_domain_type_opens_no_way_around_its_checked_constructor() {
        let library = "crates/release-glz-domain/src/lib.rs";
        let cases = [
            (
                "pub struct Digest {\n    pub text: String,\n}\n",
                "`Digest` has the pub field `text`",
            ),
            (
                "pub struct Digest(pub String);\n",
                "`Digest` has the pub field `0`",
            ),
            (
                "pub struct Digest(String);\nimpl From<String> for Digest {\n    fn from(text: String) -> Self { Self(text) }\n}\n",
                "impl From<String> for `Digest`",
            ),
            (
                "pub struct Digest(String);\nimpl From<&str> for Digest {\n    fn from(text: &str) -> Self { Self(text.to_owned()) }\n}\n",
                "impl From<&str> for `Digest`",
            ),
        ];
        for (source, item) in cases {
            assert_eq!(
                with_domain(source),
                [format!("{library}: domain-open: {item}")]
            );
        }
    }

    #[test]
    fn every_crate_keeps_its_edges() {
        assert_eq!(
            planted(
                "xtask/Cargo.toml",
                &format!("{XTASK_MANIFEST}release-glz = {{ path = \"..\" }}\n")
            ),
            ["xtask/Cargo.toml: crate-edge: xtask depends on release-glz"]
        );
        assert_eq!(
            planted(
                "xtask/Cargo.toml",
                &format!(
                    "{XTASK_MANIFEST}support = {{ package = \"release-glz-test-support\", path = \"../crates/test-support\" }}\n"
                )
            ),
            ["xtask/Cargo.toml: crate-edge: xtask depends on release-glz-test-support"]
        );
        assert_eq!(
            planted(
                "Cargo.toml",
                &ROOT_MANIFEST.replace("\n[dev-dependencies]\n", "")
            ),
            [
                "Cargo.toml: crate-edge: release-glz depends on release-glz-test-support outside dev-dependencies"
            ]
        );
        let root = clean();
        put(
            root.path(),
            "Cargo.toml",
            &ROOT_MANIFEST.replace("\"xtask\"]", "\"crates/extra\", \"xtask\"]"),
        );
        put(
            root.path(),
            "crates/extra/Cargo.toml",
            "[package]\nname = \"extra\"\n",
        );
        assert_eq!(
            keys(root.path()),
            ["crates/extra/Cargo.toml: unmapped-crate: extra has no row in EDGES"]
        );
    }

    #[test]
    fn a_manifest_allows_no_lint() {
        let support = "crates/test-support/Cargo.toml";
        assert_eq!(
            planted(
                support,
                &format!("{TEST_SUPPORT_MANIFEST}\n[lints.clippy]\npanic = \"allow\"\n")
                    .replace("[lints]\nworkspace = true\n", "")
            ),
            [format!(
                "{support}: lint-exception: [lints.clippy] allows panic"
            )]
        );
        assert_eq!(
            planted(
                "crates/release-glz-core/Cargo.toml",
                &format!(
                    "{CORE_MANIFEST}\n[lints.rust]\nmissing_docs = {{ level = \"allow\", priority = 1 }}\n"
                )
            ),
            [
                "crates/release-glz-core/Cargo.toml: lint-exception: [lints.rust] allows missing_docs"
            ]
        );
        assert_eq!(
            planted(
                "Cargo.toml",
                &format!("{ROOT_MANIFEST}too_many_lines = \"allow\"\n")
            ),
            ["Cargo.toml: lint-exception: [workspace.lints.clippy] allows too_many_lines"]
        );
    }

    #[test]
    fn the_debt_holds_exactly_the_findings_that_still_fire() {
        let root = clean();
        put(
            root.path(),
            "src/copy.rs",
            "const DIGEST_HEX_LEN: usize = 64;\n",
        );
        let found = findings(root.path()).unwrap();
        let entry = "src/copy.rs: core-rule-copy: the module defines DIGEST_HEX_LEN";
        assert!(judge(&found, &[entry]).is_clean());
        let stale = judge(&[], &[entry]);
        assert_eq!(stale.stale, [entry]);
        assert!(stale.to_string().contains("remove this entry"), "{stale}");
        let unexpected = judge(&found, &[]);
        assert_eq!(unexpected.unexpected, found);
        assert!(
            unexpected
                .to_string()
                .contains("construct the checked type in release-glz-domain"),
            "{unexpected}"
        );
        let twice = [found.clone(), found].concat();
        assert_eq!(judge(&twice, &[entry]).unexpected.len(), 1);
        assert!(judge(&twice, &[entry, entry]).is_clean());
    }

    #[test]
    fn the_repository_keeps_its_structure_within_its_debt() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let verdict = judge(&findings(root).unwrap(), DEBT);
        assert!(verdict.is_clean(), "{verdict}");
    }
}
