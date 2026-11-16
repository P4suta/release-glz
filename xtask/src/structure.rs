//! The structure gate: every release decision stays in the proved core, and every crate keeps its place.
//!
//! Each finding names the file, the rule, and the item that breaks it, and the report adds the fix.
//! [`DEBT`] holds the findings of the tree that the gate first met, and an entry that no longer fires fails the gate until a change deletes it.

use crate::container::Failure;
use crate::fs;
use proc_macro2::{TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::{Component, Path, PathBuf};
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

/// The prefix of the features that each build one negative control.
const CONTROL_FEATURE: &str = "negative-control-";

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
    ModulePath,
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
            Self::ModulePath => "module-path",
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
                "prove the module's decision in a `#[cfg(kani)] mod proofs` inside that module, and tie each harness to a negative control in xtask/src/inventory.rs"
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
            Self::ModulePath => {
                "keep the module's file inside the workspace, so the gate reads it with the rest of the crate"
            }
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
        core_dependencies(&workspace, member, allowed, &mut found);
        core_sources(&workspace, member, &mut found)?;
    }
    for name in SHELL_CRATES {
        let member = workspace.required(name)?;
        scan_sources(&workspace, member, Place::Shell, &mut found)?;
    }
    if let Some(domain) = workspace.member(DOMAIN) {
        scan_sources(&workspace, domain, Place::Domain, &mut found)?;
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

/// The path that `path` names once each `.` and `..` component is resolved without the file system, so two spellings of one file compare equal.
fn normalized(path: &Path) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match resolved.components().next_back() {
                Some(Component::Normal(_)) => {
                    resolved.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                Some(Component::CurDir | Component::ParentDir) | None => resolved.push(component),
            },
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                resolved.push(component);
            }
        }
    }
    resolved
}

/// The workspace: its root manifest and every member, the root package first.
///
/// A member is a crate that `members` lists, or a crate inside the root and outside every `exclude` entry that a member's `path` dependency names, as Cargo reads a workspace.
/// A `path` dependency elsewhere names an external crate, which the gate leaves alone.
#[derive(Debug)]
struct Workspace {
    root: PathBuf,
    manifest: DocumentMut,
    members: Vec<Member>,
}

impl Workspace {
    fn read(root: &Path) -> Result<Self, Failure> {
        let root = normalized(root);
        let manifest = manifest_at(&root, "Cargo.toml")?;
        let mut workspace = Self {
            root,
            manifest,
            members: Vec::new(),
        };
        let excluded = workspace.listed("exclude")?;
        let joins = |directory: &PathBuf| {
            directory.starts_with(&workspace.root)
                && !excluded
                    .iter()
                    .any(|exclusion| directory.starts_with(exclusion))
        };
        let mut pending = VecDeque::new();
        if workspace.manifest.contains_key("package") {
            pending.push_back(workspace.root.clone());
        }
        pending.extend(workspace.listed("members")?);
        let mut members = Vec::new();
        while let Some(directory) = pending.pop_front() {
            if members
                .iter()
                .any(|member: &Member| member.directory == directory)
            {
                continue;
            }
            let member = workspace.member_at(directory)?;
            pending.extend(
                dependencies(&member.manifest, workspace.origin(&member.directory))
                    .into_iter()
                    .filter_map(|dependency| dependency.path)
                    .filter(joins),
            );
            members.push(member);
        }
        workspace.members = members;
        Ok(workspace)
    }

    /// The directories that the `[workspace]` array under `key` lists, relative to the root.
    fn listed(&self, key: &str) -> Result<Vec<PathBuf>, Failure> {
        let listed = self
            .manifest
            .get("workspace")
            .and_then(|workspace| workspace.get(key))
            .and_then(Item::as_array);
        listed
            .into_iter()
            .flat_map(toml_edit::Array::iter)
            .map(|entry| {
                entry
                    .as_str()
                    .map(|relative| normalized(&self.root.join(relative)))
                    .ok_or_else(|| {
                        Failure::new(format!(
                            "Cargo.toml lists a workspace {key} entry that isn't a string"
                        ))
                    })
            })
            .collect()
    }

    /// The `[workspace.dependencies]` table, whose entries a member's `workspace = true` entry inherits.
    fn inherited(&self) -> Option<&Item> {
        self.manifest
            .get("workspace")
            .and_then(|workspace| workspace.get("dependencies"))
    }

    /// Where the dependency entries of the manifest in `directory` resolve.
    fn origin<'a>(&'a self, directory: &'a Path) -> Origin<'a> {
        Origin {
            directory,
            root: &self.root,
            inherited: self.inherited(),
        }
    }

    fn member_at(&self, directory: PathBuf) -> Result<Member, Failure> {
        let manifest_path = self.shown(&directory.join("Cargo.toml"))?;
        let manifest = manifest_at(&directory, &manifest_path)?;
        Member::new(directory, manifest_path, manifest)
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

/// Where the entries of one manifest's dependency tables resolve.
#[derive(Debug, Clone, Copy)]
struct Origin<'a> {
    /// The directory of the manifest, against which its own `path` keys resolve.
    directory: &'a Path,
    /// The workspace root, against which an inherited `path` key resolves.
    root: &'a Path,
    /// The `[workspace.dependencies]` table, whose entries a `workspace = true` entry inherits.
    inherited: Option<&'a Item>,
}

/// One entry of a dependency table.
#[derive(Debug)]
struct Dependency {
    /// The package it names, which a `package` key may rename.
    package: String,
    /// The directory of a local crate that a `path` key names.
    path: Option<PathBuf>,
    kind: Kind,
    optional: bool,
    default_features: bool,
}

impl Dependency {
    /// Reads one entry, whose `package` and `path` come from the workspace's definition when the entry inherits it.
    ///
    /// An inherited entry has default features unless the definition turns them off and the entry doesn't turn them back on, as Cargo reads it.
    fn read(key: &str, entry: &Item, kind: Kind, origin: Origin<'_>) -> Self {
        let inherits = entry.get("workspace").and_then(Item::as_bool) == Some(true);
        let definition = origin
            .inherited
            .filter(|_| inherits)
            .and_then(|definitions| definitions.get(key));
        let (source, base) = definition.map_or((entry, origin.directory), |definition| {
            (definition, origin.root)
        });
        let declared = |item: &Item| item.get("default-features").and_then(Item::as_bool);
        Self {
            package: source
                .get("package")
                .and_then(Item::as_str)
                .unwrap_or(key)
                .to_owned(),
            path: source
                .get("path")
                .and_then(Item::as_str)
                .map(|path| normalized(&base.join(path))),
            kind,
            optional: entry
                .get("optional")
                .and_then(Item::as_bool)
                .unwrap_or(false),
            default_features: declared(source).unwrap_or(true)
                || (definition.is_some() && declared(entry) == Some(true)),
        }
    }
}

/// Every entry of every dependency table of `manifest`, the per-target ones included.
fn dependencies(manifest: &DocumentMut, origin: Origin<'_>) -> Vec<Dependency> {
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
                        .map(|(key, entry)| Dependency::read(key, entry, kind, origin)),
                );
            }
        }
    }
    found
}

/// A proved crate names no dependency but those `allowed` in `[dependencies]`, each optional and without default features.
fn core_dependencies(
    workspace: &Workspace,
    member: &Member,
    allowed: &[&str],
    found: &mut Vec<Finding>,
) {
    for dependency in dependencies(&member.manifest, workspace.origin(&member.directory)) {
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

fn parse_text(path: &Path, text: &str) -> Result<syn::File, Failure> {
    syn::parse_file(text)
        .map_err(|error| Failure::new(format!("parsing {} failed: {error}", path.display())))
}

fn parse(path: &Path) -> Result<syn::File, Failure> {
    parse_text(path, &fs::read_to_string(path)?)
}

/// A module file that a declaration loads.
#[derive(Debug)]
struct Load {
    module: String,
    /// The path as rustc joins it, with each `.` and `..` left for the file system to resolve.
    file: PathBuf,
    /// The name of a non-`mod.rs` module file, whose child modules lie in a directory of that name.
    relative: Option<String>,
}

/// The walk over one source that finds the files its module declarations load, the way rustc resolves them.
#[derive(Debug)]
struct Loads {
    /// The directory against which the current module's declarations resolve.
    directory: PathBuf,
    /// The name of a non-`mod.rs` module file, which its inline and child modules add to their directory.
    relative: Option<String>,
    found: Vec<Load>,
}

impl Loads {
    /// The files that the declarations of `file` at `path` load, where `relative` names `path` when rustc reads it as a non-`mod.rs` module.
    fn of(file: &syn::File, path: &Path, relative: Option<String>) -> Vec<Load> {
        let mut loads = Self {
            directory: path.parent().map_or_default(Path::to_path_buf),
            relative,
            found: Vec::new(),
        };
        loads.visit_file(file);
        loads.found
    }
}

impl Visit<'_> for Loads {
    fn visit_item_mod(&mut self, node: &syn::ItemMod) {
        let (paths, always) = module_paths(&node.attrs);
        let name = node.ident.to_string();
        let nested = self.relative.as_ref().map_or_else(
            || self.directory.clone(),
            |relative| self.directory.join(relative),
        );
        let mut targets: Vec<(PathBuf, Option<String>)> = paths
            .iter()
            .map(|path| (self.directory.join(path), None))
            .collect();
        if let Some((_, items)) = &node.content {
            if !always {
                targets.push((nested.join(&name), None));
            }
            let outer = (self.directory.clone(), self.relative.take());
            for (directory, _) in targets {
                self.directory = directory;
                for item in items {
                    self.visit_item(item);
                }
            }
            (self.directory, self.relative) = outer;
        } else {
            if !always {
                targets.push((nested.join(format!("{name}.rs")), Some(name.clone())));
                targets.push((nested.join(&name).join("mod.rs"), None));
            }
            self.found
                .extend(targets.into_iter().map(|(file, relative)| Load {
                    module: name.clone(),
                    file,
                    relative,
                }));
        }
    }

    /// A block keeps the directory of its module but drops the file name, as rustc does.
    fn visit_block(&mut self, node: &syn::Block) {
        let outer = self.relative.take();
        syn::visit::visit_block(self, node);
        self.relative = outer;
    }
}

/// The text of a `path = "..."` attribute.
fn path_value(meta: &syn::Meta) -> Option<String> {
    let syn::Meta::NameValue(pair) = meta else {
        return None;
    };
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(text),
        ..
    }) = &pair.value
    else {
        return None;
    };
    pair.path.is_ident("path").then(|| text.value())
}

/// The paths that the attributes of a `cfg_attr` name, which apply only when its predicate holds.
fn conditional_paths(meta: &syn::Meta, paths: &mut Vec<String>) {
    let syn::Meta::List(list) = meta else {
        return;
    };
    let Ok(nested) =
        list.parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
    else {
        return;
    };
    for attribute in nested.iter().skip(1) {
        if let Some(path) = path_value(attribute) {
            paths.push(path);
        } else if attribute.path().is_ident("cfg_attr") {
            conditional_paths(attribute, paths);
        }
    }
}

/// The paths that a module's `#[path]` attributes name, directly or inside `cfg_attr`, and whether one names it in every build.
fn module_paths(attributes: &[syn::Attribute]) -> (Vec<String>, bool) {
    let mut paths = Vec::new();
    let mut always = false;
    for attribute in attributes {
        if let Some(path) = path_value(&attribute.meta) {
            paths.push(path);
            always = true;
        } else if attribute.path().is_ident("cfg_attr") {
            conditional_paths(&attribute.meta, &mut paths);
        }
    }
    (paths, always)
}

/// The ways rustc may read the file at `path`: as a `mod.rs`-like file, and, unless it is named `mod.rs`, as a module of its own name.
fn readings(path: &Path) -> Vec<Option<String>> {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| stem != "mod");
    let mut readings = vec![None];
    readings.extend(stem.map(Some));
    readings
}

/// The first directory of `path` that is a symbolic link with `..` right after it, where the file system leaves through the link's target and a lexical path doesn't.
fn linked_parent(path: &Path) -> Result<Option<PathBuf>, Failure> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if fs::is_symlink(&prefix)? {
                    return Ok(Some(prefix));
                }
                prefix.push(component);
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                prefix.push(component);
            }
        }
    }
    Ok(None)
}

/// Why the gate can't follow a module declaration's path, when a `..` in it leaves a symbolic link, so the file rustc reads differs from the lexical path.
fn crossed_link(workspace: &Workspace, load: &Load) -> Result<Option<String>, Failure> {
    let Some(link) = linked_parent(&load.file)?.map(|link| normalized(&link)) else {
        return Ok(None);
    };
    let place = if link.starts_with(&workspace.root) {
        format!("the symbolic link {}", workspace.shown(&link)?)
    } else {
        "a symbolic link outside the workspace".to_owned()
    };
    Ok(Some(format!(
        "`{}` resolves `..` after {place}",
        load.module
    )))
}

/// Every source of a crate, parsed: each file below its `src`, and each file that a module declaration loads from anywhere else.
///
/// A declaration whose path leaves a symbolic link by `..`, or that loads a file outside the workspace, is a finding, since the gate can't read the file rustc reads.
fn crate_sources(
    workspace: &Workspace,
    member: &Member,
    found: &mut Vec<Finding>,
) -> Result<BTreeMap<PathBuf, syn::File>, Failure> {
    let mut sources = BTreeMap::new();
    let mut pending = Vec::new();
    for path in fs::files_with_suffix(&member.directory.join("src"), ".rs")? {
        let file = parse(&path)?;
        pending.extend(
            readings(&path)
                .into_iter()
                .map(|relative| (path.clone(), relative)),
        );
        sources.insert(path, file);
    }
    let mut seen = BTreeSet::new();
    while let Some((path, relative)) = pending.pop() {
        let Some(file) = sources.get(&path) else {
            continue;
        };
        if !seen.insert((path.clone(), relative.clone())) {
            continue;
        }
        for load in Loads::of(file, &path, relative) {
            let target = normalized(&load.file);
            let refusal = if let Some(item) = crossed_link(workspace, &load)? {
                Some(item)
            } else if sources.contains_key(&target) {
                None
            } else {
                let Some(text) = fs::read_if_present(&target)? else {
                    continue;
                };
                if target.starts_with(&workspace.root) {
                    sources.insert(target.clone(), parse_text(&target, &text)?);
                    None
                } else {
                    Some(format!(
                        "`{}` loads a file outside the workspace",
                        load.module
                    ))
                }
            };
            if let Some(item) = refusal {
                let finding = Finding::new(&workspace.shown(&path)?, Rule::ModulePath, item);
                if !found.contains(&finding) {
                    found.push(finding);
                }
            } else {
                pending.push((target, load.relative));
            }
        }
    }
    Ok(sources)
}

/// The text of a finding about a module without proofs.
const UNPROVED: &str = "holds no #[cfg(kani)] mod proofs with a #[kani::proof] harness";

/// The root attributes, the proofs, and the syntax of each source of a proved crate.
fn core_sources(
    workspace: &Workspace,
    member: &Member,
    found: &mut Vec<Finding>,
) -> Result<(), Failure> {
    let library = member.directory.join("src").join("lib.rs");
    for (path, file) in crate_sources(workspace, member, found)? {
        let shown = workspace.shown(&path)?;
        let around = path != library && !has_proofs(&file.items);
        if path == library {
            root_findings(&shown, &file, found);
        } else if around {
            found.push(Finding::new(&shown, Rule::CoreUnproved, UNPROVED));
        }
        let mut unproved = Unproved {
            around,
            ..Unproved::default()
        };
        unproved.visit_file(&file);
        found.extend(unproved.found.into_iter().map(|module| {
            Finding::new(&shown, Rule::CoreUnproved, format!("`{module}` {UNPROVED}"))
        }));
        found.extend(
            Scan::hits(&file, Place::Core, &BTreeSet::new(), false)
                .into_iter()
                .map(|(rule, item)| Finding::new(&shown, rule, item)),
        );
    }
    Ok(())
}

/// The syntax findings of every source of a crate for the rules of `place`.
fn scan_sources(
    workspace: &Workspace,
    member: &Member,
    place: Place,
    found: &mut Vec<Finding>,
) -> Result<(), Failure> {
    let sources = crate_sources(workspace, member, found)?;
    let src = member.directory.join("src");
    let prelude: BTreeSet<String> = sources
        .iter()
        .filter(|(path, _)| is_crate_root(&src, path))
        .flat_map(|(_, file)| core_aliases(file))
        .collect();
    for (path, file) in &sources {
        let shown = workspace.shown(path)?;
        found.extend(
            Scan::hits(file, place, &prelude, is_crate_root(&src, path))
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

/// Whether an attribute is `#[cfg(feature = "negative-control-...")]`, which only the build of one negative control enables.
fn is_control_guard(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg")
        && attribute
            .parse_args::<syn::MetaNameValue>()
            .is_ok_and(|pair| {
                let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(feature),
                    ..
                }) = &pair.value
                else {
                    return false;
                };
                pair.path.is_ident("feature") && feature.value().starts_with(CONTROL_FEATURE)
            })
}

/// Whether the items of a module hold a `#[cfg(kani)] mod proofs` with a `#[kani::proof]` harness.
fn has_proofs(items: &[syn::Item]) -> bool {
    items.iter().any(|item| {
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
                .is_some_and(|(_, proofs)| proofs.iter().any(is_harness))
    })
}

/// Whether a module stays out of every build that ships, as proofs, tests, and negative controls do, so it needs no harness of its own.
fn is_exempt(module: &syn::ItemMod) -> bool {
    module.attrs.iter().any(|attribute| {
        is_cfg(attribute, "kani") || is_test(attribute) || is_control_guard(attribute)
    })
}

/// The walk over one source of a proved crate that names each inline module, at any depth, that holds no proofs of its own.
#[derive(Debug, Default)]
struct Unproved {
    /// The names of the modules around the current one, outermost first.
    context: Vec<String>,
    /// Whether the module around the current one holds no proofs, whose finding already covers a `mod proofs` without `cfg(kani)` inside it.
    around: bool,
    found: Vec<String>,
}

impl Visit<'_> for Unproved {
    fn visit_item_mod(&mut self, node: &syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        if is_exempt(node) {
            return;
        }
        let unproved = !has_proofs(items);
        self.context.push(node.ident.to_string());
        if unproved && !(self.around && node.ident == "proofs") {
            self.found.push(self.context.join("::"));
        }
        let around = std::mem::replace(&mut self.around, unproved);
        syn::visit::visit_item_mod(self, node);
        self.around = around;
        self.context.pop();
    }
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
        for dependency in dependencies(&member.manifest, workspace.origin(&member.directory)) {
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

/// How the negative controls enclose a piece of syntax.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Control {
    #[default]
    Outside,
    /// Inside an item that only a negative control's feature compiles.
    Guarded,
    /// Inside a negative control: an item named as one, which only a negative control's feature compiles.
    Inside,
}

/// The items around a piece of syntax that exempt it from a rule.
#[derive(Debug, Clone, Copy, Default)]
struct Flags {
    /// Inside a `#[cfg(kani)]` item, which only the proofs compile.
    kani: bool,
    /// Inside a test item, which may spell values.
    test: bool,
    control: Control,
}

impl Flags {
    fn within(self, attributes: &[syn::Attribute], name: &str) -> Self {
        let guarded = self.control != Control::Outside || attributes.iter().any(is_control_guard);
        let control =
            if self.control == Control::Inside || (guarded && name.starts_with(NEGATIVE_CONTROL)) {
                Control::Inside
            } else if guarded {
                Control::Guarded
            } else {
                Control::Outside
            };
        Self {
            kani: self.kani || attributes.iter().any(|attribute| is_cfg(attribute, "kani")),
            test: self.test || attributes.iter().any(is_test),
            control,
        }
    }
}

impl Place {
    const fn keeps(self, rule: Rule, flags: Flags) -> bool {
        match (self, rule) {
            (Self::Core, Rule::CoreStd) => true,
            (Self::Core, Rule::CoreOwned) => {
                !flags.kani && !matches!(flags.control, Control::Inside)
            }
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
        syn::UseTree::Name(name) if name.ident == "self" => leaves.push(Leaf {
            path: prefix.to_vec(),
            local: prefix.last().cloned(),
        }),
        syn::UseTree::Rename(rename) if rename.ident == "self" => leaves.push(Leaf {
            path: prefix.to_vec(),
            local: Some(rename.rename.to_string()),
        }),
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

/// The names that the `use` and `extern crate` items among `items` bind.
fn scope_leaves(items: &[&syn::Item]) -> Vec<Leaf> {
    let mut leaves = Vec::new();
    for item in items {
        if let syn::Item::Use(node) = item {
            use_leaves(&node.tree, &[], &mut leaves);
        } else if let syn::Item::ExternCrate(node) = item
            && let Some((_, alias)) = &node.rename
        {
            leaves.push(Leaf {
                path: vec![node.ident.to_string()],
                local: Some(alias.to_string()),
            });
        }
    }
    leaves
}

/// The names that the `extern crate` items of a crate root give the core crate, which every module of the crate may use.
fn core_aliases(file: &syn::File) -> impl Iterator<Item = String> + '_ {
    file.items.iter().filter_map(|item| {
        let syn::Item::ExternCrate(node) = item else {
            return None;
        };
        let (_, alias) = node.rename.as_ref()?;
        (node.ident == CORE_CRATE).then(|| alias.to_string())
    })
}

/// Whether rustc reads the file at `path` as the root of a library or binary crate whose sources lie in `src`.
fn is_crate_root(src: &Path, path: &Path) -> bool {
    let bin = src.join("bin");
    path == src.join("lib.rs")
        || path == src.join("main.rs")
        || path.parent() == Some(bin.as_path())
        || (path.ends_with("main.rs")
            && path.parent().and_then(Path::parent) == Some(bin.as_path()))
}

/// The path segments that name a module relative to the current one.
const RELATIVE: [&str; 3] = ["self", "super", "crate"];

/// The names that one module or block binds to the core crate and to its predicates.
#[derive(Debug, Clone, Default)]
struct Scope {
    /// Whether a module opens the scope, so `self` and `super` count from it, rather than a block.
    module: bool,
    /// The local names of the core crate.
    crates: BTreeSet<String>,
    /// The local names of the core predicates, each with the predicate it names.
    rules: BTreeMap<String, String>,
}

/// One name that a scope binds into the core crate.
#[derive(Debug)]
enum Binding {
    /// A name of the core crate itself.
    Crate(String),
    /// A name of a core predicate, with the predicate.
    Rule(String, String),
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
    /// The module and block scopes around the current syntax, outermost first.
    scopes: Vec<Scope>,
    /// The names that the crate root's `extern crate` items give the core crate.
    prelude: BTreeSet<String>,
    /// Whether the file is its crate's root, which `crate` names.
    root: bool,
    /// The names of the items around the current one, outermost first.
    context: Vec<String>,
    flags: Flags,
    /// How many types enclose the current syntax.
    typed: usize,
    hits: Vec<(Rule, String)>,
}

impl Scan {
    fn hits(
        file: &syn::File,
        place: Place,
        prelude: &BTreeSet<String>,
        root: bool,
    ) -> Vec<(Rule, String)> {
        let mut scan = Self {
            place,
            scopes: Vec::new(),
            prelude: prelude.clone(),
            root,
            context: Vec::new(),
            flags: Flags::default().within(&file.attrs, ""),
            typed: 0,
            hits: Vec::new(),
        };
        scan.open(true, &file.items.iter().collect::<Vec<_>>());
        scan.visit_file(file);
        scan.hits
    }

    /// Opens a module scope, or a block scope that keeps the names of the scope around it, and binds the names its `items` import.
    fn open(&mut self, module: bool, items: &[&syn::Item]) {
        let inherited = if module {
            Scope::default()
        } else {
            self.scopes.last().cloned().unwrap_or_default()
        };
        self.scopes.push(Scope {
            module,
            ..inherited
        });
        self.bind(items);
    }

    /// Binds, in the scope on top, the names that `items` import into the core crate, once the inherited names they shadow leave it.
    ///
    /// An import may name another import of the same scope, so the binding repeats until no name joins.
    fn bind(&mut self, items: &[&syn::Item]) {
        let leaves = scope_leaves(items);
        let explicit: BTreeSet<String> = leaves
            .iter()
            .filter_map(|leaf| leaf.local.clone())
            .collect();
        let Some(index) = self.scopes.len().checked_sub(1) else {
            return;
        };
        if let Some(scope) = self.scopes.last_mut() {
            scope.crates.retain(|name| !explicit.contains(name));
            scope.rules.retain(|name, _| !explicit.contains(name));
        }
        loop {
            let bindings = self.bindings(index, &leaves, &explicit);
            let Some(scope) = self.scopes.last_mut() else {
                return;
            };
            let mut joined = false;
            for binding in bindings {
                joined |= match binding {
                    Binding::Crate(name) => scope.crates.insert(name),
                    Binding::Rule(name, rule) => scope.rules.insert(name, rule).is_none(),
                };
            }
            if !joined {
                return;
            }
        }
    }

    /// The names that `leaves` bind into the core crate in the scope at `index`, where an `explicit` name shadows a glob's.
    fn bindings(&self, index: usize, leaves: &[Leaf], explicit: &BTreeSet<String>) -> Vec<Binding> {
        let mut bindings = Vec::new();
        for leaf in leaves {
            match (&leaf.local, self.resolve(index, &leaf.path)) {
                (Some(local), Some(path)) => {
                    if path.len() == 1 {
                        bindings.push(Binding::Crate(local.clone()));
                    } else if let Some(rule) = path
                        .last()
                        .filter(|last| CORE_RULES.contains(&last.as_str()))
                    {
                        bindings.push(Binding::Rule(local.clone(), rule.clone()));
                    }
                }
                (None, Some(path)) if path.len() == 1 => bindings.extend(
                    CORE_RULES
                        .iter()
                        .filter(|rule| !explicit.contains(**rule))
                        .map(|rule| Binding::Rule((*rule).to_owned(), (*rule).to_owned())),
                ),
                (None, None) => {
                    let from = self
                        .scope_of(index, &leaf.path)
                        .filter(|from| *from != index)
                        .and_then(|from| self.scopes.get(from));
                    if let Some(scope) = from {
                        let open = |name: &&String| !explicit.contains(*name);
                        bindings.extend(
                            scope
                                .crates
                                .iter()
                                .filter(open)
                                .cloned()
                                .map(Binding::Crate),
                        );
                        bindings.extend(
                            scope
                                .rules
                                .iter()
                                .filter(|(name, _)| open(name))
                                .map(|(name, rule)| Binding::Rule(name.clone(), rule.clone())),
                        );
                    }
                }
                (Some(_), None) | (None, Some(_)) => {}
            }
        }
        bindings
    }

    /// The module scope around the scope at `index`, which `self` names.
    fn module_at(&self, index: usize) -> Option<usize> {
        self.scopes
            .get(..=index)?
            .iter()
            .rposition(|scope| scope.module)
    }

    /// The scope that a path of only `self`, `super`, and `crate` names from the scope at `index`.
    fn scope_of(&self, index: usize, names: &[String]) -> Option<usize> {
        let mut at = index;
        for (position, name) in names.iter().enumerate() {
            at = match name.as_str() {
                "self" => self.module_at(at)?,
                "super" => self.module_at(self.module_at(at)?.checked_sub(1)?)?,
                "crate" if position == 0 && self.root => 0,
                _ => return None,
            };
        }
        Some(at)
    }

    /// The path from the core crate's own name that `names` reach from the scope at `index`, when its scopes bind them into the core crate.
    fn resolve(&self, index: usize, names: &[String]) -> Option<Vec<String>> {
        let relative = names
            .iter()
            .take_while(|name| RELATIVE.contains(&name.as_str()))
            .count();
        let (prefix, rest) = names.split_at_checked(relative)?;
        let scope = self.scopes.get(self.scope_of(index, prefix)?)?;
        let (first, after) = rest.split_first()?;
        let external = prefix.is_empty() && (first == CORE_CRATE || self.prelude.contains(first));
        let core = || std::iter::once(CORE_CRATE.to_owned());
        if external || scope.crates.contains(first) {
            Some(core().chain(after.iter().cloned()).collect())
        } else if after.is_empty() {
            scope
                .rules
                .get(first)
                .map(|rule| core().chain([rule.clone()]).collect())
        } else {
            None
        }
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
        let called = self
            .resolve(self.scopes.len().saturating_sub(1), names)
            .filter(|path| {
                path.last()
                    .is_some_and(|rule| CORE_RULES.contains(&rule.as_str()))
            });
        if let Some(called) = called {
            let called = called.join("::");
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
            let items = node
                .content
                .as_ref()
                .map_or_default(|(_, items)| items.iter().collect::<Vec<_>>());
            scan.open(true, &items);
            syn::visit::visit_item_mod(scan, node);
            scan.scopes.pop();
        });
    }

    fn visit_block(&mut self, node: &syn::Block) {
        let items: Vec<&syn::Item> = node
            .stmts
            .iter()
            .filter_map(|statement| {
                if let syn::Stmt::Item(item) = statement {
                    Some(item)
                } else {
                    None
                }
            })
            .collect();
        self.open(false, &items);
        syn::visit::visit_block(self, node);
        self.scopes.pop();
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

#[cfg(feature = \"negative-control-admit\")]
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

    /// The library of the release engine in a clean workspace.
    const SHELL_LIBRARY: &str = "pub fn shell(value: &str) -> String { value.to_owned() }\n";

    fn core_root() -> String {
        format!(
            "#![no_std]\n#![forbid(unsafe_code)]\n#![deny({})]\n#![cfg_attr(kani, allow(clippy::panic))]\n",
            DENIED.join(", ")
        )
    }

    /// The library of the release decisions in a clean workspace.
    fn core_library() -> String {
        format!("{}extern crate alloc;\nmod rule;\n", core_root())
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
            ("src/lib.rs", SHELL_LIBRARY),
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
        put(
            root.path(),
            "crates/release-glz-core/src/lib.rs",
            &core_library(),
        );
        put(
            root.path(),
            "crates/assurance-core/src/lib.rs",
            &core_root(),
        );
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
        planted_all(&[(relative, contents)])
    }

    /// What the gate finds in a clean workspace once each pair's contents replace the file at its path.
    fn planted_all(files: &[(&str, &str)]) -> Vec<String> {
        let root = clean();
        for (relative, contents) in files {
            put(root.path(), relative, contents);
        }
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

    /// A crate that no `members` entry lists, which allows a lint.
    const EXTRA_MANIFEST: &str =
        "[package]\nname = \"extra\"\n\n[lints.clippy]\npanic = \"allow\"\n";

    /// The findings of the crate of [`EXTRA_MANIFEST`] at `crates/extra`.
    const EXTRA: [&str; 2] = [
        "crates/extra/Cargo.toml: unmapped-crate: extra has no row in EDGES",
        "crates/extra/Cargo.toml: lint-exception: [lints.clippy] allows panic",
    ];

    #[test]
    fn a_path_dependency_joins_the_workspace_without_a_members_entry() {
        let dependency = "extra = { path = \"crates/extra\" }\n";
        let plain = ROOT_MANIFEST.replace(
            "\n[dev-dependencies]",
            &format!("{dependency}\n[dev-dependencies]"),
        );
        let targeted =
            format!("{ROOT_MANIFEST}\n[target.'cfg(unix)'.build-dependencies]\n{dependency}");
        for root in [plain, targeted] {
            assert_eq!(
                planted_all(&[
                    ("Cargo.toml", &root),
                    ("crates/extra/Cargo.toml", EXTRA_MANIFEST)
                ]),
                [
                    "Cargo.toml: crate-edge: release-glz depends on extra",
                    EXTRA[0],
                    EXTRA[1]
                ]
            );
        }
        assert_eq!(
            planted_all(&[
                (
                    "Cargo.toml",
                    &format!("{ROOT_MANIFEST}\n[workspace.dependencies]\n{dependency}")
                ),
                (
                    "xtask/Cargo.toml",
                    &format!("{XTASK_MANIFEST}extra = {{ workspace = true }}\n")
                ),
                ("crates/extra/Cargo.toml", EXTRA_MANIFEST),
            ]),
            [
                EXTRA[0],
                EXTRA[1],
                "xtask/Cargo.toml: crate-edge: xtask depends on extra"
            ]
        );
        assert_eq!(
            planted_all(&[
                (
                    "crates/test-support/Cargo.toml",
                    &TEST_SUPPORT_MANIFEST
                        .replace("\n[lints]", "extra = { path = \"../extra\" }\n\n[lints]")
                ),
                (
                    "crates/extra/Cargo.toml",
                    &EXTRA_MANIFEST.replace(
                        "\n[lints",
                        "\n[dependencies]\ndeeper = { path = \"../deeper\" }\n\n[lints"
                    )
                ),
                ("crates/deeper/Cargo.toml", "[package]\nname = \"deeper\"\n"),
            ]),
            [
                "crates/deeper/Cargo.toml: unmapped-crate: deeper has no row in EDGES",
                EXTRA[0],
                EXTRA[1],
                "crates/test-support/Cargo.toml: crate-edge: release-glz-test-support depends on extra",
            ]
        );
    }

    #[test]
    fn a_path_dependency_outside_the_workspace_or_under_an_exclusion_is_no_member() {
        let excluded = ROOT_MANIFEST
            .replace(
                "\n[dev-dependencies]",
                "extra = { path = \"crates/excluded/extra\" }\n\n[dev-dependencies]",
            )
            .replace(
                "\n\n[workspace.lints.clippy]",
                "\nexclude = [\"crates/excluded\"]\n\n[workspace.lints.clippy]",
            );
        assert_eq!(
            planted_all(&[
                ("Cargo.toml", &excluded),
                ("crates/excluded/extra/Cargo.toml", EXTRA_MANIFEST),
            ]),
            Vec::<String>::new()
        );
        let external = ROOT_MANIFEST.replace(
            "\n[dev-dependencies]",
            "outer = { path = \"../outer\" }\n\n[dev-dependencies]",
        );
        assert_eq!(planted("Cargo.toml", &external), Vec::<String>::new());
        let manifest = "crates/release-glz-core/Cargo.toml";
        assert_eq!(
            planted(
                manifest,
                &format!(
                    "{CORE_MANIFEST}outer = {{ path = \"../../../outer\", optional = true, default-features = false }}\n"
                )
            ),
            [format!("{manifest}: core-dependency: depends on outer")]
        );
    }

    #[test]
    fn an_inherited_dependency_counts_as_its_workspace_definition() {
        let support = "support = { package = \"release-glz-test-support\", path = \"crates/test-support\" }\n";
        assert_eq!(
            planted_all(&[
                (
                    "Cargo.toml",
                    &format!("{ROOT_MANIFEST}\n[workspace.dependencies]\n{support}")
                ),
                (
                    "xtask/Cargo.toml",
                    &format!("{XTASK_MANIFEST}support = {{ workspace = true }}\n")
                ),
            ]),
            ["xtask/Cargo.toml: crate-edge: xtask depends on release-glz-test-support"]
        );
        let manifest = "crates/release-glz-core/Cargo.toml";
        let inherited = "serde = { workspace = true, optional = true }\n";
        let lean = "serde = { version = \"1\", default-features = false }\n";
        let defaults = Some("serde without optional = true and default-features = false");
        let cases = [
            (inherited, "serde = { version = \"1\" }\n", defaults),
            (inherited, lean, None),
            (
                "serde = { workspace = true, optional = true, default-features = true }\n",
                lean,
                defaults,
            ),
            (
                "json = { workspace = true, optional = true }\n",
                "json = { package = \"serde_json\", version = \"1\", default-features = false }\n",
                Some("serde_json"),
            ),
        ];
        for (entry, definition, item) in cases {
            let core = format!("[package]\nname = \"release-glz-core\"\n\n[dependencies]\n{entry}");
            assert_eq!(
                planted_all(&[
                    (
                        "Cargo.toml",
                        &format!("{ROOT_MANIFEST}\n[workspace.dependencies]\n{definition}")
                    ),
                    (manifest, &core),
                ]),
                item.map(|item| format!("{manifest}: core-dependency: depends on {item}"))
                    .into_iter()
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn every_inline_core_module_proves_its_decision() {
        let unproved = |path: &str, module: &str| {
            format!(
                "{path}: core-unproved: `{module}` holds no #[cfg(kani)] mod proofs with a #[kani::proof] harness"
            )
        };
        assert_eq!(
            planted(
                RULE,
                &format!("{PROVED}pub mod hidden {{\n    pub fn admit() -> bool {{ true }}\n}}\n")
            ),
            [unproved(RULE, "hidden")]
        );
        assert_eq!(
            planted(
                RULE,
                &format!(
                    "{PROVED}mod outer {{\n    mod inner {{}}\n\n    #[cfg(kani)]\n    mod proofs {{\n        #[kani::proof]\n        fn admits() {{}}\n    }}\n}}\n"
                )
            ),
            [unproved(RULE, "outer::inner")]
        );
        let library = "crates/release-glz-core/src/lib.rs";
        let shipped = "mod proofs {\n    pub fn admit() -> bool { true }\n}\n";
        assert_eq!(
            planted(
                library,
                &format!("{}mod hidden {{}}\n{shipped}", core_library())
            ),
            [unproved(library, "hidden"), unproved(library, "proofs")]
        );
        assert_eq!(
            planted(RULE, &format!("{PROVED}#[cfg(not(kani))]\n{shipped}")),
            [unproved(RULE, "proofs")]
        );
        assert_eq!(
            planted(
                RULE,
                &format!(
                    "{PROVED}#[cfg(test)]\nmod tests {{}}\n\n#[cfg(kani)]\nmod symbolic {{}}\n\n#[cfg(feature = \"negative-control-admit\")]\nmod controls {{}}\n"
                )
            ),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_path_attribute_brings_its_file_under_the_shell_rules() {
        let copy = "const DIGEST_HEX_LEN: usize = 64;\n";
        let defines =
            |path: &str| format!("{path}: core-rule-copy: the module defines DIGEST_HEX_LEN");
        let declared = |declaration: &str| format!("{SHELL_LIBRARY}{declaration}\nmod copy;\n");
        for declaration in [
            "#[path = \"../outside/copy.rs\"]",
            "#[cfg_attr(unix, path = \"../outside/copy.rs\")]",
        ] {
            assert_eq!(
                planted_all(&[
                    ("src/lib.rs", &declared(declaration)),
                    ("outside/copy.rs", &format!("{copy}mod deeper;\n")),
                    (
                        "outside/deeper.rs",
                        "fn hex(value: &str) -> bool { value.bytes().all(|byte| byte.is_ascii_hexdigit()) }\n"
                    ),
                ]),
                [
                    defines("outside/copy.rs"),
                    "outside/deeper.rs: core-rule-copy: `hex` calls is_ascii_hexdigit".to_owned()
                ]
            );
        }
        assert_eq!(
            planted_all(&[
                ("src/lib.rs", &declared("#[path = \"copy.txt\"]")),
                ("src/copy.txt", copy),
            ]),
            [defines("src/copy.txt")]
        );
        assert_eq!(
            planted_all(&[
                (
                    "src/nested.rs",
                    "mod inline {\n    #[path = \"../../../outside/copy.rs\"]\n    mod copy;\n}\n"
                ),
                ("outside/copy.rs", copy),
            ]),
            [defines("outside/copy.rs")]
        );
    }

    #[test]
    fn a_path_attribute_brings_its_file_under_the_core_rules() {
        assert_eq!(
            planted_all(&[
                (
                    "crates/release-glz-core/src/lib.rs",
                    &format!(
                        "{}#[path = \"../../../outside/rule.rs\"]\nmod sneaky;\n",
                        core_library()
                    )
                ),
                (
                    "outside/rule.rs",
                    "pub fn read() { let _ = std::env::args(); }\n"
                ),
            ]),
            [
                "outside/rule.rs: core-std: `read` names std::env::args",
                "outside/rule.rs: core-unproved: holds no #[cfg(kani)] mod proofs with a #[kani::proof] harness",
            ]
        );
        let far = tempfile::tempdir().unwrap();
        let outside = far.path().join("far.rs");
        fs::write(&outside, "").unwrap();
        assert_eq!(
            planted(
                "src/lib.rs",
                &format!(
                    "{SHELL_LIBRARY}#[path = r\"{}\"]\nmod far;\n",
                    outside.display()
                )
            ),
            ["src/lib.rs: module-path: `far` loads a file outside the workspace"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_module_path_that_climbs_out_of_a_symbolic_link_is_refused() {
        let root = clean();
        fs::create_dir_all(root.path().join("outside/nested")).unwrap();
        put(
            root.path(),
            "outside/policy.rs",
            "const DIGEST_HEX_LEN: usize = 64;\n",
        );
        put(root.path(), "src/policy.rs", "");
        put(
            root.path(),
            "src/lib.rs",
            &format!("{SHELL_LIBRARY}#[path = \"link/../policy.rs\"]\nmod policy;\n"),
        );
        std::os::unix::fs::symlink(
            root.path().join("outside/nested"),
            root.path().join("src/link"),
        )
        .unwrap();
        assert_eq!(
            keys(root.path()),
            ["src/lib.rs: module-path: `policy` resolves `..` after the symbolic link src/link"]
        );
    }

    #[test]
    fn a_negative_control_needs_its_feature_guard() {
        let cases = [
            (
                "fn negative_control_unguarded() -> Option<String> { None }\n",
                Some("`negative_control_unguarded` names String"),
            ),
            (
                "#[cfg(not(feature = \"negative-control-broken\"))]\nfn negative_control_broken() -> Option<String> { None }\n",
                Some("`negative_control_broken` names String"),
            ),
            (
                "#[cfg(feature = \"negative-control-broken\")]\nfn broken() -> Option<String> { None }\n",
                Some("`broken` names String"),
            ),
            (
                "#[cfg(feature = \"negative-control-broken\")]\nimpl Channel {\n    fn helper() -> Option<String> { None }\n}\n",
                Some("`Channel::helper` names String"),
            ),
            (
                "#[cfg(feature = \"negative-control-broken\")]\nimpl Channel {\n    fn negative_control_broken() -> Option<String> { None }\n}\n",
                None,
            ),
        ];
        for (source, item) in cases {
            assert_eq!(
                planted(RULE, &format!("{PROVED}{source}")),
                item.map(|item| format!("{RULE}: core-owned: {item}"))
                    .into_iter()
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_crate_alias_names_the_core() {
        let call = "fn pin(value: &str) -> bool { policy::is_object_id(value.as_bytes()) }\n";
        let calls = ["src/copy.rs: core-rule-copy: `pin` calls release_glz_core::is_object_id"];
        for alias in [
            "use release_glz_core as policy;\n",
            "use ::release_glz_core::{self as policy};\n",
            "extern crate release_glz_core as policy;\n",
        ] {
            assert_eq!(planted("src/copy.rs", &format!("{alias}{call}")), calls);
        }
        assert_eq!(
            planted(
                "src/copy.rs",
                "use policy::is_object_id as valid;\nuse release_glz_core as policy;\nfn pin(value: &str) -> bool { valid(value.as_bytes()) }\n"
            ),
            calls
        );
        assert_eq!(
            planted_all(&[
                (
                    "src/lib.rs",
                    &format!("{SHELL_LIBRARY}extern crate release_glz_core as policy;\n")
                ),
                ("src/copy.rs", call),
            ]),
            calls
        );
    }

    #[test]
    fn an_import_binds_only_inside_its_scope() {
        let import = "use release_glz_core::is_object_id as valid;\n";
        let cases = [
            (
                format!(
                    "#[cfg(test)]\nmod tests {{\n    {import}}}\n\nfn valid(value: &str) -> bool {{ !value.is_empty() }}\n\nfn check(value: &str) -> bool {{ valid(value) }}\n"
                ),
                None,
            ),
            (
                format!(
                    "fn first(value: &str) -> bool {{\n    {import}    valid(value.as_bytes())\n}}\n\nfn second(value: &str) -> bool {{ valid(value) }}\n"
                ),
                Some("first"),
            ),
            (
                format!(
                    "{import}\nfn local(value: &str) -> bool {{\n    use crate::checks::valid;\n    valid(value)\n}}\n"
                ),
                None,
            ),
            (
                format!(
                    "{import}\nmod inner {{\n    use super::valid;\n\n    fn pin(value: &[u8]) -> bool {{ valid(value) }}\n}}\n"
                ),
                Some("inner::pin"),
            ),
            (
                format!(
                    "{import}\nmod inner {{\n    use super::*;\n\n    fn pin(value: &[u8]) -> bool {{ valid(value) }}\n}}\n"
                ),
                Some("inner::pin"),
            ),
        ];
        for (source, context) in cases {
            assert_eq!(
                planted("src/copy.rs", &source),
                context
                    .map(|context| format!("src/copy.rs: core-rule-copy: `{context}` calls release_glz_core::is_object_id"))
                    .into_iter()
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(
            planted(
                "src/lib.rs",
                &format!(
                    "{import}\nmod inner {{\n    use crate::valid;\n\n    fn pin(value: &[u8]) -> bool {{ valid(value) }}\n}}\n"
                )
            ),
            ["src/lib.rs: core-rule-copy: `inner::pin` calls release_glz_core::is_object_id"]
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
