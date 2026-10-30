//! Every Kani harness and every negative control, run from a frozen source in the pinned image and audited before the gate relies on them.
//!
//! The harnesses of each module get their own bounded run, so the time limit of one run never grows with the number of modules.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use assurance_core::{Admission, admit_control, admit_proofs};
use serde::Deserialize;

use crate::container::{Container, Failure, Mounts};
use crate::inventory::{CONTROLS, Control, HARNESSES, Harness, PACKAGES};
use crate::proof_report::{ProofReport, logs_supported};
use crate::source_snapshot::{SourceSnapshot, read_bounded};

/// The largest export the audit reads.
const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// The target directory inside the container, which lives in the evidence so it never shares the host's.
const TARGET_DIRECTORY: &str = "/evidence/kani-target";

/// The target directory of the census, which holds nothing but that one build.
const CENSUS_DIRECTORY: &str = "kani-census";

/// The end of the name of the file in which Kani's compiler records the harnesses of a crate.
const METADATA: &str = ".kani-metadata.json";

/// One harness that Kani's compiler found in a crate.
#[derive(Debug, Deserialize)]
struct CompiledHarness {
    pretty_name: String,
}

/// What Kani's compiler records about one crate.
#[derive(Debug, Deserialize)]
struct Metadata {
    crate_name: String,
    proof_harnesses: Vec<CompiledHarness>,
}

/// The harnesses of one module, which one bounded run proves.
#[derive(Debug, Clone)]
struct Module {
    package: &'static str,
    /// The harness filter that selects them, which starts the name of each one.
    filter: String,
    harnesses: Vec<Harness>,
}

impl Module {
    /// The name of its run in the evidence.
    fn label(&self) -> String {
        let module = self
            .filter
            .trim_end_matches("proofs::")
            .trim_end_matches("::");
        format!(
            "{}-{}",
            self.package,
            if module.is_empty() { "lib" } else { module }
        )
    }
}

/// The module of the harness `name`: its path up to and including the last `::`, which every harness of that module starts with.
fn module_of(name: &str) -> Option<&str> {
    name.rfind("::").and_then(|end| name.get(..end + 2))
}

/// Split the inventory into the modules of the harnesses that the compiler found, by package.
///
/// It refuses a harness that only the compiler or only the inventory names, and a harness outside every module.
/// Kani selects a module's harnesses by a substring of their names, so it also refuses a module whose filter another module's harness contains.
fn split(
    compiled: &BTreeMap<String, &'static str>,
    harnesses: &[Harness],
) -> Result<Vec<Module>, Failure> {
    let listed = harnesses
        .iter()
        .map(|harness| harness.name)
        .collect::<BTreeSet<_>>();
    let found = compiled.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if listed.len() != harnesses.len() || listed != found {
        return Err(Failure::new(format!(
            "Kani's compiler and the inventory name different harnesses: only the compiler found {:?}, and only the inventory lists {:?}",
            found.difference(&listed).collect::<Vec<_>>(),
            listed.difference(&found).collect::<Vec<_>>()
        )));
    }
    let mut modules = BTreeMap::<(&str, &str), Module>::new();
    for harness in harnesses {
        let package = compiled[harness.name];
        let filter = module_of(harness.name).ok_or_else(|| {
            Failure::new(format!(
                "the harness {} lies outside every module",
                harness.name
            ))
        })?;
        modules
            .entry((package, filter))
            .or_insert_with(|| Module {
                package,
                filter: filter.to_owned(),
                harnesses: Vec::new(),
            })
            .harnesses
            .push(*harness);
    }
    let modules = modules.into_values().collect::<Vec<_>>();
    for module in &modules {
        if let Some((name, _)) = compiled.iter().find(|(name, package)| {
            **package == module.package
                && module_of(name) != Some(module.filter.as_str())
                && name.contains(&module.filter)
        }) {
            return Err(Failure::new(format!(
                "the filter {} of {} would also select {name}",
                module.filter, module.package
            )));
        }
    }
    Ok(modules)
}

/// Every file under `directory` in which Kani's compiler recorded a crate, without following links.
fn metadata_files(directory: &Path) -> Result<Vec<PathBuf>, Failure> {
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(Failure::io)? {
            let entry = entry.map_err(Failure::io)?;
            let kind = entry.file_type().map_err(Failure::io)?;
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(METADATA))
            {
                files.push(path);
            }
        }
    }
    Ok(files)
}

/// The package of every harness that Kani's compiler records in `files`, one file for each proof package.
fn census_of(files: &[PathBuf]) -> Result<BTreeMap<String, &'static str>, Failure> {
    let mut compiled = BTreeMap::new();
    let mut crates = BTreeSet::new();
    for file in files {
        let metadata: Metadata = serde_json::from_slice(&read_bounded(file, MAX_REPORT_BYTES)?)
            .map_err(|error| Failure::new(format!("{} is unreadable: {error}", file.display())))?;
        let package = PACKAGES
            .into_iter()
            .find(|package| package.replace('-', "_") == metadata.crate_name)
            .ok_or_else(|| {
                Failure::new(format!(
                    "the census compiled {}, which no proof package is",
                    metadata.crate_name
                ))
            })?;
        if !crates.insert(package) {
            return Err(Failure::new(format!(
                "the census recorded {package} more than once"
            )));
        }
        for harness in metadata.proof_harnesses {
            if compiled
                .insert(harness.pretty_name.clone(), package)
                .is_some()
            {
                return Err(Failure::new(format!(
                    "two proof packages hold the harness {}",
                    harness.pretty_name
                )));
            }
        }
    }
    if crates.len() != PACKAGES.len() {
        return Err(Failure::new(format!(
            "the census recorded {crates:?} instead of every proof package"
        )));
    }
    Ok(compiled)
}

/// The package of every harness that Kani's compiler finds in the proof packages, from a build that compiles every harness and verifies none.
///
/// The compiler finds a harness however its module reaches the crate, so the gate never depends on how the sources are laid out.
fn census(
    container: &Container,
    mounts: &Mounts<'_>,
) -> Result<BTreeMap<String, &'static str>, Failure> {
    let target = format!("/evidence/{CENSUS_DIRECTORY}");
    let mut command = vec!["cargo", "kani"];
    for package in PACKAGES {
        command.extend(["--package", package]);
    }
    command.push("--only-codegen");
    let exit = container.run(mounts, &[("CARGO_TARGET_DIR", target.as_str())], &command)?;
    keep_logs(mounts.evidence, "census", &exit.stdout, &exit.stderr)?;
    if exit.code != Some(0) {
        return Err(Failure::new(format!(
            "the census build exited with {:?}; inspect {}",
            exit.code,
            mounts.evidence.display()
        )));
    }
    census_of(&metadata_files(&mounts.evidence.join(CENSUS_DIRECTORY))?)
}

/// Run every harness and every negative control, and refuse unless each run is admitted.
pub fn run(root: &Path) -> Result<(), Failure> {
    let evidence = crate::container::evidence_directory(root, "proofs")?;
    println!("proof evidence: {}", evidence.display());
    let source = SourceSnapshot::capture(root, &evidence)?;
    let container = Container::build(root, &evidence, "verification/kani.Dockerfile")?;
    println!(
        "proof image {}; frozen source {} in {} files",
        container.image(),
        source.digest,
        source.files
    );
    let mounts = Mounts {
        workspace: source.path(),
        evidence: &evidence,
        // Cargo resolves the whole workspace, whose registry dependencies the image doesn't hold.
        network: true,
    };
    let environment = [("CARGO_TARGET_DIR", TARGET_DIRECTORY)];

    let modules = admit_every_harness(&container, &mounts, &source, root, "proofs")?;
    println!(
        "verified all {} harnesses in {modules} module runs",
        HARNESSES.len()
    );

    for (index, control) in CONTROLS.iter().enumerate() {
        let name = format!("control-{index:02}");
        let export = format!("/evidence/{name}.json");
        let exit = container.run(
            &mounts,
            &environment,
            &[
                "cargo",
                "kani",
                "--package",
                control.package,
                "--features",
                control.feature,
                "--harness",
                control.harness,
                "--exact",
                "-Z",
                "unstable-options",
                "--export-json",
                &export,
            ],
        )?;
        keep_logs(&evidence, &name, &exit.stdout, &exit.stderr)?;
        let report = read_report(&evidence, &name)?;
        let mut audit = report.audit_control(control);
        audit.logs_supported = logs_supported(&exit.stdout, &exit.stderr);
        audit.source_matches = source.matches(root)?;
        let admission = admit_control(exit.code, audit);
        if admission != Admission::Admit {
            return Err(refused(control, admission, &evidence));
        }
        println!("{} fails {} as expected", control.feature, control.harness);
    }
    fs::write(
        evidence.join("receipt.txt"),
        format!(
            "source {}\nfiles {}\nimage {}\nharnesses {}\nmodule runs {modules}\nnegative controls {}\nverdict admitted\n",
            source.digest,
            source.files,
            container.image(),
            HARNESSES.len(),
            CONTROLS.len()
        ),
    )
    .map_err(Failure::io)?;
    println!(
        "admitted {} harnesses and {} negative controls",
        HARNESSES.len(),
        CONTROLS.len()
    );
    Ok(())
}

/// Prove every harness of the inventory from `source`, one bounded run per module named after `name`, and refuse unless the audit admits each run.
///
/// It returns the number of module runs.
pub fn admit_every_harness(
    container: &Container,
    mounts: &Mounts<'_>,
    source: &SourceSnapshot,
    root: &Path,
    name: &str,
) -> Result<usize, Failure> {
    let modules = split(&census(container, mounts)?, &HARNESSES)?;
    for module in &modules {
        let run = format!("{name}-{}", module.label());
        let export = format!("/evidence/{run}.json");
        let exit = container.run(
            mounts,
            &[("CARGO_TARGET_DIR", TARGET_DIRECTORY)],
            &[
                "cargo",
                "kani",
                "--package",
                module.package,
                "--harness",
                &module.filter,
                "-Z",
                "unstable-options",
                "--export-json",
                &export,
            ],
        )?;
        keep_logs(mounts.evidence, &run, &exit.stdout, &exit.stderr)?;
        let report = read_report(mounts.evidence, &run)?;
        let mut audit = report.audit_proofs(&module.harnesses);
        audit.logs_supported = logs_supported(&exit.stdout, &exit.stderr);
        audit.source_matches = source.matches(root)?;
        let admission = admit_proofs(exit.code, audit);
        if admission != Admission::Admit {
            return Err(Failure::new(format!(
                "the proof run of {} in {} is refused: {admission:?}; inspect {}",
                module.filter,
                module.package,
                mounts.evidence.display()
            )));
        }
        println!(
            "verified the {} harnesses of {} in {}",
            module.harnesses.len(),
            module.filter,
            module.package
        );
    }
    Ok(modules.len())
}

fn refused(control: &Control, admission: Admission, evidence: &Path) -> Failure {
    Failure::new(format!(
        "the negative control {} of {} is refused: {admission:?}; inspect {}",
        control.feature,
        control.harness,
        evidence.display()
    ))
}

fn keep_logs(evidence: &Path, name: &str, stdout: &str, stderr: &str) -> Result<(), Failure> {
    fs::write(evidence.join(format!("{name}.stdout.log")), stdout).map_err(Failure::io)?;
    fs::write(evidence.join(format!("{name}.stderr.log")), stderr).map_err(Failure::io)
}

/// Read the export of the run `name`, and keep the part the audit reads beside it.
fn read_report(evidence: &Path, name: &str) -> Result<ProofReport, Failure> {
    let bytes = read_bounded(&evidence.join(format!("{name}.json")), MAX_REPORT_BYTES)?;
    let report: ProofReport = serde_json::from_slice(&bytes)
        .map_err(|error| Failure::new(format!("Kani's export of {name} is unreadable: {error}")))?;
    let audited = serde_json::to_vec_pretty(&report)
        .map_err(|error| Failure::new(format!("the audited report won't serialize: {error}")))?;
    fs::write(evidence.join(format!("{name}.audited.json")), audited).map_err(Failure::io)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use super::{census_of, metadata_files, module_of, split};
    use crate::inventory::{HARNESSES, Harness};

    fn harness(name: &'static str) -> Harness {
        Harness { name, covers: 0 }
    }

    fn compiled(entries: &[(&str, &'static str)]) -> BTreeMap<String, &'static str> {
        entries
            .iter()
            .map(|(name, package)| ((*name).to_owned(), *package))
            .collect()
    }

    #[test]
    fn a_harness_belongs_to_the_module_its_name_starts_with() {
        assert_eq!(module_of("run::proofs::a"), Some("run::proofs::"));
        assert_eq!(module_of("proofs::a"), Some("proofs::"));
        assert_eq!(module_of("a::b::proofs::c"), Some("a::b::proofs::"));
        assert_eq!(module_of("a"), None);
    }

    #[test]
    fn each_harness_of_the_inventory_runs_once_in_the_run_of_its_own_module() {
        // The harnesses of `assurance-core` live at its root, and those of `release-glz-core` in its modules.
        let census = HARNESSES
            .iter()
            .map(|harness| {
                let package = if harness.name.starts_with("proofs::") {
                    "assurance-core"
                } else {
                    "release-glz-core"
                };
                (harness.name.to_owned(), package)
            })
            .collect();
        let modules = split(&census, &HARNESSES).unwrap();
        let mut proved = BTreeSet::new();
        for module in &modules {
            assert!(!module.harnesses.is_empty());
            for harness in &module.harnesses {
                assert!(harness.name.starts_with(&module.filter));
                assert!(proved.insert(harness.name), "{} runs twice", harness.name);
            }
        }
        assert_eq!(proved.len(), HARNESSES.len());
        let labels = modules
            .iter()
            .map(super::Module::label)
            .collect::<BTreeSet<_>>();
        assert_eq!(labels.len(), modules.len(), "two runs share a name");
        assert!(labels.contains("assurance-core-lib") && labels.contains("release-glz-core-run"));
    }

    #[test]
    fn the_split_refuses_a_harness_that_only_the_compiler_or_the_inventory_names() {
        let census = compiled(&[("run::proofs::a", "core"), ("run::proofs::b", "core")]);
        let both = [harness("run::proofs::a"), harness("run::proofs::b")];
        assert_eq!(split(&census, &both).unwrap().len(), 1);
        assert!(split(&census, &both[..1]).is_err());
        let unknown = [both[0], both[1], harness("run::proofs::c")];
        assert!(split(&census, &unknown).is_err());
        let twice = [both[0], both[1], both[1]];
        assert!(split(&census, &twice).is_err());
        let outside = compiled(&[("a", "core")]);
        assert!(split(&outside, &[harness("a")]).is_err());
    }

    #[test]
    fn the_split_refuses_a_filter_that_selects_another_modules_harness() {
        let harnesses = [harness("run::proofs::a"), harness("rerun::proofs::b")];
        let overlapping = compiled(&[("run::proofs::a", "core"), ("rerun::proofs::b", "core")]);
        assert!(split(&overlapping, &harnesses).is_err());
        let apart = compiled(&[("run::proofs::a", "core"), ("rerun::proofs::b", "other")]);
        assert_eq!(split(&apart, &harnesses).unwrap().len(), 2);
    }

    #[test]
    fn the_census_reads_exactly_one_record_of_each_proof_package() {
        let directory = tempfile::tempdir().unwrap();
        let core = directory
            .path()
            .join("kani/x86_64/debug/build/release-glz-core/1/out");
        let assurance = directory
            .path()
            .join("kani/x86_64/debug/build/assurance-core/2/out");
        fs::create_dir_all(&core).unwrap();
        fs::create_dir_all(&assurance).unwrap();
        fs::write(
            core.join("release_glz_core-1.kani-metadata.json"),
            r#"{"crate_name":"release_glz_core","proof_harnesses":[{"pretty_name":"run::proofs::a","crate_name":"release_glz_core"}],"test_harnesses":[]}"#,
        )
        .unwrap();
        fs::write(
            assurance.join("assurance_core-2.kani-metadata.json"),
            r#"{"crate_name":"assurance_core","proof_harnesses":[{"pretty_name":"proofs::b"}]}"#,
        )
        .unwrap();
        fs::write(assurance.join("assurance_core-2.json"), "{}").unwrap();
        let files = metadata_files(directory.path()).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(
            census_of(&files).unwrap(),
            compiled(&[
                ("run::proofs::a", "release-glz-core"),
                ("proofs::b", "assurance-core")
            ])
        );
        assert!(census_of(&[files[0].clone(), files[0].clone(), files[1].clone()]).is_err());
        assert!(census_of(&files[..1]).is_err());
        fs::write(
            assurance.join("serde-3.kani-metadata.json"),
            r#"{"crate_name":"serde","proof_harnesses":[]}"#,
        )
        .unwrap();
        assert!(census_of(&metadata_files(directory.path()).unwrap()).is_err());
    }
}
