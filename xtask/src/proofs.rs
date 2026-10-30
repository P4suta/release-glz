//! Every Kani harness and every negative control, run from a frozen source in the pinned image and audited before the gate relies on them.
//!
//! Each harness gets its own bounded run, so neither the time nor the memory of one run grows with the other harnesses.

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

/// One harness of the inventory and the package that holds it, which one bounded run proves.
#[derive(Debug, Clone, Copy)]
pub struct Proof {
    pub package: &'static str,
    pub harness: Harness,
}

impl Proof {
    /// The name of its run in the evidence, which `-` keeps apart from every other harness because a name holds `-` nowhere else.
    fn label(&self) -> String {
        format!("{}-{}", self.package, self.harness.name.replace("::", "-"))
    }

    /// The arguments of the Kani run that proves exactly this harness and exports its report to `export`.
    fn arguments<'a>(&'a self, export: &'a str) -> [&'a str; 11] {
        [
            "cargo",
            "kani",
            "--package",
            self.package,
            "--harness",
            self.harness.name,
            "--exact",
            "-Z",
            "unstable-options",
            "--export-json",
            export,
        ]
    }
}

/// Pair each harness of the inventory with the package in which the compiler found it, in the order of the inventory.
///
/// It refuses a harness that only the compiler or only the inventory names.
fn proofs_to_run(
    compiled: &BTreeMap<String, &'static str>,
    harnesses: &[Harness],
) -> Result<Vec<Proof>, Failure> {
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
    Ok(harnesses
        .iter()
        .map(|harness| Proof {
            package: compiled[harness.name],
            harness: *harness,
        })
        .collect())
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

    let proofs = admit_every_harness(&container, &mounts, &source, root, "proofs")?;
    println!(
        "verified all {} harnesses, each in its own run",
        proofs.len()
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
            "source {}\nfiles {}\nimage {}\nharnesses {}\nnegative controls {}\nverdict admitted\n",
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

/// Prove every harness of the inventory from `source`, each in its own bounded run named after `name`, and refuse unless the audit admits each run.
///
/// It returns the harnesses it proved, each with its package, in the order of the inventory.
pub fn admit_every_harness(
    container: &Container,
    mounts: &Mounts<'_>,
    source: &SourceSnapshot,
    root: &Path,
    name: &str,
) -> Result<Vec<Proof>, Failure> {
    let proofs = proofs_to_run(&census(container, mounts)?, &HARNESSES)?;
    for proof in &proofs {
        let run = format!("{name}-{}", proof.label());
        let export = format!("/evidence/{run}.json");
        let exit = container.run(
            mounts,
            &[("CARGO_TARGET_DIR", TARGET_DIRECTORY)],
            &proof.arguments(&export),
        )?;
        keep_logs(mounts.evidence, &run, &exit.stdout, &exit.stderr)?;
        let report = read_report(mounts.evidence, &run)?;
        let mut audit = report.audit_proofs(&[proof.harness]);
        audit.logs_supported = logs_supported(&exit.stdout, &exit.stderr);
        audit.source_matches = source.matches(root)?;
        let admission = admit_proofs(exit.code, audit);
        if admission != Admission::Admit {
            return Err(Failure::new(format!(
                "the proof run of {} in {} is refused: {admission:?}; inspect {}",
                proof.harness.name,
                proof.package,
                mounts.evidence.display()
            )));
        }
        println!("verified {} in {}", proof.harness.name, proof.package);
    }
    Ok(proofs)
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

    use super::{Proof, census_of, metadata_files, proofs_to_run};
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
    fn each_harness_of_the_inventory_runs_once_in_a_run_of_its_own() {
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
            .collect::<BTreeMap<_, _>>();
        let proofs = proofs_to_run(&census, &HARNESSES).unwrap();
        let names = proofs
            .iter()
            .map(|proof| proof.harness.name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            HARNESSES
                .iter()
                .map(|harness| harness.name)
                .collect::<Vec<_>>()
        );
        assert!(
            proofs
                .iter()
                .all(|proof| census[proof.harness.name] == proof.package)
        );
        let labels = proofs.iter().map(Proof::label).collect::<BTreeSet<_>>();
        assert_eq!(labels.len(), proofs.len(), "two runs share a name");
    }

    #[test]
    fn a_run_selects_exactly_its_own_harness() {
        let proof = Proof {
            package: "core",
            harness: harness("run::proofs::a"),
        };
        let arguments = proof.arguments("/evidence/a.json");
        let selected = arguments
            .windows(3)
            .any(|window| window == ["--harness", "run::proofs::a", "--exact"]);
        assert!(selected, "{arguments:?}");
        assert!(
            arguments
                .windows(2)
                .any(|window| window == ["--package", "core"])
        );
        assert_eq!(arguments.last(), Some(&"/evidence/a.json"));
        assert_eq!(proof.label(), "core-run-proofs-a");
    }

    #[test]
    fn the_runs_refuse_a_harness_that_only_the_compiler_or_the_inventory_names() {
        let census = compiled(&[("run::proofs::a", "core"), ("run::proofs::b", "core")]);
        let both = [harness("run::proofs::a"), harness("run::proofs::b")];
        assert_eq!(proofs_to_run(&census, &both).unwrap().len(), 2);
        assert!(proofs_to_run(&census, &both[..1]).is_err());
        let unknown = [both[0], both[1], harness("run::proofs::c")];
        assert!(proofs_to_run(&census, &unknown).is_err());
        let twice = [both[0], both[1], both[1]];
        assert!(proofs_to_run(&census, &twice).is_err());
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
