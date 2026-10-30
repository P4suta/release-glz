//! Every Kani harness and every negative control, run from a frozen source in the pinned image and audited before the gate relies on them.

use std::fs;
use std::path::Path;

use assurance_core::{Admission, admit_control, admit_proofs};

use crate::container::{Container, Failure, Mounts};
use crate::inventory::{CONTROLS, Control, HARNESSES, PACKAGES};
use crate::proof_report::{ProofReport, logs_supported};
use crate::source_snapshot::{SourceSnapshot, read_bounded};

/// The largest export the audit reads.
const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// The target directory inside the container, which lives in the evidence so it never shares the host's.
pub const TARGET_DIRECTORY: &str = "/evidence/kani-target";

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

    admit_every_harness(&container, &mounts, &source, root, "proofs")?;
    println!("verified all {} harnesses", HARNESSES.len());

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

/// Run every harness of the proof packages from `source` as the run `name`, and refuse unless the audit admits it.
pub fn admit_every_harness(
    container: &Container,
    mounts: &Mounts<'_>,
    source: &SourceSnapshot,
    root: &Path,
    name: &str,
) -> Result<(), Failure> {
    let export = format!("/evidence/{name}.json");
    let mut command = vec!["cargo", "kani"];
    for package in PACKAGES {
        command.extend(["--package", package]);
    }
    command.extend(["-Z", "unstable-options", "--export-json", &export]);
    let exit = container.run(mounts, &[("CARGO_TARGET_DIR", TARGET_DIRECTORY)], &command)?;
    keep_logs(mounts.evidence, name, &exit.stdout, &exit.stderr)?;
    let report = read_report(mounts.evidence, name)?;
    let mut audit = report.audit_proofs(&HARNESSES);
    audit.logs_supported = logs_supported(&exit.stdout, &exit.stderr);
    audit.source_matches = source.matches(root)?;
    let admission = admit_proofs(exit.code, audit);
    if admission != Admission::Admit {
        return Err(Failure::new(format!(
            "the proof run is refused: {admission:?}; inspect {}",
            mounts.evidence.display()
        )));
    }
    Ok(())
}

fn refused(control: &Control, admission: Admission, evidence: &Path) -> Failure {
    Failure::new(format!(
        "the negative control {} of {} is refused: {admission:?}; inspect {}",
        control.feature,
        control.harness,
        evidence.display()
    ))
}

pub fn keep_logs(evidence: &Path, name: &str, stdout: &str, stderr: &str) -> Result<(), Failure> {
    fs::write(evidence.join(format!("{name}.stdout.log")), stdout).map_err(Failure::io)?;
    fs::write(evidence.join(format!("{name}.stderr.log")), stderr).map_err(Failure::io)
}

/// Read the export of the run `name`, and keep the part the audit reads beside it.
pub fn read_report(evidence: &Path, name: &str) -> Result<ProofReport, Failure> {
    let bytes = read_bounded(&evidence.join(format!("{name}.json")), MAX_REPORT_BYTES)?;
    let report: ProofReport = serde_json::from_slice(&bytes)
        .map_err(|error| Failure::new(format!("Kani's export of {name} is unreadable: {error}")))?;
    let audited = serde_json::to_vec_pretty(&report)
        .map_err(|error| Failure::new(format!("the audited report won't serialize: {error}")))?;
    fs::write(evidence.join(format!("{name}.audited.json")), audited).map_err(Failure::io)?;
    Ok(report)
}
