//! The Quint model of the release protocol, checked by TLC in the pinned image, with a probe that has to fail and the traces that the replay test reads.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::container::{Container, Exit, Failure, Mounts};

/// The Quint release that `verification/quint/package.json` pins.
const QUINT_VERSION: &str = "0.33.1";

/// The model, relative to the repository.
const MODEL: &str = "verification/quint/release_run.qnt";

/// The module whose invariant the model checker proves.
const MAIN: &str = "release_run";

/// The modules whose broken runners have to violate the invariant, each with the history variable that its defect sets, so each part of the check can fail.
const PROBES: [(&str, &str); 2] = [
    ("release_run_buggy", "outOfOrder"),
    ("release_run_unfloored", "understated"),
];

/// The invariant that both modules are checked for.
const INVARIANT: &str = "safe";

/// The distinct states that TLC finds in the model, which a change of the model has to update on purpose.
const DISTINCT_STATES: u64 = 194_408;

/// The seed of the random traces.
const SEED: &str = "0x33";

/// How many random traces the replay test reads.
const RANDOM_TRACES: &str = "20";

/// The most steps a random trace takes.
const STEPS: &str = "40";

/// The committed traces, relative to the repository.
const TRACES: &str = "verification/quint/traces";

/// One TLC worker, so a check explores the states in the same order on every machine, and a heap that fits beside Apalache's in the container.
///
/// Quint starts TLC with an 8 GiB heap unless the configuration names another, and the container's 2 GiB limit would then kill it once the heap grew past that.
const TLC_CONFIG: &str = r#"{"workers": 1, "maxHeap": "-Xmx768m"}"#;

/// The heap of the Apalache JVM that translates the model for TLC.
const JAVA_OPTIONS: [(&str, &str); 1] = [("JAVA_TOOL_OPTIONS", "-Xmx768m")];

/// Where the container mounts the checkout, read-only.
const CHECKOUT: &str = "/workspace";

/// The container's own writable directory, where Apalache writes its translation.
const SCRATCH: &str = "/tmp";

/// The TLC configuration in the run's evidence, as the container sees it.
const TLC_CONFIG_PATH: &str = "/evidence/tlc.json";

/// Where Quint writes the trace of each scenario test, as the container sees it.
const SCENARIO_TRACES: &str = "/evidence/traces/release_run_{test}.itf.json";

/// Where Quint writes the random traces, as the container sees it.
const RANDOM_TRACE_PATHS: &str = "/evidence/traces/release_run.{seq}.itf.json";

/// Check the model, its probe, and its traces in the pinned image.
pub fn run(root: &Path) -> Result<(), Failure> {
    let evidence = crate::container::evidence_directory(root, "quint")?;
    fs::write(evidence.join("tlc.json"), TLC_CONFIG).map_err(Failure::io)?;
    fs::create_dir(evidence.join("traces")).map_err(Failure::io)?;
    let container = Container::build(root, &evidence, "verification/quint.Dockerfile")?;
    let version = container.output(root, &evidence, &["quint", "--version"])?;
    if version.trim() != QUINT_VERSION {
        return Err(Failure::new(format!(
            "the image runs another Quint release: {version}"
        )));
    }
    container.output(root, &evidence, &["quint", "typecheck", MODEL])?;
    container.output(
        root,
        &evidence,
        &[
            "quint",
            "test",
            MODEL,
            "--main",
            MAIN,
            "--backend",
            "typescript",
            "--out-itf",
            SCENARIO_TRACES,
        ],
    )?;
    for (probe, _) in PROBES {
        container.output(
            root,
            &evidence,
            &[
                "quint",
                "test",
                MODEL,
                "--main",
                probe,
                "--backend",
                "typescript",
            ],
        )?;
    }
    container.output(
        root,
        &evidence,
        &[
            "quint",
            "run",
            MODEL,
            "--main",
            MAIN,
            "--backend",
            "typescript",
            "--seed",
            SEED,
            "--max-samples",
            RANDOM_TRACES,
            "--n-traces",
            RANDOM_TRACES,
            "--max-steps",
            STEPS,
            "--invariant",
            INVARIANT,
            "--mbt",
            "--out-itf",
            RANDOM_TRACE_PATHS,
            "--verbosity",
            "0",
        ],
    )?;

    let checked = tlc(&container, root, &evidence, MAIN)?;
    let found = distinct_states(&checked.stdout);
    if checked.code != Some(0) || found != Some(DISTINCT_STATES) {
        return Err(Failure::new(format!(
            "TLC found {found:?} distinct states of {MAIN}, which must hold {INVARIANT} in all {DISTINCT_STATES}; see {}",
            evidence.display()
        )));
    }
    for (probe, defect) in PROBES {
        let probed = tlc(&container, root, &evidence, probe)?;
        let report = format!("{}{}", probed.stdout, probed.stderr);
        if probed.code == Some(0) || !violates(&report, defect) {
            return Err(Failure::new(format!(
                "TLC found no violation of {INVARIANT} in {probe} that sets {defect}, so nothing shows that this part of the check can fail; see {}",
                evidence.display()
            )));
        }
    }
    let traces = compare_traces(&root.join(TRACES), &evidence.join("traces"))?;
    println!(
        "Quint {QUINT_VERSION}: TLC proved {INVARIANT} in all {DISTINCT_STATES} states of {MAIN}, found the violation in each of {} probes, and Quint wrote the {traces} committed traces again; evidence in {}",
        PROBES.len(),
        evidence.display()
    );
    Ok(())
}

/// Check `module` with TLC, and keep its report in the evidence.
///
/// Apalache writes its translation next to the working directory, so the check runs from the container's own `/tmp` instead of the read-only checkout.
fn tlc(container: &Container, root: &Path, evidence: &Path, module: &str) -> Result<Exit, Failure> {
    let mounts = Mounts {
        workspace: root,
        evidence,
        network: false,
    };
    let model = format!("{CHECKOUT}/{MODEL}");
    let exit = container.run(
        &mounts,
        &JAVA_OPTIONS,
        &[
            "env",
            "-C",
            SCRATCH,
            "quint",
            "verify",
            &model,
            "--main",
            module,
            "--backend",
            "tlc",
            "--tlc-config",
            TLC_CONFIG_PATH,
            "--invariant",
            INVARIANT,
        ],
    )?;
    fs::write(
        evidence.join(format!("{module}.tlc.log")),
        format!("{}{}", exit.stdout, exit.stderr),
    )
    .map_err(Failure::io)?;
    Ok(exit)
}

/// Whether TLC's report shows a counterexample that ends with the history variable `defect` set, which records the probe's defect.
fn violates(report: &str, defect: &str) -> bool {
    let set = format!("_{defect} = TRUE");
    report.contains("found a counterexample")
        && report.lines().any(|line| line.trim_start().ends_with(&set))
}

/// The number of distinct states in TLC's final report.
fn distinct_states(report: &str) -> Option<u64> {
    report.lines().rev().find_map(|line| {
        let (_, rest) = line.split_once(" states generated, ")?;
        rest.split_once(" distinct states found")?.0.parse().ok()
    })
}

/// The variables and states of an ITF trace, without the metadata that says when Quint wrote it.
fn states(text: &str) -> Result<(Value, Value), Failure> {
    let document: Value = serde_json::from_str(text)
        .map_err(|error| Failure::new(format!("a trace isn't JSON: {error}")))?;
    Ok((document["vars"].clone(), document["states"].clone()))
}

/// The names of the traces in `directory`, in order.
fn trace_names(directory: &Path) -> Result<Vec<String>, Failure> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory).map_err(Failure::io)? {
        let name = entry.map_err(Failure::io)?.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| Failure::new("a trace has a name that isn't UTF-8"))?;
        if name.ends_with(".itf.json") {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Require the traces that Quint wrote again to equal the committed ones, and return how many there are.
fn compare_traces(committed: &Path, written: &Path) -> Result<usize, Failure> {
    let names = trace_names(committed)?;
    if names != trace_names(written)? {
        return Err(Failure::new(format!(
            "Quint writes other traces than {} holds; regenerate them and review the change",
            committed.display()
        )));
    }
    for name in &names {
        let read = |directory: &Path| {
            fs::read_to_string(directory.join(name))
                .map_err(Failure::io)
                .and_then(|text| states(&text))
        };
        if read(committed)? != read(written)? {
            return Err(Failure::new(format!(
                "{name} differs from the trace Quint writes; regenerate it and review the change"
            )));
        }
    }
    Ok(names.len())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{PROBES, QUINT_VERSION, compare_traces, distinct_states, violates};

    #[test]
    fn only_a_counterexample_that_sets_the_probes_defect_shows_the_probe_failing() {
        let violation = "/\\ release_run_buggy_release_run_model_outOfOrder = TRUE\n\n[violation] Found an issue (2124ms).\nerror: found a counterexample\n";
        assert!(violates(violation, "outOfOrder"));
        assert!(!violates(violation, "understated"));
        assert!(!violates(
            "error: found a counterexample\n/\\ x_outOfOrder = FALSE\n",
            "outOfOrder"
        ));
        assert!(!violates(
            "/\\ x_outOfOrder = TRUE\nerror: TLC error\n",
            "outOfOrder"
        ));
        let model = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../verification/quint/release_run.qnt"),
        )
        .unwrap();
        for (probe, defect) in PROBES {
            assert!(model.contains(&format!("module {probe} {{")), "{probe}");
            assert!(model.contains(&format!("var {defect}: bool")), "{defect}");
        }
    }

    #[test]
    fn the_final_report_names_the_distinct_states() {
        let report = "Progress(9): 295,380 states generated (295,380 s/min), 133,969 distinct states found (133,969 ds/min), 23,075 states left on queue.\nModel checking completed. No error has been found.\n476952 states generated, 188667 distinct states found, 0 states left on queue.\n";
        assert_eq!(distinct_states(report), Some(188_667));
        assert_eq!(distinct_states("Model checking completed."), None);
    }

    #[test]
    fn a_missing_extra_or_changed_trace_is_refused() {
        let trace = |state: &str| {
            format!(
                r##"{{"#meta":{{"timestamp":{}}},"vars":["x"],"states":[{{"x":{state}}}]}}"##,
                state.len()
            )
        };
        let committed = tempfile::tempdir().unwrap();
        let written = tempfile::tempdir().unwrap();
        fs::write(committed.path().join("a.itf.json"), trace("1")).unwrap();
        fs::write(written.path().join("a.itf.json"), trace("1")).unwrap();
        assert_eq!(compare_traces(committed.path(), written.path()).unwrap(), 1);

        fs::write(written.path().join("a.itf.json"), trace("22")).unwrap();
        assert!(compare_traces(committed.path(), written.path()).is_err());

        fs::write(written.path().join("a.itf.json"), trace("1")).unwrap();
        fs::write(written.path().join("b.itf.json"), trace("1")).unwrap();
        assert!(compare_traces(committed.path(), written.path()).is_err());
        assert!(compare_traces(written.path(), committed.path()).is_err());
    }

    /// The image installs the Quint release that the check expects, so a version bump has to change both.
    #[test]
    fn the_image_installs_the_quint_release_the_check_expects() {
        let package = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../verification/quint/package.json"),
        )
        .unwrap();
        assert!(package.contains(&format!("\"@informalsystems/quint\": \"{QUINT_VERSION}\"")));
    }
}
