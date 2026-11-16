//! A sequence of named steps that runs every step and then reports each failure together.

use crate::container::Failure;

/// The outcome of the steps run so far.
#[derive(Debug, Default)]
pub struct Report {
    failures: Vec<String>,
}

impl Report {
    /// Runs one step, recording a failure without stopping the later steps.
    pub fn stage(&mut self, name: &str, run: impl FnOnce() -> Result<(), Failure>) {
        eprintln!("==> {name}");
        if let Err(failure) = run() {
            eprintln!("{name}: {failure}");
            self.failures.push(name.to_owned());
        }
    }

    /// Succeeds when every step succeeded, and otherwise names each failed step.
    pub fn finish(self, what: &str) -> Result<(), Failure> {
        if self.failures.is_empty() {
            eprintln!("{what}: clean");
            Ok(())
        } else {
            Err(Failure::new(format!(
                "{what} failed: {}",
                self.failures.join(", ")
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Report;
    use crate::container::Failure;

    #[test]
    fn every_step_runs_and_each_failure_is_named() {
        let mut report = Report::default();
        let mut ran = Vec::new();
        report.stage("first", || {
            ran.push("first");
            Err(Failure::new("broken"))
        });
        report.stage("second", || {
            ran.push("second");
            Ok(())
        });
        report.stage("third", || {
            ran.push("third");
            Err(Failure::new("broken"))
        });
        assert_eq!(ran, ["first", "second", "third"]);
        assert_eq!(
            report.finish("steps").unwrap_err().to_string(),
            "steps failed: first, third"
        );
        Report::default().finish("steps").unwrap();
    }
}
