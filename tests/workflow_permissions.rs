//! Properties of the generated release workflow, read from its parsed YAML rather than its text.

use std::collections::BTreeSet;
use std::path::Path;

use release_glz::workflow::{CANDIDATE_ARTIFACT_PREFIX, render_configured};
use serde_norway::Value;

const ACTION: &str = "P4suta/release-glz@abcdef0123456789abcdef0123456789abcdef01";

fn workflow() -> Value {
    workflow_for(Path::new("packages/widget/gleam.toml"))
}

fn workflow_for(manifest: &Path) -> Value {
    let rendered = render_configured(
        "main",
        manifest,
        "1.19.2",
        "release",
        "HEXPM_API_KEY",
        "release-glz/",
        ACTION.split_once('@').unwrap().1,
    )
    .unwrap();
    serde_norway::from_str(&rendered).unwrap()
}

/// The commands the Action accepts, read from its source so a new one needs a classification here.
fn action_commands() -> BTreeSet<String> {
    let source = std::fs::read_to_string("action/index.js").unwrap();
    let list = source
        .split_once("const SUPPORTED_COMMANDS = new Set([")
        .unwrap()
        .1
        .split_once("]);")
        .unwrap()
        .0;
    list.split(',')
        .map(|item| item.trim().trim_matches('"').to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Whether an input value always reaches the Action as a non-empty string.
///
/// The Action treats an empty input as unset, and an expression can expand to nothing, so only literal text outside every `${{ }}` counts.
fn always_set(value: &str) -> bool {
    let mut literal = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${{") {
        literal.push_str(&rest[..start]);
        let Some(end) = rest[start..].find("}}") else {
            return false;
        };
        rest = &rest[start + end + 2..];
    }
    literal.push_str(rest);
    !literal.trim().is_empty()
}

/// Whether one run of the Action with these inputs starts the compiler.
fn action_compiles(with: &Value) -> bool {
    let input = |name: &str| with.get(name).and_then(Value::as_str);
    let hands_off = |name: &str| input(name).is_some_and(always_set);
    match input("command").expect("an Action step names its command") {
        "plan" | "rehearse" => true,
        "release-pr" => !hands_off("plan-file") && !hands_off("candidate"),
        "doctor" => input("candidate-build") == Some("true"),
        "verify" | "release" | "status" => false,
        other => panic!("no compiler classification for the Action command `{other}`"),
    }
}

fn steps(job: &Value) -> impl Iterator<Item = &Value> {
    job.get("steps")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
}

fn uses(step: &Value, action: &str) -> bool {
    step.get("uses")
        .and_then(Value::as_str)
        .is_some_and(|uses| uses.split('@').next() == Some(action))
}

fn compiles(job: &Value) -> bool {
    steps(job).any(|step| {
        uses(step, "erlef/setup-beam")
            || (uses(step, "P4suta/release-glz") && action_compiles(&step["with"]))
    })
}

/// Whether a job may write anything, counting the workflow default for a job without its own permissions.
fn writes(workflow: &Value, job: &Value) -> bool {
    let permissions = job.get("permissions").unwrap_or(&workflow["permissions"]);
    match permissions {
        Value::String(all) => all == "write-all",
        Value::Mapping(scopes) => scopes.values().any(|scope| scope.as_str() == Some("write")),
        _ => false,
    }
}

/// Jobs that both compile and hold a write permission.
fn compiling_write_jobs(workflow: &Value) -> Vec<String> {
    workflow["jobs"]
        .as_mapping()
        .unwrap()
        .iter()
        .filter(|(_, job)| compiles(job) && writes(workflow, job))
        .map(|(name, _)| name.as_str().unwrap().to_owned())
        .collect()
}

fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
    workflow["jobs"]
        .get(name)
        .unwrap_or_else(|| panic!("the workflow has no `{name}` job"))
}

fn action_step<'a>(job: &'a Value, command: &str) -> &'a Value {
    steps(job)
        .find(|step| {
            uses(step, "P4suta/release-glz") && step["with"]["command"].as_str() == Some(command)
        })
        .unwrap_or_else(|| panic!("no step runs `{command}`"))
}

fn checkout_ref(job: &Value) -> &str {
    steps(job)
        .find(|step| uses(step, "actions/checkout"))
        .and_then(|step| step["with"]["ref"].as_str())
        .unwrap()
}

#[test]
fn every_action_command_has_a_compiler_classification() {
    let commands = action_commands();
    assert!(commands.contains("plan") && commands.contains("release-pr"));
    for command in commands {
        let with: Value = serde_norway::from_str(&format!("command: {command}")).unwrap();
        action_compiles(&with);
    }
}

#[test]
fn no_job_that_compiles_holds_a_write_permission() {
    let workflow = workflow();
    assert_eq!(compiling_write_jobs(&workflow), Vec::<String>::new());
    assert!(compiles(job(&workflow, "plan")));
    assert!(compiles(job(&workflow, "rehearse-release-pr")));
    assert!(!compiles(job(&workflow, "release-pr")));
    assert!(!compiles(job(&workflow, "bind-release-pr")));
}

#[test]
fn the_check_finds_a_write_job_that_would_compile() {
    let mut without_plan = workflow();
    let with = without_plan["jobs"]["release-pr"]["steps"]
        .as_sequence_mut()
        .unwrap()
        .iter_mut()
        .find(|step| uses(step, "P4suta/release-glz"))
        .unwrap()["with"]
        .as_mapping_mut()
        .unwrap();
    with.remove("plan-file");
    assert_eq!(compiling_write_jobs(&without_plan), ["release-pr"]);

    for plan_file in [
        "",
        "  ",
        "${{ steps.plan.outputs.path }}",
        "${{ runner.temp",
    ] {
        let mut maybe_empty = workflow();
        maybe_empty["jobs"]["release-pr"]["steps"]
            .as_sequence_mut()
            .unwrap()
            .iter_mut()
            .find(|step| uses(step, "P4suta/release-glz"))
            .unwrap()["with"]["plan-file"] = Value::String(plan_file.to_owned());
        assert_eq!(
            compiling_write_jobs(&maybe_empty),
            ["release-pr"],
            "plan-file `{plan_file}`"
        );
    }

    let mut with_compiler = workflow();
    let setup: Value =
        serde_norway::from_str("uses: erlef/setup-beam@0000000000000000000000000000000000000000")
            .unwrap();
    with_compiler["jobs"]["bind-release-pr"]["steps"]
        .as_sequence_mut()
        .unwrap()
        .insert(0, setup);
    assert_eq!(compiling_write_jobs(&with_compiler), ["bind-release-pr"]);
}

#[test]
fn the_push_run_binds_the_intent_of_the_release_pr_head_it_wrote() {
    let workflow = workflow();
    let head = "${{ needs.release-pr.outputs.release-pr-head }}";

    let plan = job(&workflow, "plan");
    let planned = action_step(plan, "plan");
    assert!(planned["with"]["plan-file"].as_str().is_some());

    let release_pr = job(&workflow, "release-pr");
    assert_eq!(release_pr["needs"].as_str(), Some("plan"));
    let written = action_step(release_pr, "release-pr");
    assert_eq!(
        written["with"]["plan-file"].as_str(),
        planned["with"]["plan-file"]
            .as_str()
            .map(|path| path.replace(
                "release-glz-plan.json",
                "release-glz-plan/release-glz-plan.json"
            ))
            .as_deref()
    );
    let written_id = written["id"].as_str().unwrap();
    assert_eq!(
        release_pr["outputs"]["release-pr-head"].as_str(),
        Some(format!("${{{{ steps.{written_id}.outputs.release-pr-head }}}}").as_str())
    );

    let rehearse = job(&workflow, "rehearse-release-pr");
    assert_eq!(rehearse["needs"].as_str(), Some("release-pr"));
    assert_eq!(checkout_ref(rehearse), head);
    assert_eq!(
        action_step(rehearse, "rehearse")["with"]["source-ref"].as_str(),
        Some(head)
    );

    let bind = job(&workflow, "bind-release-pr");
    let needs: BTreeSet<_> = bind["needs"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|need| need.as_str().unwrap())
        .collect();
    assert_eq!(needs, BTreeSet::from(["release-pr", "rehearse-release-pr"]));
    assert_eq!(checkout_ref(bind), head);
    let bound = action_step(bind, "release-pr");
    assert!(bound["with"]["candidate"].as_str().is_some());
    assert!(bound["with"].get("dry-run").is_none());
    assert!(bound["with"].get("plan-file").is_none());
}

#[test]
fn the_candidate_artifact_carries_the_name_that_publication_accepts() {
    let workflow = workflow();
    let upload = steps(job(&workflow, "prepare"))
        .find(|step| uses(step, "actions/upload-artifact"))
        .unwrap();
    assert_eq!(
        upload["with"]["name"].as_str(),
        Some(format!("{CANDIDATE_ARTIFACT_PREFIX}${{{{ github.run_id }}}}").as_str())
    );
    let publish = job(&workflow, "publish");
    let release = action_step(publish, "release");
    assert_eq!(
        release["env"]["RELEASE_GLZ_ACTIONS_RUN_ID"].as_str(),
        Some("${{ inputs.candidate-run-id || github.run_id }}")
    );
}

/// Whether `group` makes every run of one package wait for the others and no other package wait for it.
///
/// Every run must name the same group, so the only expression it may hold is the repository, and another package's group must differ.
fn serializes_one_package(group: &str, other_package_group: &str) -> bool {
    let expressions: Vec<_> = group.match_indices("${{").collect();
    expressions.len() == 1
        && group.contains("${{ github.repository }}")
        && group != other_package_group
}

#[test]
fn only_writing_jobs_serialize_and_only_per_package() {
    let workflow = workflow();
    let other_package = workflow_for(Path::new("packages/gadget/gleam.toml"));
    assert!(workflow.get("concurrency").is_none());
    let mut groups = BTreeSet::new();
    for name in ["release-pr", "bind-release-pr", "publish"] {
        let concurrency = &job(&workflow, name)["concurrency"];
        let group = concurrency["group"].as_str().unwrap();
        let other_group = job(&other_package, name)["concurrency"]["group"]
            .as_str()
            .unwrap();
        assert!(
            serializes_one_package(group, other_group),
            "{name}: {group}"
        );
        assert_eq!(
            concurrency["cancel-in-progress"].as_bool(),
            Some(false),
            "{name}"
        );
        assert!(groups.insert(group.to_owned()), "{name} shares a group");
    }
    for name in ["plan", "prepare", "rehearse-release-pr", "authorize"] {
        assert!(job(&workflow, name).get("concurrency").is_none(), "{name}");
    }
}

#[test]
fn the_concurrency_check_refuses_per_run_and_shared_groups() {
    let group = "release-glz-publish-${{ github.repository }}-0123abcd";
    assert!(serializes_one_package(
        group,
        "release-glz-publish-${{ github.repository }}-4567ef01"
    ));
    assert!(!serializes_one_package(group, group));
    for per_run in [
        "release-glz-publish-${{ github.repository }}-0123abcd-${{ github.run_id }}",
        "release-glz-publish-${{ github.repository }}-${{ github.sha }}",
        "release-glz-publish-0123abcd",
    ] {
        assert!(
            !serializes_one_package(per_run, "release-glz-publish-other"),
            "{per_run}"
        );
    }
}

#[test]
fn the_workflow_runs_for_pushes_and_dispatches_only() {
    let workflow = workflow();
    let events: BTreeSet<_> = workflow["on"]
        .as_mapping()
        .unwrap()
        .keys()
        .map(|event| event.as_str().unwrap())
        .collect();
    assert_eq!(events, BTreeSet::from(["push", "workflow_dispatch"]));
}
