#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use release_glz::config::HookConfig;
use release_glz::hooks::{HookContext, HookRunner};
use semver::Version;

/// Seconds the hook may run, which leave PowerShell time to start its child before the timeout.
const HOOK_TIMEOUT_SECONDS: u64 = 10;

#[tokio::test]
async fn hook_timeout_ends_every_process_the_hook_started() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let pid_file = outside.path().join("grandchild.pid");
    let script = format!(
        "$child = Start-Process -FilePath '{}' -ArgumentList '-n','300','127.0.0.1' -NoNewWindow -PassThru; Set-Content -LiteralPath '{}' -Value $child.Id -NoNewline; Start-Sleep -Seconds 300",
        system32("PING.EXE").display(),
        pid_file.display()
    );
    let hook = powershell_hook("lingering-child", script);

    let started = Instant::now();
    let error = HookRunner::default()
        .run_verify(&[hook], temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(started.elapsed() < Duration::from_secs(60));
    assert!(error.contains("timed out"), "{error}");

    let grandchild =
        fs::read_to_string(&pid_file).expect("the hook started its child before the timeout");
    let deadline = Instant::now() + Duration::from_secs(30);
    while process_is_alive(&grandchild) {
        assert!(
            Instant::now() < deadline,
            "grandchild {grandchild} outlived the timed-out hook"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_hook_that_exits_with_an_error_reports_failure() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();

    let error = HookRunner::default()
        .run_verify(
            &[powershell_hook("nonzero", "exit 17".into())],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("reported failure"), "{error}");
}

/// A required hook that runs `script` in Windows PowerShell.
fn powershell_hook(id: &str, script: String) -> HookConfig {
    HookConfig {
        id: id.into(),
        argv: vec![
            system32(r"WindowsPowerShell\v1.0\powershell.exe")
                .to_string_lossy()
                .into_owned(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            script,
        ],
        timeout_seconds: HOOK_TIMEOUT_SECONDS,
        required: true,
        // Windows reads environment names without regard to case, so the uppercase names that hook configuration requires still reach PowerShell.
        env: ["SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA"]
            .map(String::from)
            .to_vec(),
    }
}

/// A program in the Windows system directory, named by an absolute path because hooks start with an empty environment.
fn system32(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("Windows sets SystemRoot"))
        .join("System32")
        .join(program)
}

fn process_is_alive(pid: &str) -> bool {
    let output = Command::new(system32("tasklist.exe"))
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
}

fn context() -> HookContext {
    HookContext {
        package: "widget".into(),
        version: Version::new(1, 2, 3),
        source_sha: "a".repeat(40),
        intent_digest: None,
        candidate_digest: None,
        idempotency_key: None,
    }
}
