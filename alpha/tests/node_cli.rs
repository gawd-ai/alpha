//! The non-interactive `alpha node` front-ends (`--exec`, `--script`,
//! `--json`). The REPL polish that makes the daemon scriptable for demos/CI: stdout carries ONLY the
//! verb output (boot/banner go to stderr), so `--json` is machine-parseable.
//!
//! `--minimal` boots a bare kernel (no organs ⇒ no monitor sense-tape on stdout), isolating the
//! front-end plumbing from the live substrate's chatter — exactly what a JSON consumer needs.

use std::io::Write;
use std::process::Command;

/// `alpha node` — the daemon subcommand. Everything after `node` is the daemon's flag set.
fn alpha_node() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_alpha"));
    c.arg("node");
    c
}

#[test]
fn exec_help_prints_only_the_verb_output_to_stdout() {
    let out = alpha_node().args(["--minimal", "--exec", "help"]).output().expect("run alpha node");
    assert!(out.status.success(), "`--exec help` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("commands: author [--critter]"), "help text on stdout: {stdout:?}");
    // The boot banner must NOT reach stdout in non-interactive mode — it goes to stderr instead.
    assert!(!stdout.contains("Alpha Sanctum daemon"), "banner must not pollute stdout: {stdout:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Alpha Sanctum daemon"), "banner belongs on stderr: {stderr:?}");
}

#[test]
fn exec_json_status_is_machine_parseable() {
    let out = alpha_node()
        .args(["--minimal", "--json", "--exec", "status"])
        .output()
        .expect("run alpha node");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("`status --json` stdout must be a single JSON object ({e}): {stdout:?}")
    });
    assert_eq!(v["ai_allowed"], serde_json::json!(false), "allow-ai defaults off");
    assert_eq!(v["loaded"], serde_json::json!(0), "--minimal loads nothing");
}

#[test]
fn exec_json_author_critter_keeps_progress_off_stdout() {
    let out = alpha_node()
        .args(["--json", "--exec", "author --critter reverse the bytes"])
        .output()
        .expect("run alpha node");
    assert!(out.status.success(), "`--json --exec author --critter` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("author --critter --json stdout must be one JSON object ({e}): {stdout:?}")
    });
    assert_eq!(v["ok"], serde_json::json!(true), "author result should be successful: {stdout}");
    assert!(
        v["creature_id"].as_u64().is_some(),
        "author result should include the loaded critter id: {stdout}"
    );
    assert!(
        !stdout.contains("authored"),
        "progress lines must not pollute JSON stdout: {stdout:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("authored"),
        "progress should still be visible on stderr for automation logs: {stderr:?}"
    );
}

/// Deletes its path on drop — so the temp script is cleaned up even if an assertion panics.
struct TempScript(std::path::PathBuf);
impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn script_runs_lines_and_skips_comments() {
    let path = std::env::temp_dir().join(format!("sanctumd-cli-{}.gawd", std::process::id()));
    let _cleanup = TempScript(path.clone());
    {
        let mut f = std::fs::File::create(&path).expect("create script");
        writeln!(f, "# a comment line — skipped").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "help").unwrap();
        writeln!(f, "status").unwrap();
    }
    let out =
        alpha_node().args(["--minimal", "--script"]).arg(&path).output().expect("run alpha node");
    assert!(out.status.success(), "`--script` should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("commands: author"), "the `help` line ran: {stdout:?}");
    assert!(stdout.contains("allow-ai"), "the `status` line ran: {stdout:?}");
    assert!(
        !stdout.contains("# a comment"),
        "comment lines must be skipped, not echoed: {stdout:?}"
    );
}
