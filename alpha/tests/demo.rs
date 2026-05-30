//! `alpha demo` — the managed runner for the external demo registry. The demos
//! are NOT linked into alpha; `alpha demo` reads `demos/demos.json` and spawns the named demo. These
//! tests exercise the *runner* (list + resolution + error paths) without launching a full demo — the
//! demos themselves are gated standalone in CI (`cargo run -p walkthrough` / `-p federation`).

use std::process::Command;
use std::{fs, process};

fn alpha_demo() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_alpha"));
    c.arg("demo");
    c
}

#[test]
fn list_reads_the_external_manifest() {
    // The binary resolves demos.json via omni::workspace_root(), so this is cwd-independent.
    let out = alpha_demo().arg("list").output().expect("run alpha demo list");
    assert!(
        out.status.success(),
        "`alpha demo list` should exit 0; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("walkthrough"), "registry should list walkthrough: {stdout:?}");
    assert!(stdout.contains("federation"), "registry should list federation: {stdout:?}");
}

#[test]
fn no_args_prints_the_registry() {
    let out = alpha_demo().output().expect("run alpha demo");
    assert!(out.status.success(), "`alpha demo` with no args should list (exit 0)");
    assert!(String::from_utf8_lossy(&out.stdout).contains("walkthrough"));
}

#[test]
fn unknown_demo_fails_with_guidance() {
    let out = alpha_demo().arg("definitely-not-a-demo").output().expect("run alpha demo <bad>");
    assert!(!out.status.success(), "an unknown demo must be a non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown demo"), "should explain the failure: {stderr:?}");
    assert!(stderr.contains("alpha demo list"), "should point at `alpha demo list`: {stderr:?}");
}

#[test]
fn alpha_demos_manifest_env_overrides_the_default_registry() {
    let dir = std::env::temp_dir().join(format!(
        "alpha-demo-manifest-test-{}-{}",
        process::id(),
        "override"
    ));
    fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("demos.json");
    fs::write(
        &manifest,
        r#"{
          "demos": [
            { "name": "override-demo", "summary": "from ALPHA_DEMOS_MANIFEST", "bin": "noop" }
          ]
        }"#,
    )
    .unwrap();

    let out = alpha_demo()
        .arg("list")
        .env("ALPHA_DEMOS_MANIFEST", &manifest)
        .output()
        .expect("run alpha demo list with ALPHA_DEMOS_MANIFEST");
    assert!(
        out.status.success(),
        "`alpha demo list` should read the override; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("override-demo"), "override registry should be listed: {stdout:?}");
    assert!(!stdout.contains("walkthrough"), "default registry should not be listed: {stdout:?}");

    let _ = fs::remove_dir_all(dir);
}
