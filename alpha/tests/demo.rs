//! `alpha demo` — the managed runner for the external demo registry. The demos
//! are NOT linked into alpha; `alpha demo` reads `demos/demos.json` and spawns the named demo. These
//! tests exercise the *runner* (list + resolution + error paths) without launching a full demo — the
//! runnable demos themselves are gated standalone in the one-CPU CI job.

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
fn list_shows_the_cluster_manual_runbook_tagged() {
    // ADR-0045: the cluster demo is a multi-process runbook, not runner-launchable, but it IS in the
    // registry so `alpha demo list` is authoritative and agrees with demos/README.md.
    let out = alpha_demo().arg("list").output().expect("run alpha demo list");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cluster"), "registry should list cluster: {stdout:?}");
    assert!(
        stdout.contains("manual runbook"),
        "cluster should be tagged as a manual runbook: {stdout:?}"
    );
}

#[test]
fn run_cluster_prints_the_runbook_and_exits_zero() {
    // ADR-0045: a manual demo doesn't fail with "unknown demo" (it's listed) — it points at the
    // runbook and exits cleanly, the coherent behavior for an operator following the docs.
    let out = alpha_demo().arg("run").arg("cluster").output().expect("run alpha demo run cluster");
    assert!(
        out.status.success(),
        "`alpha demo run cluster` must exit 0 (runbook pointer), not error; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("runbook"), "should print the runbook pointer: {stdout:?}");
    assert!(stdout.contains("00-build.sh"), "should show the first runbook step: {stdout:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unknown demo"),
        "a listed demo must never read as unknown: {stderr:?}"
    );
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

#[test]
fn oversized_demo_manifest_is_rejected_before_json_parse() {
    let dir = std::env::temp_dir().join(format!(
        "alpha-demo-manifest-test-{}-{}",
        process::id(),
        "oversized"
    ));
    fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("demos.json");
    fs::File::create(&manifest).unwrap().set_len(alpha::MAX_ALPHA_DEMO_MANIFEST_BYTES + 1).unwrap();

    let out = alpha_demo()
        .arg("list")
        .env("ALPHA_DEMOS_MANIFEST", &manifest)
        .output()
        .expect("run alpha demo list with oversized ALPHA_DEMOS_MANIFEST");
    assert!(!out.status.success(), "oversized demo manifest should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("alpha demo manifest"), "should name the bounded file: {stderr:?}");
    assert!(stderr.contains("exceeds"), "should explain the byte cap: {stderr:?}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn demo_manifest_rejects_cargo_feature_argument_shapes() {
    let dir = std::env::temp_dir().join(format!(
        "alpha-demo-manifest-test-{}-{}",
        process::id(),
        "bad-feature"
    ));
    fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("demos.json");
    fs::write(
        &manifest,
        r#"{
          "demos": [
            {
              "name": "unsafe-feature",
              "package": "walkthrough",
              "features": ["--release"]
            }
          ]
        }"#,
    )
    .unwrap();

    let out = alpha_demo()
        .arg("list")
        .env("ALPHA_DEMOS_MANIFEST", &manifest)
        .output()
        .expect("run alpha demo list with invalid feature metadata");
    assert!(!out.status.success(), "invalid Cargo feature syntax must fail closed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid Cargo feature"), "should explain the refusal: {stderr:?}");

    let too_long = "x".repeat(65);
    fs::write(
        &manifest,
        format!(
            r#"{{
              "demos": [
                {{
                  "name": "oversized-feature",
                  "package": "walkthrough",
                  "features": ["{too_long}"]
                }}
              ]
            }}"#
        ),
    )
    .unwrap();
    let out = alpha_demo()
        .arg("list")
        .env("ALPHA_DEMOS_MANIFEST", &manifest)
        .output()
        .expect("run alpha demo list with an oversized feature name");
    assert!(!out.status.success(), "an oversized feature name must fail closed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("at most 64 bytes"), "should explain the name cap: {stderr:?}");

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn demo_manifest_bounds_cargo_feature_count() {
    let dir = std::env::temp_dir().join(format!(
        "alpha-demo-manifest-test-{}-{}",
        process::id(),
        "too-many-features"
    ));
    fs::create_dir_all(&dir).unwrap();
    let manifest = dir.join("demos.json");
    let features =
        (0..17).map(|index| format!(r#""feature-{index}""#)).collect::<Vec<_>>().join(",");
    fs::write(
        &manifest,
        format!(
            r#"{{
              "demos": [
                {{
                  "name": "too-many-features",
                  "package": "walkthrough",
                  "features": [{features}]
                }}
              ]
            }}"#
        ),
    )
    .unwrap();

    let out = alpha_demo()
        .arg("list")
        .env("ALPHA_DEMOS_MANIFEST", &manifest)
        .output()
        .expect("run alpha demo list with too many features");
    assert!(!out.status.success(), "an oversized feature list must fail closed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("limit is 16"), "should explain the feature cap: {stderr:?}");

    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn package_demo_passes_validated_features_before_the_binary_argument_boundary() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "alpha-demo-manifest-test-{}-{}",
        process::id(),
        "feature-argv"
    ));
    let bin_dir = dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let manifest = dir.join("demos.json");
    fs::write(
        &manifest,
        r#"{
          "demos": [
            {
              "name": "feature-demo",
              "package": "demo-package",
              "features": ["openai"]
            }
          ]
        }"#,
    )
    .unwrap();

    // `alpha demo` execs `cargo` on Unix. Put a bounded local recorder first on PATH so this proves
    // the exact argv without invoking Cargo or compiling a demo.
    let fake_cargo = bin_dir.join("cargo");
    fs::write(
        &fake_cargo,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$ALPHA_FAKE_CARGO_ARGS\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_cargo).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&fake_cargo, permissions).unwrap();

    let args_file = dir.join("argv");
    let mut paths = vec![bin_dir];
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    let path = std::env::join_paths(paths).unwrap();
    let out = alpha_demo()
        .args(["run", "feature-demo", "--demo-flag", "value"])
        .env("ALPHA_DEMOS_MANIFEST", &manifest)
        .env("ALPHA_FAKE_CARGO_ARGS", &args_file)
        .env("PATH", path)
        .output()
        .expect("run alpha demo through the fake Cargo recorder");
    assert!(
        out.status.success(),
        "fake Cargo launch should succeed; stderr: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let args = fs::read_to_string(&args_file).expect("fake Cargo recorded argv");
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        [
            "run",
            "--locked",
            "-p",
            "demo-package",
            "--features",
            "openai",
            "--",
            "--demo-flag",
            "value",
        ]
    );

    let _ = fs::remove_dir_all(dir);
}
