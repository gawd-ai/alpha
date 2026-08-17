//! `alpha demo [list | run <name> | <name>]` — launch a narrated demo.
//!
//! The demos are **not** linked into the α binary. They are separate crates
//! listed in an external manifest (`demos/demos.json`), compiled separately, and added or removed by
//! editing that manifest with **no `alpha` recompile** — the same "added/removed by manifest" rule the
//! rest of the substrate applies to creatures. The front door is a *managed runner*: it resolves the
//! named demo and launches it (its cargo `package`, plus any validated package features, in a source
//! checkout, or a prebuilt `bin` for an installed alpha). On Unix the selected command replaces
//! Alpha, so signals and process ownership stay direct; other platforms wait for it and forward its
//! exit code. Running a demo crate directly (`cargo run -p walkthrough`) is unchanged.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

#[derive(Deserialize)]
struct DemoManifest {
    #[serde(default)]
    demos: Vec<DemoEntry>,
}

#[derive(Deserialize)]
struct DemoEntry {
    name: String,
    #[serde(default)]
    summary: String,
    /// Cargo workspace package to `cargo run -p` (source checkout).
    package: Option<String>,
    /// Prebuilt binary to exec (installed alpha). Wins over `package` if both are set; a relative
    /// path resolves against the manifest's directory.
    bin: Option<String>,
    /// Bounded Cargo feature names enabled when this entry is launched from its source `package`.
    /// Not forwarded when `bin` wins: a prebuilt binary already has its feature set baked in.
    #[serde(default)]
    features: Vec<String>,
    /// A **manual runbook** demo (ADR-0045): a multi-process walkthrough the runner can't launch as a
    /// single child (e.g. `cluster`, which stands up an `omega serve` + two `alpha node`s). It is
    /// *listed* (tagged `(manual runbook)`) so `alpha demo list` is authoritative, and `alpha demo run
    /// <name>` prints the runbook pointer and exits cleanly instead of failing with "unknown demo".
    #[serde(default)]
    manual: bool,
    /// Directory holding the runbook scripts (relative to the manifest dir), printed by `run` for a
    /// `manual` demo. Ignored for runner-launched demos.
    runbook: Option<String>,
}

/// Keep registry-controlled Cargo feature expansion small and predictable. These are package-local
/// feature names, not arbitrary Cargo arguments: the runner joins them into the single value after
/// `--features`, and never invokes a shell.
const MAX_DEMO_FEATURES: usize = 16;
const MAX_DEMO_FEATURE_NAME_BYTES: usize = 64;

fn validate_manifest(manifest: &DemoManifest) -> Result<(), String> {
    for demo in &manifest.demos {
        if demo.features.len() > MAX_DEMO_FEATURES {
            return Err(format!(
                "alpha demo: `{}` declares {} Cargo features; limit is {MAX_DEMO_FEATURES}",
                demo.name,
                demo.features.len()
            ));
        }
        for (index, feature) in demo.features.iter().enumerate() {
            let first_is_safe = feature
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
            let valid = first_is_safe
                && feature.len() <= MAX_DEMO_FEATURE_NAME_BYTES
                && feature
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
            if !valid {
                return Err(format!(
                    "alpha demo: `{}` has invalid Cargo feature {feature:?}; feature names must start with an ASCII alphanumeric or `_`, contain only ASCII alphanumeric, `_`, or `-` bytes, and be at most {MAX_DEMO_FEATURE_NAME_BYTES} bytes",
                    demo.name
                ));
            }
            if demo.features[..index].contains(feature) {
                return Err(format!(
                    "alpha demo: `{}` declares duplicate Cargo feature {feature:?}",
                    demo.name
                ));
            }
        }
    }
    Ok(())
}

/// Locate `demos.json`: explicit `$ALPHA_DEMOS_MANIFEST` (or legacy `$GAWD_DEMOS_MANIFEST`), then the
/// workspace's `demos/demos.json` (resolved from anywhere inside a source checkout), then
/// `./demos/demos.json`. First that exists wins.
fn manifest_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("ALPHA_DEMOS_MANIFEST") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(p) = std::env::var("GAWD_DEMOS_MANIFEST") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    [
        omni::workspace_root().join("demos").join("demos.json"),
        PathBuf::from("demos").join("demos.json"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

fn load() -> Result<(PathBuf, DemoManifest), String> {
    let path = manifest_path().ok_or_else(|| {
        "alpha demo: no demo manifest found (looked at $ALPHA_DEMOS_MANIFEST, \
         $GAWD_DEMOS_MANIFEST, <workspace>/demos/demos.json, ./demos/demos.json)."
            .to_string()
    })?;
    let text = crate::read_text_file_bounded(
        &path,
        crate::MAX_ALPHA_DEMO_MANIFEST_BYTES,
        "alpha demo manifest",
    )?;
    let manifest: DemoManifest = serde_json::from_str(&text)
        .map_err(|e| format!("alpha demo: invalid {}: {e}", path.display()))?;
    validate_manifest(&manifest)?;
    Ok((path, manifest))
}

/// Dispatch `alpha demo [list | run <name> | <name>] [args]`. With no args (or `list`) it prints the
/// registry; otherwise it spawns the named demo, passing any trailing args through.
pub fn run(args: &[String]) -> ExitCode {
    let (path, manifest) = match load() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let first = args.first().map(String::as_str);
    if first.is_none() || first == Some("list") {
        return list(&path, &manifest);
    }

    // `run <name> [args]`, or the back-compatible bare `<name> [args]`.
    let (name, rest): (&str, &[String]) = if first == Some("run") {
        match args[1..].split_first() {
            Some((n, r)) => (n.as_str(), r),
            None => {
                eprintln!("alpha demo run: needs a demo name. Try `alpha demo list`.");
                return ExitCode::from(2);
            }
        }
    } else {
        (args[0].as_str(), &args[1..])
    };

    let Some(entry) = manifest.demos.iter().find(|d| d.name == name) else {
        eprintln!(
            "alpha demo: unknown demo `{name}`. Run `alpha demo list` to see what's available."
        );
        return ExitCode::from(2);
    };
    // A manual runbook demo (e.g. `cluster`) can't be launched as one child — point at the runbook
    // and exit cleanly, never a bare "unknown demo" for a demo the docs list (ADR-0045).
    if entry.manual {
        return print_runbook(entry, &path);
    }
    spawn(entry, &path, rest)
}

/// Print the pointer to a manual runbook demo's scripts and exit cleanly (ADR-0045).
fn print_runbook(entry: &DemoEntry, manifest_path: &Path) -> ExitCode {
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let dir = entry.runbook.as_deref().unwrap_or(entry.name.as_str());
    println!(
        "`{}` is a manual, multi-process runbook — the runner can't launch it as one child.",
        entry.name
    );
    if !entry.summary.is_empty() {
        println!("\n{}", entry.summary);
    }
    println!("\nFollow the runbook in {}:", manifest_dir.join(dir).display());
    println!(
        "    cd {dir} && ./00-build.sh && ./01-boot.sh   # then 02-join, 03-graph, 04-cross-run, …"
    );
    println!("\nSee {}/README.md for the full sequence.", dir);
    ExitCode::SUCCESS
}

fn list(path: &Path, manifest: &DemoManifest) -> ExitCode {
    println!("Demos (from {}):\n", path.display());
    if manifest.demos.is_empty() {
        println!("  (none configured)");
        return ExitCode::SUCCESS;
    }
    let width = manifest.demos.iter().map(|d| d.name.len()).max().unwrap_or(0);
    for d in &manifest.demos {
        let tag = if d.manual { "  (manual runbook)" } else { "" };
        println!("  {:<width$}  {}{tag}", d.name, d.summary);
    }
    println!("\nRun one with: alpha demo run <name>  (a manual runbook prints its steps).");
    ExitCode::SUCCESS
}

fn spawn(entry: &DemoEntry, manifest_path: &Path, rest: &[String]) -> ExitCode {
    let manifest_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut cmd = if let Some(bin) = &entry.bin {
        let p = Path::new(bin);
        let exe = if p.is_absolute() { p.to_path_buf() } else { manifest_dir.join(p) };
        let mut c = Command::new(exe);
        c.args(rest);
        c
    } else if let Some(pkg) = &entry.package {
        // Build + run the demo crate from the workspace root (manifest is <root>/demos/demos.json).
        let root = manifest_dir.parent().unwrap_or_else(|| Path::new("."));
        let mut c = Command::new("cargo");
        c.current_dir(root).args(["run", "--locked", "-p", pkg]);
        if !entry.features.is_empty() {
            // One joined argument after `--features` means registry data can select only validated
            // package features; it can never grow a new Cargo flag or cross the `--` boundary.
            c.arg("--features").arg(entry.features.join(","));
        }
        c.arg("--").args(rest);
        c
    } else {
        eprintln!("alpha demo: `{}` has neither `package` nor `bin` set.", entry.name);
        return ExitCode::from(2);
    };

    // Replacing Alpha on Unix keeps one process tree: a supervisor stopping `alpha demo` signals the
    // selected Cargo/prebuilt command directly instead of leaving it orphaned behind a waiting Alpha
    // launcher. `exec()` also inherits stdio, so narration continues to stream to the terminal.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let error = cmd.exec();
        eprintln!("alpha demo: failed to launch `{}`: {error}", entry.name);
        ExitCode::FAILURE
    }

    // Windows has no `exec(2)` equivalent. Waiting still preserves the documented exit-code and
    // inherited-stdio behavior there.
    #[cfg(not(unix))]
    match cmd.status() {
        Ok(st) => st.code().map(|c| ExitCode::from(c as u8)).unwrap_or(ExitCode::FAILURE),
        Err(e) => {
            eprintln!("alpha demo: failed to launch `{}`: {e}", entry.name);
            ExitCode::FAILURE
        }
    }
}
