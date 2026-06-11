//! `alpha demo [list | run <name> | <name>]` — launch a narrated demo.
//!
//! The demos are **not** linked into the α binary. They are separate crates
//! listed in an external manifest (`demos/demos.json`), compiled separately, and added or removed by
//! editing that manifest with **no `alpha` recompile** — the same "added/removed by manifest" rule the
//! rest of the substrate applies to creatures. The front door is a *managed runner*: it resolves the
//! named demo and **spawns** it (its cargo `package` in a source checkout, or a prebuilt `bin` for an
//! installed alpha), streaming the child's output and forwarding its exit code. Running a demo crate
//! directly (`cargo run -p walkthrough`) is unchanged.

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
    spawn(entry, &path, rest)
}

fn list(path: &Path, manifest: &DemoManifest) -> ExitCode {
    println!("Demos (from {}):\n", path.display());
    if manifest.demos.is_empty() {
        println!("  (none configured)");
        return ExitCode::SUCCESS;
    }
    let width = manifest.demos.iter().map(|d| d.name.len()).max().unwrap_or(0);
    for d in &manifest.demos {
        println!("  {:<width$}  {}", d.name, d.summary);
    }
    println!("\nRun one with: alpha demo run <name>");
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
        c.current_dir(root).args(["run", "-p", pkg, "--"]).args(rest);
        c
    } else {
        eprintln!("alpha demo: `{}` has neither `package` nor `bin` set.", entry.name);
        return ExitCode::from(2);
    };

    // `status()` inherits the parent's stdio, so the demo's narration streams to the terminal.
    match cmd.status() {
        Ok(st) => st.code().map(|c| ExitCode::from(c as u8)).unwrap_or(ExitCode::FAILURE),
        Err(e) => {
            eprintln!("alpha demo: failed to launch `{}`: {e}", entry.name);
            ExitCode::FAILURE
        }
    }
}
