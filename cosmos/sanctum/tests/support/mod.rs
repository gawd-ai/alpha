use std::path::PathBuf;

pub fn workspace_root() -> PathBuf {
    // sanctum's manifest dir is <root>/cosmos/sanctum; the true root (which owns
    // target/, where the fixture cdylibs land) is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

pub fn native_cdylib(lib_stem: &str) -> PathBuf {
    let file =
        format!("{}{}{}", std::env::consts::DLL_PREFIX, lib_stem, std::env::consts::DLL_SUFFIX);

    // Sanitizer and other isolated-target harnesses set an exact fixture directory. Treat it as
    // exclusive: falling back to target/debug here could silently load a stale, non-instrumented
    // cdylib and turn a green memory-safety lane into a false negative.
    if let Some(dir) = std::env::var_os("GAWD_NATIVE_FIXTURE_DIR") {
        let candidate = PathBuf::from(&dir).join(&file);
        if candidate.exists() {
            return candidate;
        }
        panic!(
            "native fixture {file} missing from configured GAWD_NATIVE_FIXTURE_DIR {}",
            PathBuf::from(dir).display()
        );
    }

    let root = workspace_root();
    let candidates = [
        root.join("target").join("debug").join("deps").join(&file),
        root.join("target").join("debug").join(&file),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return candidate;
        }
    }

    panic!("native fixture {file} missing; looked under target/debug/deps and target/debug");
}
