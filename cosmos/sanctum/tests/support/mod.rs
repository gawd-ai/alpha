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
