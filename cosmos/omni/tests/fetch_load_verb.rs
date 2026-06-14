//! The `registry fetch-load` operator workflow **over the bus**. Boots a real node, publishes a
//! creature into the local registry, then drives a single `Verb::FetchLoad` to `Role::CONTROL` and
//! asserts the whole operator path fires end-to-end: `FetchGxPlan` → a windowed `FetchGxChunk` pull →
//! `gawdxfer::ChunkAssembler` (per-chunk + whole-file SHA-256) → `kernel.load`. The loaded creature
//! then answers a `send`, proving the fetched bytes are a live, admissible artifact — not just
//! reassembled blob.
//!
//! This is the in-process twin of the cross-node GX transfer the `m2_two_node` test hand-scripts; the
//! verb encapsulates that exact choreography so an operator (or AI) issues one command instead of a
//! hand-rolled pull loop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Dispatch, Role, StubSigner, StubVerifier};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use bestiary::{RegistryReply, REGISTRY_REPLY_SCHEMA};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

use omni::{
    boot_control, boot_organs_with_monitor, recv_corr, AiControl, Verb, VerbResult, CONTROL_SCHEMA,
};

// ---- self-cleaning temp dir (no external tempdir dep) ----

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("omni-fetchload-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    /// Write a critter manifest + Rhai-script artifact; return `(manifest_path, artifact_path)`.
    fn critter_files(&self, name: &str, script: &[u8]) -> (String, String) {
        let m = Manifest::new(name, "0.2.0", Backend::Critter, "gawd_critter_v1");
        let m_path = self.0.join(format!("{name}.manifest.json"));
        std::fs::write(&m_path, serde_json::to_vec(&m).unwrap()).unwrap();
        let a_path = self.0.join(format!("{name}.rhai"));
        std::fs::write(&a_path, script).unwrap();
        (m_path.to_string_lossy().into_owned(), a_path.to_string_lossy().into_owned())
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Boot a live node with control bound on `Role::CONTROL` over the default in-memory `registry-mem`.
fn node(allow_ai: bool) -> Arc<Kernel> {
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    );
    let critter_builder = boot_organs_with_monitor(&kernel, false).expect("organs boot");
    let ai = Arc::new(AiControl::new(allow_ai));
    boot_control(&kernel, &ai, Some(critter_builder), None).expect("control boots");
    kernel
}

/// Drive one verb over the bus: ship it to `Role::CONTROL` and decode the `VerbResult` reply.
fn control(kernel: &Kernel, corr: u64, verb: &Verb) -> VerbResult {
    let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
    let payload = serde_json::to_vec(verb).unwrap();
    bus.send(
        Dispatch::to(Address::Role(Role::new(Role::CONTROL)), payload)
            .with_schema(CONTROL_SCHEMA)
            .with_reply_to(Address::Creature(probe_id))
            .with_corr(corr),
    )
    .expect("control envelope routes to Role::CONTROL");
    let reply = recv_corr(&rx, corr, Duration::from_secs(30)).expect("a VerbResult reply");
    serde_json::from_slice::<VerbResult>(&reply.payload).expect("payload is a VerbResult")
}

/// A Rhai critter that echoes its payload, padded with a comment so the artifact spans several GX
/// chunks at a small chunk size — exercising the windowed pull + assembler, not a one-chunk shortcut.
fn multichunk_echo_critter() -> Vec<u8> {
    let mut script = format!("// {}\n", "pad ".repeat(1500)); // ~6 KiB of leading comment
    script.push_str("fn handle(env) { env.payload }\n");
    script.into_bytes()
}

#[test]
fn fetch_load_pulls_over_gx_assembles_and_loads_a_runnable_creature() {
    let kernel = node(true); // allow-AI on: FetchLoad loads code → gated
    let files = TempDir::new("local");
    let script = multichunk_echo_critter();
    let (m_path, a_path) = files.critter_files("echo-pulled", &script);

    // (1) Publish the critter into the local registry — node-local paths, like `load`.
    let res = control(
        &kernel,
        1,
        &Verb::RegistryPublish { manifest_path: m_path, artifact_path: a_path, realm: None },
    );
    assert!(res.ok, "publish ok: {:?}", res.json);
    let hash =
        res.json.get("artifact_hash").and_then(|v| v.as_str()).expect("artifact_hash").to_string();

    // (2) Fetch-load it back over GX at a small chunk size (forces a multi-chunk transfer), assemble,
    // integrity-check, and admit + load — all behind one operator command.
    let res = control(
        &kernel,
        2,
        &Verb::FetchLoad {
            artifact_hash: hash.clone(),
            node: None,
            registry_id: None,
            realm: None,
            chunk_size: Some(1024),
        },
    );
    assert!(res.ok, "fetch-load ok: {:?}", res.json);
    assert!(
        res.json.get("chunks").and_then(|v| v.as_u64()).unwrap_or(0) > 1,
        "spanned >1 GX chunk"
    );
    assert_eq!(
        res.json.get("bytes").and_then(|v| v.as_u64()),
        Some(script.len() as u64),
        "fetch-load reports the assembled artifact size"
    );
    let loaded_id =
        res.json.get("creature_id").and_then(|v| v.as_u64()).expect("a loaded creature id");

    // (3) The fetched bytes are a live, admissible creature: send to it and read its echo.
    let res = control(
        &kernel,
        3,
        &Verb::Send { id: loaded_id, text: "pulled-and-running".into(), node: None },
    );
    assert!(res.ok, "send to the fetch-loaded creature ok: {:?}", res.json);
    let reply_text = res.json.get("reply").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(
        reply_text.contains("pulled-and-running"),
        "the fetch-loaded echo critter runs: {:?}",
        res.json
    );
}

#[test]
fn fetch_load_of_an_absent_hash_is_a_clean_not_found() {
    let kernel = node(true);
    // A validly-shaped (64 lowercase hex) but unpublished hash → NotFound, not a panic or a hang.
    let absent = "a".repeat(64);
    let res = control(
        &kernel,
        1,
        &Verb::FetchLoad {
            artifact_hash: absent,
            node: None,
            registry_id: None,
            realm: None,
            chunk_size: None,
        },
    );
    assert!(!res.ok, "absent fetch-load is not ok: {:?}", res.json);
    assert_eq!(res.json.get("not_found").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn fetch_load_rejects_a_gx_plan_for_a_different_artifact_hash() {
    let kernel = node(true);
    let requested = "a".repeat(64);
    let other = "b".repeat(64);

    let (registry_id, registry_bus, registry_rx) = kernel.open_endpoint(Capabilities::default());
    kernel.bind_role(Role::new(Role::REGISTRY), registry_id);
    let forged_hash = other.clone();
    let fake_registry = std::thread::spawn(move || {
        let env =
            registry_rx.recv_timeout(Duration::from_secs(5)).expect("fetch-load plan request");
        let manifest = Manifest::new("wrong-plan", "0.2.0", Backend::Critter, "gawd_critter_v1");
        let reply = RegistryReply::FetchedGx {
            manifest,
            artifact_hash: forged_hash.clone(),
            transfer_id: "wrong-transfer".into(),
            file_size: 1,
            file_hash: forged_hash,
            chunk_size: gawdxfer::MIN_CHUNK_SIZE,
            total_chunks: 1,
        };
        registry_bus
            .send(Dispatch::reply_to_env(&env, reply.to_bytes()).with_schema(REGISTRY_REPLY_SCHEMA))
            .expect("fake registry sends forged plan");

        if let Ok(env) = registry_rx.recv_timeout(Duration::from_millis(200)) {
            let reply = RegistryReply::Error {
                message: "unexpected chunk pull after mismatched plan".into(),
            };
            let _ = registry_bus.send(
                Dispatch::reply_to_env(&env, reply.to_bytes()).with_schema(REGISTRY_REPLY_SCHEMA),
            );
        }
    });

    let res = control(
        &kernel,
        1,
        &Verb::FetchLoad {
            artifact_hash: requested.clone(),
            node: None,
            registry_id: None,
            realm: None,
            chunk_size: Some(gawdxfer::MIN_CHUNK_SIZE),
        },
    );
    fake_registry.join().expect("fake registry exits");

    assert!(!res.ok, "mismatched plan is rejected: {:?}", res.json);
    let err = res.json.get("error").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(err.contains("GX plan"), "error names the plan: {err}");
    assert!(err.contains(&requested), "error includes requested hash: {err}");
    assert!(err.contains(&other), "error includes returned hash: {err}");
}

#[test]
fn fetch_load_rejects_a_malformed_hash_before_touching_the_registry() {
    let kernel = node(true);
    let res = control(
        &kernel,
        1,
        &Verb::FetchLoad {
            artifact_hash: "../escape".into(),
            node: None,
            registry_id: None,
            realm: None,
            chunk_size: None,
        },
    );
    assert!(!res.ok, "malformed hash is rejected: {:?}", res.json);
    let err = res.json.get("error").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(err.contains("artifact_hash"), "error names the field: {err}");
}
