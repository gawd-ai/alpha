//! Registry / Bestiary control verbs **over the bus**. Boots a real node and drives the catalogue
//! verbs purely by sending `Verb` envelopes to `Role::CONTROL`, asserting each round-trips a
//! `RegistryOp`/`BestiaryOp` to the bound registry creature and returns the expected JSON.
//!
//! Two registry creatures are exercised on the same `Role::REGISTRY` socket: the default in-memory
//! `registry-mem` (publish/fetch/list + the allow-AI gate), and a durable `bestiary-daemon` (the
//! `bestiary_prove` verb returns a verifiable `EntryProof`) — proving the verbs serve whichever
//! registry creature is bound, unchanged.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Dispatch, RealmId, Role, StubSigner, StubVerifier};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use bestiary::{DeterministicCurator, EntryProof, FsBestiaryStore};
use bestiary_daemon::{BestiaryConfig, BestiaryDaemon};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

use omni::{
    boot_control, boot_organs_with_monitor, recv_corr, AiControl, Verb, VerbResult, CONTROL_SCHEMA,
    MAX_CONTROL_ARTIFACT_BYTES, MAX_CONTROL_MANIFEST_BYTES,
};

// ---- self-cleaning temp dir (no external tempdir dep) ----

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("omni-regverbs-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    /// Write a manifest JSON + an artifact file; return `(manifest_path, artifact_path)`.
    fn creature_files(&self, name: &str, bytes: &[u8]) -> (String, String) {
        let m = Manifest::new(name, "0.2.0", Backend::Daemon, "gawd_creature_v1");
        let m_path = self.manifest_file(name, &m);
        let a_path = self.0.join(format!("{name}.artifact.bin"));
        std::fs::write(&a_path, bytes).unwrap();
        (m_path, a_path.to_string_lossy().into_owned())
    }
    fn manifest_file(&self, name: &str, manifest: &Manifest) -> String {
        let m_path = self.0.join(format!("{name}.manifest.json"));
        std::fs::write(&m_path, serde_json::to_vec(manifest).unwrap()).unwrap();
        m_path.to_string_lossy().into_owned()
    }
    fn sparse_file(&self, name: &str, len: u64) -> String {
        let path = self.0.join(name);
        std::fs::File::create(&path).unwrap().set_len(len).unwrap();
        path.to_string_lossy().into_owned()
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Boot a live node with control bound on `Role::CONTROL` over the default in-memory `registry-mem`.
fn node(allow_ai: bool) -> (Arc<Kernel>, Arc<AiControl>) {
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
    (kernel, ai)
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
    let reply = recv_corr(&rx, corr, Duration::from_secs(20)).expect("a VerbResult reply");
    serde_json::from_slice::<VerbResult>(&reply.payload).expect("payload is a VerbResult")
}

#[test]
fn publish_then_fetch_and_list_round_trip_through_the_registry() {
    let (kernel, _ai) = node(true);
    let files = TempDir::new("publish");
    let bytes = b"registry-verb-artifact-bytes".to_vec();
    let (m_path, a_path) = files.creature_files("catalogued", &bytes);

    // (1) Publish into the local Realm — node-local paths, like `load`.
    let res = control(
        &kernel,
        1,
        &Verb::RegistryPublish {
            manifest_path: m_path.clone(),
            artifact_path: a_path.clone(),
            realm: None,
        },
    );
    assert!(res.ok, "publish ok: {:?}", res.json);
    let hash =
        res.json.get("artifact_hash").and_then(|v| v.as_str()).expect("artifact_hash").to_string();

    // (2) Fetch it back — metadata + artifact length, never the raw bytes inline.
    let res =
        control(&kernel, 2, &Verb::RegistryFetch { artifact_hash: hash.clone(), realm: None });
    assert!(res.ok, "fetch ok: {:?}", res.json);
    assert_eq!(res.json.get("name").and_then(|v| v.as_str()), Some("catalogued"));
    assert_eq!(
        res.json.get("artifact_len").and_then(|v| v.as_u64()),
        Some(bytes.len() as u64),
        "fetch returns the artifact length, not the bytes"
    );
    assert!(res.json.get("artifact").is_none(), "raw artifact bytes are NOT inlined in the reply");

    // (3) List — the published entry is visible in the catalogue snapshot.
    let res = control(&kernel, 3, &Verb::RegistryList { realm: None });
    assert!(res.ok, "list ok: {:?}", res.json);
    let hashes: Vec<&str> = res.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("artifact_hash").and_then(|v| v.as_str()))
        .collect();
    assert!(hashes.contains(&hash.as_str()), "list includes the published hash: {hashes:?}");

    // (4) Fetch an unknown (validly-shaped, 64-hex, but absent) hash → a clean not-found error, node
    // survives (a later read still works). A malformed hash is a different, Error-shaped path.
    let res =
        control(&kernel, 4, &Verb::RegistryFetch { artifact_hash: "f".repeat(64), realm: None });
    assert!(!res.ok, "unknown fetch is an error");
    assert!(!res.is_gate_block(), "not-found is not a gate refusal");
    assert_eq!(res.json.get("not_found").and_then(|v| v.as_bool()), Some(true));
    let res = control(&kernel, 5, &Verb::Status);
    assert!(res.ok, "node still answers after a not-found");

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn realm_scoped_list_excludes_other_realms() {
    let (kernel, _ai) = node(true);
    let files = TempDir::new("realms");
    let (m_crew, a_crew) = files.creature_files("crew-creature", b"crew-bytes");
    let (m_guest, a_guest) = files.creature_files("guest-creature", b"guest-bytes");

    let crew_hash = {
        let res = control(
            &kernel,
            1,
            &Verb::RegistryPublish {
                manifest_path: m_crew,
                artifact_path: a_crew,
                realm: Some(RealmId::new("crew")),
            },
        );
        assert!(res.ok, "publish into crew ok: {:?}", res.json);
        assert_eq!(res.json.get("realm").and_then(|v| v.as_str()), Some("crew"));
        res.json["artifact_hash"].as_str().unwrap().to_string()
    };
    let guest_hash = {
        let res = control(
            &kernel,
            2,
            &Verb::RegistryPublish {
                manifest_path: m_guest,
                artifact_path: a_guest,
                realm: Some(RealmId::new("guests")),
            },
        );
        assert!(res.ok, "publish into guests ok: {:?}", res.json);
        res.json["artifact_hash"].as_str().unwrap().to_string()
    };

    // A crew-scoped list sees the crew entry and not the guest entry.
    let res = control(&kernel, 3, &Verb::RegistryList { realm: Some(RealmId::new("crew")) });
    assert!(res.ok);
    let hashes: Vec<&str> = res.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("artifact_hash").and_then(|v| v.as_str()))
        .collect();
    assert!(hashes.contains(&crew_hash.as_str()), "crew list has the crew entry: {hashes:?}");
    assert!(
        !hashes.contains(&guest_hash.as_str()),
        "crew list excludes the guest entry: {hashes:?}"
    );

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn registry_list_is_sorted_for_stable_operator_output() {
    let (kernel, _ai) = node(true);
    let files = TempDir::new("list-sort");
    let (m_z, a_z) = files.creature_files("sort-z", b"sort-z-bytes");
    let (m_b, a_b) = files.creature_files("sort-b", b"sort-b-bytes");
    let (m_a, a_a) = files.creature_files("sort-a", b"sort-a-bytes");

    for (corr, manifest_path, artifact_path, realm) in
        [(1, m_z, a_z, "guests"), (2, m_b, a_b, "crew"), (3, m_a, a_a, "crew")]
    {
        let res = control(
            &kernel,
            corr,
            &Verb::RegistryPublish {
                manifest_path,
                artifact_path,
                realm: Some(RealmId::new(realm)),
            },
        );
        assert!(res.ok, "publish {realm} ok: {:?}", res.json);
    }

    let res = control(&kernel, 4, &Verb::RegistryList { realm: None });
    assert!(res.ok, "list ok: {:?}", res.json);
    let rows: Vec<(String, String)> = res.json["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            let name = e.get("name").and_then(|v| v.as_str())?;
            if !name.starts_with("sort-") {
                return None;
            }
            Some((e.get("realm").and_then(|v| v.as_str()).unwrap().to_string(), name.to_string()))
        })
        .collect();

    assert_eq!(
        rows,
        vec![
            ("crew".to_string(), "sort-a".to_string()),
            ("crew".to_string(), "sort-b".to_string()),
            ("guests".to_string(), "sort-z".to_string()),
        ],
        "registry list should be deterministic by realm, name, version, hash"
    );

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn publish_is_gated_but_reads_are_not() {
    // Gate OFF: a mutating verb (publish) over the bus is refused with `ai-not-allowed`, while the
    // reads (list/fetch) still answer — exactly the `load`-vs-`status` posture.
    let (kernel, _ai) = node(false);
    let files = TempDir::new("gate");
    let (m_path, a_path) = files.creature_files("gated", b"gated-bytes");

    let blocked = control(
        &kernel,
        1,
        &Verb::RegistryPublish { manifest_path: m_path, artifact_path: a_path, realm: None },
    );
    assert!(!blocked.ok, "publish is refused while allow-ai is off");
    assert!(blocked.is_gate_block(), "publish refusal is the allow-ai gate: {:?}", blocked.json);

    let list = control(&kernel, 2, &Verb::RegistryList { realm: None });
    assert!(list.ok, "list is never gated");
    assert!(!list.is_gate_block());

    let fetch =
        control(&kernel, 3, &Verb::RegistryFetch { artifact_hash: "nope".into(), realm: None });
    assert!(!fetch.is_gate_block(), "a read's failure is never a gate refusal");

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn node_local_path_reads_are_bounded_before_load_or_publish() {
    let (kernel, _ai) = node(true);
    let files = TempDir::new("path-bounds");

    let huge_manifest =
        files.sparse_file("too-large.manifest.json", MAX_CONTROL_MANIFEST_BYTES + 1);
    let res = control(
        &kernel,
        1,
        &Verb::Load { manifest_path: huge_manifest, artifact_path: "/no/such/artifact".into() },
    );
    assert!(!res.ok, "oversized manifest is refused");
    let err = res.json["error"].as_str().unwrap_or_default();
    assert!(err.contains("exceeds") && err.contains("manifest"), "bounded error: {err}");

    let critter_manifest =
        Manifest::new("huge-critter", "0.1.0", Backend::Critter, "gawd_critter_v1");
    let m_path = files.manifest_file("huge-critter", &critter_manifest);
    let huge_artifact = files.sparse_file("too-large.rhai", MAX_CONTROL_ARTIFACT_BYTES + 1);
    let res =
        control(&kernel, 2, &Verb::Load { manifest_path: m_path, artifact_path: huge_artifact });
    assert!(!res.ok, "oversized non-native artifact is refused before engine read");
    let err = res.json["error"].as_str().unwrap_or_default();
    assert!(err.contains("exceeds") && err.contains("artifact"), "bounded error: {err}");

    let (m_path, _) = files.creature_files("published-huge", b"small");
    let huge_artifact =
        files.sparse_file("too-large-registry-artifact.bin", MAX_CONTROL_ARTIFACT_BYTES + 1);
    let res = control(
        &kernel,
        3,
        &Verb::RegistryPublish { manifest_path: m_path, artifact_path: huge_artifact, realm: None },
    );
    assert!(!res.ok, "oversized publish artifact is refused before registry bus payload");
    let err = res.json["error"].as_str().unwrap_or_default();
    assert!(err.contains("exceeds") && err.contains("artifact"), "bounded error: {err}");

    let list = control(&kernel, 4, &Verb::RegistryList { realm: None });
    assert!(list.ok, "node still answers after bounded read refusals");
    assert_eq!(list.json["entries"].as_array().map(Vec::len), Some(0));

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn bestiary_prove_round_trips_a_verifiable_entry_proof() {
    // The verbs serve whichever creature is bound to Role::REGISTRY. Bind a durable `bestiary-daemon`
    // (over a temp root) and assert `bestiary_prove` returns a standalone `EntryProof` that verifies.
    let root = TempDir::new("prove");
    let abode = Ed25519KeyMaterial::from_seed([0x42; 32]).unwrap();

    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    );
    let critter_builder = boot_organs_with_monitor(&kernel, false).expect("organs boot");

    // Bind the durable daemon onto REGISTRY (overriding the default in-memory binding).
    let store = Arc::new(FsBestiaryStore::new(&root.0, abode.clone()).unwrap());
    let curator = Arc::new(DeterministicCurator::default());
    let daemon = BestiaryDaemon::new(store, curator, BestiaryConfig::local());
    let daemon_id = kernel
        .load_instance(
            Manifest::new("bestiary-daemon", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(daemon),
        )
        .expect("daemon admits under the dev policy");
    kernel.bind_role(Role::new(Role::REGISTRY), daemon_id);

    let ai = Arc::new(AiControl::new(true));
    boot_control(&kernel, &ai, Some(critter_builder), None).expect("control boots");

    // Publish into a Realm, then prove the entry.
    let files = TempDir::new("prove-files");
    let (m_path, a_path) = files.creature_files("proven", b"proven-artifact-bytes");
    let res = control(
        &kernel,
        1,
        &Verb::RegistryPublish {
            manifest_path: m_path,
            artifact_path: a_path,
            realm: Some(RealmId::new("crew")),
        },
    );
    assert!(res.ok, "publish to the daemon ok: {:?}", res.json);
    let hash = res.json["artifact_hash"].as_str().unwrap().to_string();

    let res = control(
        &kernel,
        2,
        &Verb::BestiaryProve { artifact_hash: hash.clone(), realm: RealmId::new("crew") },
    );
    assert!(res.ok, "prove ok: {:?}", res.json);
    let proof: EntryProof =
        serde_json::from_value(res.json["proof"].clone()).expect("proof is an EntryProof");
    assert_eq!(proof.artifact_hash, hash);
    assert_eq!(proof.realm, RealmId::new("crew"));
    assert_eq!(proof.attester, abode.public_hex(), "the daemon's abode key attests");
    assert!(proof.verify(&Ed25519Verifier), "the standalone attestation verifies");

    // Proving an unknown hash is a clean not-found, not a panic.
    let res = control(
        &kernel,
        3,
        &Verb::BestiaryProve { artifact_hash: "unknown".into(), realm: RealmId::new("crew") },
    );
    assert!(!res.ok, "prove of an unknown entry is an error");
    assert_eq!(res.json.get("not_found").and_then(|v| v.as_bool()), Some(true));

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn bestiary_prove_against_the_in_memory_stub_is_a_clean_error() {
    // The default node binds `registry-mem`, which does not speak `bestiary.op`. A `bestiary_prove`
    // there must return a structured error (the stub decodes it as a malformed registry op), never a
    // panic or a hang — the node stays live.
    let (kernel, _ai) = node(true);
    let res = control(
        &kernel,
        1,
        &Verb::BestiaryProve { artifact_hash: "h".into(), realm: RealmId::new("crew") },
    );
    assert!(!res.ok, "the stub cannot prove: {:?}", res.json);
    assert!(!res.is_gate_block());
    let res = control(&kernel, 2, &Verb::Status);
    assert!(res.ok, "node survives a prove against the stub");

    kernel.shutdown_all(aether::Deadline::default());
}
