//! One integration test that stitches the federation additions on top of the base
//! loop into a single composed end-to-end proof. Mirrors
//! `v01_end_to_end.rs` in tone and shape; mirrors the distributor + federation cross-node tests in scaffolding.
//!
//! The loop:
//!
//! **Phase 1 — the base loop with a Realm grain on the registry.**
//!
//! 1. **Author + build on A.** `agent-templated` produces source + manifest stub from a
//!    natural-language request; `build-cargo` compiles, signs, and returns an admissible
//!    `(manifest, artifact)`. Unchanged from `v01_end_to_end`.
//! 2. **Realm-scoped publish on A.** A's `registry-mem` indexes the artifact under realm `"v02-wrap"`
//!    via `Publish { realm: Some(..) }` — proves the Realm grain is honored by the publish path.
//! 3. **Realm-scoped fetch from B across the wire.** B's probe issues `Fetch { realm: Some(..) }` for
//!    `(artifact_hash, "v02-wrap")` addressed at `Node(A, registry_a)`; A's transport delivers
//!    locally; A's registry replies via `reply_to` (rewritten by the transport so the reply ships
//!    back); B's transport delivers it. **Real ed25519 handshake; real sha256 integrity check.**
//! 4. **Realm-grain assertion.** A plain `Fetch` (no realm filter, implicitly `"local"`)
//!    for the same hash returns `NotFound` — proves the Realm grain is real and the default
//!    behavior is preserved (non-federated callers don't see Realm-tagged entries).
//! 5. **Admit + safe load on B.** B's `SignedPolicy` enforces signature + artifact hash + author
//!    allowlist; B's kernel loads the foreign bytes via the spill+`dlopen` safe path.
//! 6. **Invoke on B.** Round-trip a payload through the shipped creature; assert the reverse.
//! 7. **Unload + reload on B.** Unload via the safe-lifecycle path; assert `is_loaded` flips;
//!    load the same `(manifest, artifact)` again; invoke again — the reload primitive applied
//!    to the freshly shipped artifact.
//! 8. **Capability calls-gate on B.** Restricted probe with `calls = ["creature:<reloaded>"]` —
//!    allowed path works, denied path returns `RouteError::Denied`.
//!
//! **Phase 2 — SEER + cross-node placement, targeting the freshly shipped creature.**
//!
//! 9. **Advertiser on B** offers `(reloaded_id, cpu:4)` — the shipped creature is now a
//!    placement target. **Advertiser on A** offers `(local_echo_id, cpu:2)` — proves the local
//!    advertiser is consulted alongside the peer one (S4 mitigation: even N=1 local goes through
//!    SEER, and we exercise N>1 here).
//! 10. **Distributor on A** binds to `Role::DISTRIBUTOR` with both advertisers in its peer
//!     table. Probe-A issues `Intent { outcome: "reverse-string", requirements: ["cpu >= 4"] }` —
//!     only B's cpu:4 offer matches.
//! 11. **SEER consult on `placement` topic.** A's distributor emits SEER Queries to advertiser-A
//!     (local) AND `Address::Node(NODE_B, advertiser_B)` (cross-node). transport-tcp ships the
//!     latter. Both advertisers Answer; A's distributor reconciles.
//! 12. **Placement routes to B.** A's distributor sends the Intent payload to
//!     `Address::Creature(reloaded_id)` on B; transport ships; B's kernel delivers to the shipped
//!     creature; the creature reverses; reply ships back via the preserved `reply_to`.
//! 13. **Reply at the original corr.** Probe-A receives the reversed payload at the Intent's corr
//!     — proves the full SEER-consult → placement → cross-node-invoke loop closed.
//!
//! 14. **Clean shutdown.** Both kernels' `shutdown_all` drives transport-tcp's listener/dialer/
//!     reader/writer joins so the test process exits cleanly (lifecycle on boot creatures).
//!
//! ## What this test is, and isn't
//!
//! This is a **wiring test** — it proves the base loop + SEER + distributor + Realm grain
//! all *compose* into one continuous flow against a real authored artifact. It is **not** a stress
//! test (dedicated suites already hammer the individual seams: `m1_reload_loop` for unload
//! cycling, `m2_integrity` for integrity drift, `seer_topic_isolation` for SEER walls,
//! `distributor_local` for distributor topology variants, `realm_local_route` for the realm-gateway
//! hop). This is *the loop, in one place*, with the
//! shipped creature in Phase 1 becoming the placement target in Phase 2.
//!
//! ## Ports & cache layout
//!
//! Static ports `19_950 / 19_951` so the test is trivially debuggable; explicitly distinct from
//! `m2_two_node`'s `19_900/01`, `v01_end_to_end`'s `19_910/11`, `distributor_cross_node`'s
//! `19_920/21`, `realm_local_route`'s `19_930/31`, and the `19_940/41` slot reserved for a future
//! Omega test. Cargo-backed authoring tests share `<root>/target/gawd-build-cache`, avoiding a
//! duplicate SDK artifact graph for every test binary. build-cargo's retained cache lock serializes
//! every instance and process using that directory; Cargo's own target/package locks remain
//! integrity guards, not the resource-concurrency boundary.
//!
//! Cold first build takes 30–60s for the transitive deps; warm reuses sit under 15s.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Bus, BusHandle, CreatureId, Deadline, Dispatch, Ed25519Verifier, Envelope,
    InboxReceiver, Intent, NodeId, Role, RouteError, StubSigner, Topic,
};
use agent_templated::{AgentTemplated, AuthoringReply, AuthoringRequest, AuthoringResponse};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use build_cargo::{BuildCargo, BuildConfig, BuildOp, BuildReply, Sandbox};
use distributor_requirements::{Distributor, PickModel};
use embodiment_advertiser::{EmbodimentAdvertiser, OfferEntry};
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply};
use sanctum::Kernel;
use seer::topics::placement;
use sha2::{Digest, Sha256};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest, RealmId};
use transport_tcp::{PeerConfig, TransportConfig, TransportTcp};

// ----- ports + node identities (distinct from every prior cross-node test) ----------------------

const PORT_A: u16 = 19_950;
const PORT_B: u16 = 19_951;
const NODE_A: &str = "v02-node-A";
const NODE_B: &str = "v02-node-B";

/// The Realm the test publishes under. There is no `test()` constructor on
/// `Realm` (intentional — Realm names are operator-chosen, not
/// substrate-blessed), so we use a stable explicit name that names the test itself.
const REALM_V02_WRAP: &str = "v02-wrap";

// ----- scaling helpers (valgrind-friendly, shared with the other cross-node suites) --------------

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}

fn scaled(d: Duration) -> Duration {
    d * (slow_factor() as u32)
}

// ----- workspace paths --------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // sanctum's manifest dir is <root>/cosmos/sanctum; the true root is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Canonical authoring cache shared across tests/demos. Process-unique authored crate names and the
/// serial repository defaults make reuse safe while avoiding another cold SDK dependency graph.
fn shared_build_cache() -> PathBuf {
    workspace_root().join("target").join("gawd-build-cache")
}

// ----- signed-manifest helpers ------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Boot-manifest helper — boot creatures (transport, registry, agent, build, advertiser,
/// distributor) have no shipped artifact; admission's artifact-hash gate is skipped on the
/// `load_instance` path. The policy still requires a valid signature, so we sign with an
/// allowlisted key.
fn signed_boot_manifest(name: &str, signer_key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(signer_key.public_hex().to_string());
    let sig = signer_key.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

// ----- recv helpers (corr-filtered to skip proprio / SEER stragglers) ---------------------------

/// Receive the first envelope matching `corr`. Stray envelopes (proprio fitness/lifecycle events,
/// peer_event broadcasts, late SEER traffic, etc.) are silently dropped — we want the reply for
/// the specific exchange we just initiated.
fn recv_with_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            _ => continue,
        }
    }
    None
}

/// Receive the first envelope matching `corr` *and* a predicate. Used in Phase 2 to wait for the
/// echo reply tagged 'B' (skipping the corr-matched but body-empty envelopes the distributor's
/// own routing produces if the test runs faster than the SEER consult resolves).
fn recv_with_corr_matching<F: Fn(&Envelope) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && pred(&env) => return Some(env),
            _ => continue,
        }
    }
    None
}

/// Retry the fetch dispatch until a reply arrives. transport-tcp drops envelopes addressed at a
/// not-yet-handshaked peer silently (a fabric-mechanism concern, not the test's); each retry
/// pushes one fresh dispatch.
fn retry_until_reply(
    bus: &BusHandle,
    rx: &InboxReceiver,
    mut make_dispatch: impl FnMut() -> Dispatch,
    per_attempt: Duration,
    attempts: usize,
) -> Result<Envelope, String> {
    for _ in 0..attempts {
        let d = make_dispatch();
        let want = d.corr; // accept only the reply correlated to THIS request
        let _ = bus.send(d);
        // Corr-filter within the attempt window: a slow cross-node straggler from a *prior* step
        // (e.g. a realm-scoped `Fetched` that arrives after the inter-step drain) must not be misread as
        // this request's reply. Without this, the next read races that straggler — green in isolation
        // (the reply lands inside the drain window), flaky under full-suite load. Mirrors the
        // corr-filtering `recv_corr`/`request_reply` helpers in `omni` and walkthrough.
        let deadline = std::time::Instant::now() + per_attempt;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break; // attempt window elapsed → re-send
            }
            match rx.recv_timeout(remaining) {
                Ok(env) if env.header.corr == want => return Ok(env),
                Ok(_) => continue, // stale/uncorrelated straggler — skip, keep waiting
                Err(_) => break,   // timed out this attempt → re-send
            }
        }
    }
    Err("retry budget exhausted".into())
}

// (No `wait_for_peer_event` helper here. Phase 1 demonstrably crosses the wire — the
// realm-scoped fetch round-trip can't have succeeded otherwise — so by the time Phase 2 builds the
// distributor + advertisers, the handshake's been up for seconds. We use a brief settle delay
// in step 12 instead. If a future change makes Phase 1 not exercise the wire, restore the helper
// from `distributor_cross_node.rs`.)

// ----- A tiny local-echo creature for Phase 2's A-side advertiser to offer ----------------------

/// Local echo on A — reverses the payload and prepends `'A'`. Same shape as the `TaggedEcho` used
/// in `distributor_cross_node.rs`; kept inline per the test-suite convention (no cross-test
/// helper crate).
struct TaggedEcho {
    tag: u8,
}
impl aether::Creature for TaggedEcho {
    fn bind(&mut self, _ctx: aether::CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> aether::Outcome {
        let mut reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        let mut out = vec![self.tag];
        out.append(&mut reversed);
        aether::Outcome::reply(&env, out)
    }
}

// ----- kernel construction (mirrors v01_end_to_end + distributor_cross_node) --------------------

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("v02-wrap")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

// ----- node A: full author + ship kit + (later) distributor + local-advertiser -------------------

struct NodeA {
    kernel: Arc<Kernel>,
    node_key: Ed25519KeyMaterial,
    author_label: String,
    registry_id: CreatureId,
    probe_id: CreatureId,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_a(abode: Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeA {
    let author_label = abode.public_hex().to_string();
    let allowlist = vec![author_label.clone(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

    // --- agent-templated on AUTHORING ---
    let agent_id = k
        .load_instance(
            signed_boot_manifest("agent-templated", &abode),
            Box::new(AgentTemplated::new()),
        )
        .expect("agent-templated admits on A");
    k.bind_role(Role::new(Role::AUTHORING), agent_id);

    // --- build-cargo on BUILD ---
    let mut build_cfg = BuildConfig::with_workspace_root(
        workspace_root().join("cosmos"),
        abode.clone(),
        author_label.clone(),
    );
    build_cfg.target_dir = shared_build_cache();
    build_cfg.sandbox = Sandbox::None;
    build_cfg.cargo_timeout = scaled(Duration::from_secs(300));
    let build_id = k
        .load_instance(
            signed_boot_manifest("build-cargo", &abode),
            Box::new(BuildCargo::new(build_cfg)),
        )
        .expect("build-cargo admits on A");
    k.bind_role(Role::new(Role::BUILD), build_id);

    // --- registry-mem on REGISTRY ---
    let registry_id = k
        .load_instance(
            signed_boot_manifest("registry-mem", &node_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry-mem admits on A");
    k.bind_role(Role::new(Role::REGISTRY), registry_id);

    // --- transport-tcp on TRANSPORT (passive — B dials in) ---
    let peer_b_key = Ed25519KeyMaterial::from_seed([0xB2u8; 32]).unwrap();
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(NODE_A.into()),
        listen_addr: format!("127.0.0.1:{PORT_A}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_B.into()),
            pubkey_hex: peer_b_key.public_hex().to_string(),
            dial_addr: None,
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("transport-tcp admits on A");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

    // --- Probe (Phase 1 drives it; Phase 2 subscribes it to PROPRIOCEPTION via the kernel
    //          handle returned in NodeA — we need PROPRIOCEPTION to gate on peer_connected before
    //          the cross-node SEER consult fires).
    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    k.router().subscribe(Topic::new(Topic::PROPRIOCEPTION), probe_id);

    NodeA { kernel: k, node_key, author_label, registry_id, probe_id, probe_bus, probe_rx }
}

// ----- node B: runtime kit (registry + transport); shipped creature loads mid-test --------------

struct NodeB {
    kernel: Arc<Kernel>,
    node_key: Ed25519KeyMaterial,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_b(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeB {
    let allowlist = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

    // --- registry-mem (B uses its registry as a local cache for fetched bytes; mostly a
    // standard ship-kit citizen rather than driven by the test). ---
    let _registry_id = k
        .load_instance(
            signed_boot_manifest("registry-mem", &node_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry-mem admits on B");

    // --- transport-tcp on TRANSPORT (active — dials A) ---
    let peer_a_key = Ed25519KeyMaterial::from_seed([0xA2u8; 32]).unwrap();
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(NODE_B.into()),
        listen_addr: format!("127.0.0.1:{PORT_B}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_A.into()),
            pubkey_hex: peer_a_key.public_hex().to_string(),
            dial_addr: Some(format!("127.0.0.1:{PORT_A}")),
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("transport-tcp admits on B");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

    let (_probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    NodeB { kernel: k, node_key, probe_bus, probe_rx }
}

// =================================================================================================
// The composed loop: Phase 1 (base loop + Realm grain) → Phase 2 (SEER + cross-node placement
// targeting the shipped creature).
// =================================================================================================

#[test]
fn v02_end_to_end_loop_proves_v01_plus_m6_m7_m8_compose() {
    // ---- keys (seeds match peer-pubkey reconstruction in boot_node_a/b) ----
    // Distinct seed bytes from the base loop's [0x01]/[0xA1]/[0xB1] so this test's signatures + node IDs
    // don't accidentally collide with parallel runs of the base-loop suite.
    let abode = Ed25519KeyMaterial::from_seed([0x02u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xA2u8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xB2u8; 32]).unwrap();

    // ---- boot both nodes ----
    let a = boot_node_a(abode.clone(), node_a_key);
    let b = boot_node_b(&abode, node_b_key);

    // =============================================================================================
    // Phase 1 — the base loop with a Realm grain on the registry
    // =============================================================================================

    // -- step 1: author on A --
    let req = AuthoringRequest {
        request: "write a daemon that reverses a string".into(),
        ..Default::default()
    };
    let payload = serde_json::to_vec(&req).unwrap();
    a.probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(a.probe_bus.id()))
                .with_corr(1),
        )
        .expect("send AuthoringRequest");
    let auth_env = recv_with_corr(&a.probe_rx, 1, scaled(Duration::from_secs(5)))
        .expect("AuthoringReply arrives");
    let auth_reply: AuthoringReply = serde_json::from_slice(&auth_env.payload).unwrap();
    let resp: AuthoringResponse = match auth_reply {
        AuthoringReply::Authored(r) => r,
        AuthoringReply::Failed(e) => panic!("authoring failed: {e:?}"),
    };
    assert_eq!(resp.crate_name, "reverse-daemon");

    // -- step 2: build on A --
    let build_op = BuildOp::Build {
        crate_name: resp.crate_name.clone(),
        crate_version: resp.crate_version.clone(),
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
        deps: resp.deps.clone(),
    };
    let build_payload = serde_json::to_vec(&build_op).unwrap();
    a.probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::BUILD)), build_payload)
                .with_reply_to(Address::Creature(a.probe_bus.id()))
                .with_corr(2),
        )
        .expect("send BuildOp");
    let build_env = recv_with_corr(&a.probe_rx, 2, scaled(Duration::from_secs(360)))
        .expect("BuildReply arrives");
    let build_reply: BuildReply = serde_json::from_slice(&build_env.payload).unwrap();
    let (built_manifest, built_artifact) = match build_reply {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => panic!(
            "build expected Built, got Failed({kind:?}): {message}\n--- cargo stderr ---\n{stderr}"
        ),
    };
    assert_eq!(built_manifest.provenance.author.as_deref(), Some(a.author_label.as_str()));
    assert!(built_manifest.provenance.signature.is_some());
    assert!(built_manifest.provenance.build_hash.is_some());
    let expected_artifact_hash = sha256_hex(&built_artifact);
    assert_eq!(
        built_manifest.provenance.build_hash.as_deref(),
        Some(expected_artifact_hash.as_str()),
        "build_hash must match the sha256 of the artifact bytes",
    );

    // -- step 3: realm-scoped publish on A --
    // The Realm-graned op variant: same publish path, plus a Realm grain. The test publishes under
    // realm "v02-wrap"; step 4 below proves a plain Fetch (implicit "local") does NOT see it.
    let realm_v02 = RealmId::new(REALM_V02_WRAP);
    let publish_op = RegistryOp::Publish {
        manifest: built_manifest.clone(),
        artifact: built_artifact.clone(),
        realm: Some(realm_v02.clone()),
    };
    let publish_payload = serde_json::to_vec(&publish_op).unwrap();
    a.probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::REGISTRY)), publish_payload)
                .with_reply_to(Address::Creature(a.probe_bus.id()))
                .with_corr(3),
        )
        .expect("publish to A's registry (in Realm)");
    let pub_env =
        recv_with_corr(&a.probe_rx, 3, scaled(Duration::from_secs(5))).expect("publish reply");
    let pub_reply: RegistryReply = serde_json::from_slice(&pub_env.payload).unwrap();
    let artifact_hash = match pub_reply {
        RegistryReply::Published { artifact_hash, realm } => {
            assert_eq!(realm, realm_v02, "the reply echoes the Realm the publish landed in");
            artifact_hash
        }
        other => panic!("expected Published, got {other:?}"),
    };
    assert_eq!(artifact_hash, expected_artifact_hash);

    // -- step 4: realm-scoped fetch from B across the wire (proves the Realm grain works cross-node) --
    let fetch_in_realm =
        RegistryOp::Fetch { artifact_hash: artifact_hash.clone(), realm: Some(realm_v02.clone()) };
    let fetch_payload = serde_json::to_vec(&fetch_in_realm).unwrap();
    let fetch_env = retry_until_reply(
        &b.probe_bus,
        &b.probe_rx,
        || {
            Dispatch::to(Address::Node(NodeId(NODE_A.into()), a.registry_id), fetch_payload.clone())
                .with_reply_to(Address::Creature(b.probe_bus.id()))
                .with_corr(4)
        },
        scaled(Duration::from_millis(500)),
        20,
    )
    .expect("realm-scoped fetch reply arrives from A across the wire");
    assert_eq!(fetch_env.header.corr, Some(4), "corr preserved across the wire");
    let fetch_reply: RegistryReply = serde_json::from_slice(&fetch_env.payload).unwrap();
    let (m_fetched, art_fetched) = match fetch_reply {
        RegistryReply::Fetched { manifest, artifact, realm } => {
            assert_eq!(realm, realm_v02, "the reply echoes the Realm on the realm-scoped fetch");
            (manifest, artifact)
        }
        other => panic!("expected Fetched, got {other:?}"),
    };
    assert_eq!(m_fetched, built_manifest, "fetched manifest matches what A published");
    assert_eq!(art_fetched, built_artifact, "fetched artifact bytes match what A published");

    // Drain Phase-1 stragglers before the next correlated round-trip.
    std::thread::sleep(scaled(Duration::from_millis(100)));
    while b.probe_rx.recv_timeout(scaled(Duration::from_millis(50))).is_ok() {}

    // -- step 4b: grain assertion — a plain Fetch finds NOTHING in "local" --
    // Proves the Realm grain is real: a caller using the plain Fetch wire shape (implicit
    // RealmId::local()) does not see the entry published under "v02-wrap". The default behavior
    // for a plain Fetch is preserved (it only looks in "local"); the Realm-tagged entry lives in a
    // different catalog and is unreachable without the realm filter.
    let fetch_v01_shape = RegistryOp::Fetch { artifact_hash: artifact_hash.clone(), realm: None };
    let fetch_v01_payload = serde_json::to_vec(&fetch_v01_shape).unwrap();
    let fetch_v01_env = retry_until_reply(
        &b.probe_bus,
        &b.probe_rx,
        || {
            Dispatch::to(
                Address::Node(NodeId(NODE_A.into()), a.registry_id),
                fetch_v01_payload.clone(),
            )
            .with_reply_to(Address::Creature(b.probe_bus.id()))
            .with_corr(41)
        },
        scaled(Duration::from_millis(500)),
        20,
    )
    .expect("v0.1-shape Fetch reply arrives from A");
    let fetch_v01_reply: RegistryReply = serde_json::from_slice(&fetch_v01_env.payload).unwrap();
    assert!(
        matches!(fetch_v01_reply, RegistryReply::NotFound),
        "v0.1-shape Fetch must NOT see an entry published only in a non-local Realm; got {fetch_v01_reply:?}",
    );

    // Drain again.
    std::thread::sleep(scaled(Duration::from_millis(100)));
    while b.probe_rx.recv_timeout(scaled(Duration::from_millis(50))).is_ok() {}

    // -- step 5: admit + safe load on B --
    let loaded_id = b
        .kernel
        .load(m_fetched.clone(), Artifact::Bytes(art_fetched.clone()))
        .expect("ship→admit→load on B");

    // -- step 6: invoke on B --
    b.probe_bus
        .emit(
            Dispatch::to(Address::Creature(loaded_id), b"hello world".to_vec())
                .with_reply_to(Address::Creature(b.probe_bus.id()))
                .with_corr(5),
        )
        .expect("send to shipped creature");
    let echo = recv_with_corr(&b.probe_rx, 5, scaled(Duration::from_secs(3)))
        .expect("shipped creature replies");
    assert_eq!(
        echo.payload, b"dlrow olleh",
        "reverse-daemon authored on A (via M8 Realm-graned registry), shipped to B, ran on B"
    );

    // -- step 7: unload + reload (the reload primitive on the shipped artifact) --
    b.kernel.unload(loaded_id, Deadline::from_millis(500)).expect("safe unload on B");
    assert!(!b.kernel.is_loaded(loaded_id), "is_loaded must flip to false post-unload",);
    let post_unload_err = b
        .probe_bus
        .send(Dispatch::to(Address::Creature(loaded_id), b"ghost".to_vec()))
        .expect_err("post-unload send must fail");
    assert!(
        matches!(post_unload_err, RouteError::NoSuchModule(_)),
        "post-unload route must be NoSuchModule, got {post_unload_err:?}"
    );

    let reloaded_id = b
        .kernel
        .load(m_fetched.clone(), Artifact::Bytes(art_fetched.clone()))
        .expect("M1 reload of the shipped artifact succeeds");
    b.probe_bus
        .emit(
            Dispatch::to(Address::Creature(reloaded_id), b"abc".to_vec())
                .with_reply_to(Address::Creature(b.probe_bus.id()))
                .with_corr(6),
        )
        .expect("send to reloaded creature");
    let reloaded_echo = recv_with_corr(&b.probe_rx, 6, scaled(Duration::from_secs(3)))
        .expect("reloaded creature replies");
    assert_eq!(reloaded_echo.payload, b"cba", "reloaded creature reverses correctly");

    // -- step 8: capability calls-gate on a restricted probe --
    let open_probe_id = b.probe_bus.id();
    let restricted_caps = Capabilities {
        calls: vec![format!("creature:{}", reloaded_id.0)],
        ..Capabilities::default()
    };
    let (restricted_probe_id, restricted_bus, restricted_rx) =
        b.kernel.open_endpoint(restricted_caps);
    restricted_bus
        .send(
            Dispatch::to(Address::Creature(reloaded_id), b"42".to_vec())
                .with_reply_to(Address::Creature(restricted_probe_id))
                .with_corr(7),
        )
        .expect("allowed send must pass the call-gate");
    let cap_echo = recv_with_corr(&restricted_rx, 7, scaled(Duration::from_secs(3)))
        .expect("allowed send delivered");
    assert_eq!(cap_echo.payload, b"24", "allowed send reaches the creature, which reverses");
    let denied = restricted_bus
        .send(Dispatch::to(Address::Creature(open_probe_id), b"sneak".to_vec()))
        .expect_err("disallowed destination must be denied");
    assert!(
        matches!(denied, RouteError::Denied { from } if from == restricted_probe_id),
        "expected RouteError::Denied with restricted-probe id, got {denied:?}"
    );

    // =============================================================================================
    // Phase 2 — SEER + cross-node placement, targeting the shipped creature on B
    // =============================================================================================

    // -- step 9: install the advertiser on B (offers the shipped reloaded creature at cpu:4) --
    let adv_b = EmbodimentAdvertiser::new(
        NodeId(NODE_B.into()),
        vec![OfferEntry {
            creature_id: reloaded_id,
            embodiment: placement::Embodiment {
                cpu: 4,
                mem_bytes: 8 * 1024 * 1024 * 1024,
                accelerators: vec![],
                jurisdiction: Some("ca".into()),
                connectivity: Some("wired".into()),
                sensors: vec![],
            },
        }],
    );
    let advertiser_b_id = b
        .kernel
        .load_instance(signed_boot_manifest("embodiment-advertiser", &b.node_key), Box::new(adv_b))
        .expect("B's embodiment-advertiser admits");

    // -- step 10: install the local-echo + advertiser on A (cpu:2 — won't match cpu>=4 but proves
    //             both advertisers are consulted; mirrors distributor_cross_node) --
    let local_echo_a_id = a
        .kernel
        .load_instance(
            signed_boot_manifest("echo-a-local", &a.node_key),
            Box::new(TaggedEcho { tag: b'A' }),
        )
        .expect("local echo on A admits");
    let adv_a = EmbodimentAdvertiser::new(
        NodeId(NODE_A.into()),
        vec![OfferEntry {
            creature_id: local_echo_a_id,
            embodiment: placement::Embodiment {
                cpu: 2,
                mem_bytes: 4 * 1024 * 1024 * 1024,
                accelerators: vec![],
                jurisdiction: Some("us".into()),
                connectivity: Some("wired".into()),
                sensors: vec![],
            },
        }],
    );
    let advertiser_a_id = a
        .kernel
        .load_instance(signed_boot_manifest("embodiment-advertiser", &a.node_key), Box::new(adv_a))
        .expect("A's embodiment-advertiser admits");

    // -- step 11: install the distributor on A, bound to DISTRIBUTOR, with both advertisers --
    let distributor = Distributor::new(
        NodeId(NODE_A.into()),
        vec![advertiser_a_id],
        vec![(NodeId(NODE_B.into()), advertiser_b_id)],
        PickModel::FirstFit,
        20_000, // consult corr seed (distinct from Phase-1's small ints)
    );
    let distributor_id = a
        .kernel
        .load_instance(
            signed_boot_manifest("distributor-requirements", &a.node_key),
            Box::new(distributor),
        )
        .expect("A's distributor-requirements admits");
    a.kernel.bind_role(Role::new(Role::DISTRIBUTOR), distributor_id);

    // -- step 12: gate on peer_connected (transport-tcp drops pre-handshake silently). The
    //             handshake completed long before Phase 2 started — Phase 1's fetch crossed the
    //             wire successfully — but the peer_event has been sitting in the probe's inbox
    //             and was drained on the way through Phase 1. We re-arm by waiting for any new
    //             peer_event OR proceeding if we already know the wire is up. Since the wire is
    //             demonstrably up (Phase 1 worked), we skip the wait and use a brief settle delay
    //             instead. (If a future test stops doing cross-node Fetch in Phase 1, restore the
    //             explicit wait_for_peer_event here.)
    std::thread::sleep(scaled(Duration::from_millis(200)));

    // -- step 13: probe-A issues the Intent — only B's cpu:4 offer matches --
    // The shipped creature is the reverse-daemon authored at step 1; it reverses its payload
    // (no tag — it's the genuine authored artifact, not a `TaggedEcho` test fixture). So we don't
    // tag-filter the reply; the corr alone is sufficient (the distributor's internal consult
    // traffic uses its own corr seed at 20_000+, separate from the Intent's corr=8).
    let intent_corr = 8u64;
    let probe_payload: &[u8] = b"v0.2-cross-node";
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent {
                    outcome: "reverse-string".into(),
                    requirements: vec!["cpu >= 4".into()],
                }),
                probe_payload.to_vec(),
            )
            .with_reply_to(Address::Creature(a.probe_id))
            .with_corr(intent_corr),
        )
        .expect("Intent admits + routes to A's bound distributor");

    // The reply path: distributor(consult+reconcile) → routes Intent payload to
    // Address::Creature(reloaded_id) on B via Address::Node → transport_a(ship) →
    // transport_b(deliver) → reverse-daemon(reverse) → transport_b(ship reply) →
    // transport_a(deliver reply) → probe_a (at the original reply_to + corr).
    let expected_reversed: Vec<u8> = probe_payload.iter().copied().rev().collect();
    let reply = recv_with_corr_matching(
        &a.probe_rx,
        intent_corr,
        |e| e.payload == expected_reversed,
        scaled(Duration::from_secs(10)),
    )
    .expect(
        "shipped reverse-daemon's reply arrives across the wire on the Intent's corr — \
         proves SEER consult + cross-node placement + cross-node invoke + cross-node reply",
    );
    assert_eq!(
        reply.payload, expected_reversed,
        "reverse-daemon authored on A in Phase 1, shipped to B via M8 Realm-graned registry, \
         became the M7 placement target in Phase 2, and reversed the cross-node-invoked payload",
    );

    // -- step 14: clean shutdown — drives transport-tcp's listener/dialer/reader/writer joins. --
    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
