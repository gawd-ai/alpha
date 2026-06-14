//! One integration test that stitches the four core seams
//! (author/build + ship + load + capability) into a single end-to-end loop.
//!
//! The loop:
//!
//! 1. **Author + build (on node A).** `agent-templated` produces source + manifest stub from a
//!    natural-language request; `build-cargo` compiles, signs, and returns an admissible
//!    `(manifest, artifact)`.
//! 2. **Publish + fetch over the wire.** A's `registry-mem` indexes the artifact bytes by
//!    sha256; B's `registry-mem` issues a `Fetch` addressed at `Node(A, registry_a)` across the
//!    authenticated `transport-tcp` channel; A's transport delivers it locally; A's registry
//!    replies via `reply_to` (rewritten by the transport so the reply ships back); B's transport
//!    delivers it to B's probe. Real ed25519 handshake; real sha256 integrity check.
//! 3. **Admit + safe load (on node B).** B's `SignedPolicy` enforces signature + artifact hash
//!    + author allowlist; B's kernel loads the foreign bytes via the spill+`dlopen` safe path.
//! 4. **Invoke on B.** Round-trip a payload through the freshly-loaded shipped creature; assert
//!    correct semantic behavior — proves the artifact authored on A actually *runs* on B.
//! 5. **Unload + reload (on B).** Unload via the safe-lifecycle path; assert `is_loaded` flips;
//!    load the *same* `(manifest, artifact)` again; invoke again; unload again — the safe-reload
//!    primitive applied to a real shipped artifact, not a synthetic loop.
//! 6. **Capability gate (on B).** Open a `calls`-restricted probe endpoint on B that
//!    allowlists *only* the freshly-loaded creature; prove the allowed send works and a send to a
//!    sibling endpoint is denied at the one router choke point (`RouteError::Denied`).
//!
//! ## What this test is, and isn't
//!
//! This is a **wiring test** — it proves the four core surfaces *compose*, the seams are
//! tight, and the loop runs without rewriting any one of them. It is **not** a stress test
//! (the reload loop, fetch-under-integrity-drift, the authoring matrix, and the capability gate
//! each have their own dedicated suites). This is *the loop, in one place*, against a real authored
//! artifact rather than a hand-built one.
//!
//! ## Ports & cache layout
//!
//! Static ports `19_910 / 19_911` so the test is trivially debuggable; explicitly distinct from
//! `m2_two_node`'s `19_900 / 19_901` so the two suites can run in parallel without colliding.
//! The build creature's cargo cache lives at
//! `<root>/target/v01-build-cargo-cache` so it doesn't fight `m3_authoring_loop`'s cargo cache for
//! the lockfile.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Bus, BusHandle, Deadline, Dispatch, Ed25519Verifier, Envelope, InboxReceiver, NodeId,
    Role, RouteError, StubSigner,
};
use agent_templated::{AgentTemplated, AuthoringReply, AuthoringRequest, AuthoringResponse};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use build_cargo::{BuildCargo, BuildConfig, BuildOp, BuildReply, Sandbox};
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply};
use sanctum::Kernel;
use sha2::{Digest, Sha256};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use transport_tcp::{PeerConfig, TransportConfig, TransportTcp};

// ----- ports + node identities (distinct from m2_two_node) --------------------------------------

const PORT_A: u16 = 19_910;
const PORT_B: u16 = 19_911;
const NODE_A: &str = "v01-node-A";
const NODE_B: &str = "v01-node-B";

// ----- scaling helpers (valgrind-friendly, copied from m2/m3 conventions) -----------------------

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

/// Dedicated cargo cache for this test so it doesn't share a lockfile with `m3_authoring_loop`'s
/// cache (`m3-build-cargo-cache`). Cold first build takes 30–60s for the transitive deps; warm
/// reuses sit under 5s.
fn shared_build_cache() -> PathBuf {
    workspace_root().join("target").join("v01-build-cargo-cache")
}

// ----- signed-manifest helpers ------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn signed_boot_manifest(name: &str, signer_key: &Ed25519KeyMaterial) -> Manifest {
    // Boot creatures (transport, registry, agent, build) have no shipped artifact; admission's
    // artifact-hash gate is skipped on the `load_instance` path. The policy still requires a valid
    // signature, so we sign with a key the policy allowlists.
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(signer_key.public_hex().to_string());
    let sig = signer_key.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

// ----- recv helpers -----------------------------------------------------------------------------

/// Receive the first envelope matching `corr`. Stray envelopes (proprio fitness/lifecycle events,
/// late replies from earlier dispatches under retry, etc.) are silently dropped — we want the
/// reply for the specific exchange we just initiated.
fn recv_with_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

/// Retry the fetch dispatch until a reply arrives. The transport drops envelopes addressed at a
/// not-yet-handshaked peer silently (it's a fabric-mechanism concern, not the test's), so each
/// retry pushes one fresh dispatch.
fn retry_until_reply(
    bus: &BusHandle,
    rx: &InboxReceiver,
    mut make_dispatch: impl FnMut() -> Dispatch,
    per_attempt: Duration,
    attempts: usize,
) -> Result<Envelope, String> {
    for _ in 0..attempts {
        let _ = bus.send(make_dispatch());
        if let Ok(env) = rx.recv_timeout(per_attempt) {
            return Ok(env);
        }
    }
    Err("retry budget exhausted".into())
}

// ----- kernel construction ----------------------------------------------------------------------

/// Each node has its own three keys (node key, abode key) and the policy allowlist is the union of
/// (a) the artifact-author key (the Abode key) and (b) the node's own boot key (signs the boot
/// creatures' manifests). One kernel — same engine bag, same signer/verifier shape, different
/// allowlist contents — proves admission stays *mechanism* (one shape) while the *model* (which
/// authors to trust) is injected per-node.
fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("v01-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

// ----- node A: full author + ship kit -----------------------------------------------------------

/// Node A boots with the authoring kit (`agent-templated` + `build-cargo`) AND the ship kit
/// (`registry-mem` + `transport-tcp`). Returns the kernel + the `registry_a` creature id (B needs it
/// to address the cross-node fetch envelope).
struct NodeA {
    kernel: Arc<Kernel>,
    author_label: String,
    registry_id: aether::CreatureId,
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

    // --- transport-tcp on TRANSPORT (passive — B dials us) ---
    // Compute B's pubkey from the same seed B uses in `boot_node_b`. The two boot functions agree
    // on seeds by convention, so each peer can construct the other's pubkey for the allowlist.
    let peer_b_key = Ed25519KeyMaterial::from_seed([0xB1u8; 32]).unwrap();
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

    let (_probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    NodeA { kernel: k, author_label, registry_id, probe_bus, probe_rx }
}

// ----- node B: runtime kit ----------------------------------------------------------------------

/// Node B is the runtime — it doesn't author, it ships+runs. Transport + registry, plus the
/// probe endpoint the test drives. The artifact-author allowlist for B is the SAME Abode key as A
/// uses to sign authored artifacts (otherwise the policy would reject the shipped manifest at
/// admit time, which is correct behavior but not what we're proving here).
struct NodeB {
    kernel: Arc<Kernel>,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_b(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeB {
    let allowlist = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

    // --- registry-mem (B uses its registry only as a *local* cache for fetched bytes; not
    // actually exercised in this test, but it's part of the standard ship kit) ---
    let _registry_id = k
        .load_instance(
            signed_boot_manifest("registry-mem", &node_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry-mem admits on B");

    // --- transport-tcp on TRANSPORT (active — dials A) ---
    let peer_a_key = Ed25519KeyMaterial::from_seed([0xA1u8; 32]).unwrap();
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

    NodeB { kernel: k, probe_bus, probe_rx }
}

// =================================================================================================
// The composed loop: author+build on A → ship A→B → load+run+reload on B → calls-gate.
// =================================================================================================

#[test]
fn v01_end_to_end_loop_proves_m3_m2_m1_m4_compose() {
    // ---- keys (seeds must match boot_node_a/b's hard-coded peer-pubkey reconstruction) ----
    let abode = Ed25519KeyMaterial::from_seed([0x01u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xA1u8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xB1u8; 32]).unwrap();

    // ---- boot both nodes ----
    let a = boot_node_a(abode.clone(), node_a_key);
    let b = boot_node_b(&abode, node_b_key);

    // -- step 1: author on A --
    // "write a daemon that reverses a string" is the template-match request — the template-match path,
    // the simplest end-to-end shape. The agent-templated reference creature matches on a regex
    // and returns a deterministic AuthoringResponse for it.
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
    // The build creature compiles the source, signs the resulting manifest with the Abode key,
    // and returns admissible (manifest, artifact). The cargo wall-clock budget is the dominant
    // cost in this test (cold cache: 30–60s; warm: <5s).
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
        "build_hash must match the sha256 of the artifact bytes — the M2 admission gate hinges on this",
    );

    // -- step 3: publish on A --
    let publish_op = RegistryOp::Publish {
        manifest: built_manifest.clone(),
        artifact: built_artifact.clone(),
        realm: None,
    };
    let publish_payload = serde_json::to_vec(&publish_op).unwrap();
    a.probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::REGISTRY)), publish_payload)
                .with_reply_to(Address::Creature(a.probe_bus.id()))
                .with_corr(3),
        )
        .expect("publish to A's registry");
    let pub_env =
        recv_with_corr(&a.probe_rx, 3, scaled(Duration::from_secs(5))).expect("publish reply");
    let pub_reply: RegistryReply = serde_json::from_slice(&pub_env.payload).unwrap();
    let artifact_hash = match pub_reply {
        RegistryReply::Published { artifact_hash, .. } => artifact_hash,
        other => panic!("expected Published, got {other:?}"),
    };
    assert_eq!(artifact_hash, expected_artifact_hash);

    // -- step 4: fetch from B over the wire --
    // Address::Node(NODE_A, registry_a) is the *capability-shape* address: an envelope addressed
    // off-node by NodeId, delivered to a specific creature there. The transport rewrites reply_to
    // on the way out so the reply comes back to *this* node, *this* probe.
    let fetch_op = RegistryOp::Fetch { artifact_hash: artifact_hash.clone(), realm: None };
    let fetch_payload = serde_json::to_vec(&fetch_op).unwrap();
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
    .expect("fetch reply arrives from A across the wire");
    assert_eq!(fetch_env.header.corr, Some(4), "corr preserved across the wire");
    let fetch_reply: RegistryReply = serde_json::from_slice(&fetch_env.payload).unwrap();
    let (m_fetched, art_fetched) = match fetch_reply {
        RegistryReply::Fetched { manifest, artifact, .. } => (manifest, artifact),
        other => panic!("expected Fetched, got {other:?}"),
    };
    assert_eq!(m_fetched, built_manifest, "fetched manifest matches what A published");
    assert_eq!(art_fetched, built_artifact, "fetched artifact bytes match what A published");

    // Drain any stragglers from the retry loop so the next round-trip's recv_with_corr starts
    // clean (corr filter would skip them anyway — this is belt-and-suspenders for the inbox depth).
    std::thread::sleep(scaled(Duration::from_millis(100)));
    while b.probe_rx.recv_timeout(scaled(Duration::from_millis(50))).is_ok() {}

    // -- step 5: admit + safe load on B --
    // B's SignedPolicy fires here: signature check (ed25519), author allowlist (the Abode key is
    // on B's allowlist by construction), artifact-bytes hash check (re-hash + compare to
    // `provenance.build_hash`). Then the engine spills the bytes to a tempfile and dlopens via
    // the safe-lifecycle path.
    let loaded_id = b
        .kernel
        .load(m_fetched.clone(), Artifact::Bytes(art_fetched.clone()))
        .expect("ship→admit→load on B");

    // -- step 6: invoke on B —
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
        "reverse-daemon authored on A, shipped to B, ran on B — reversed the bytes correctly"
    );

    // -- step 7: unload via safe path on B --
    b.kernel.unload(loaded_id, Deadline::from_millis(500)).expect("safe unload on B");
    assert!(
        !b.kernel.is_loaded(loaded_id),
        "is_loaded must flip to false post-unload — no zombie entry in the loaded table"
    );
    // Post-unload sends to the same id must surface as the `NoSuchModule` route error (the gate is *after* the
    // load table lookup, *before* any creature-level dispatch). This is the unload contract test from
    // the inside: the kernel doesn't pretend the unloaded id is still wired.
    let post_unload_err = b
        .probe_bus
        .send(Dispatch::to(Address::Creature(loaded_id), b"ghost".to_vec()))
        .expect_err("post-unload send must fail (the creature is gone)");
    assert!(
        matches!(post_unload_err, RouteError::NoSuchModule(_)),
        "post-unload route must be NoSuchModule, got {post_unload_err:?}"
    );

    // -- step 8: reload the SAME (manifest, artifact) on B --
    // This is the reload primitive applied to a real shipped artifact, not the synthetic
    // hammer-loop. We don't re-fetch — we re-use the bytes that already crossed the wire, the
    // way an operator's local registry would cache them after the first fetch.
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

    // -- step 9: capability calls-gate on a restricted probe --
    // Open a SECOND probe endpoint on B with calls = ["creature:<reloaded_id>"] — it may address
    // the shipped creature, nothing else. We use B's *open* probe (the one we've been driving
    // through this test) as the forbidden sibling sink — sending to it from the restricted probe
    // must be Denied at the one router choke point (no creature is involved, no dispatch crosses
    // any boundary; the gate is admit-and-route).
    let open_probe_id = b.probe_bus.id();
    let restricted_caps = Capabilities {
        calls: vec![format!("creature:{}", reloaded_id.0)],
        ..Capabilities::default()
    };
    let (restricted_probe_id, restricted_bus, restricted_rx) =
        b.kernel.open_endpoint(restricted_caps);

    // Allowed send: restricted probe → shipped creature works.
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

    // Disallowed send: restricted probe → open probe must be Denied (a sibling endpoint not on
    // the allowlist). The shipped creature is the *only* destination the restricted probe is
    // entitled to address; anything else hits the gate.
    let denied = restricted_bus
        .send(Dispatch::to(Address::Creature(open_probe_id), b"sneak".to_vec()))
        .expect_err("disallowed destination must be denied");
    assert!(
        matches!(denied, RouteError::Denied { from } if from == restricted_probe_id),
        "expected RouteError::Denied with restricted-probe id, got {denied:?}"
    );

    // -- step 10: unload + shutdown cleanly --
    b.kernel
        .unload(reloaded_id, Deadline::from_millis(500))
        .expect("final unload of shipped creature");
    assert!(!b.kernel.is_loaded(reloaded_id));

    // shutdown_all drives transport-tcp's listener/dialer/reader/writer joins (no leaked tids,
    // satisfies the lifecycle contract on the boot creatures), unloads everything via the
    // safe path, and lets the test process exit cleanly.
    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
