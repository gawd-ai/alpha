//! **The author→ship→verify→run loop, end-to-end over a real
//! authenticated channel between two `alpha node` kernels.**
//!
//! Setup:
//! - Two in-process kernels A and B, each with its own `transport-tcp` + `registry-mem` creature.
//! - Each binds the transport/registry roles: `Role::TRANSPORT` to the TCP transport,
//!   `Role::REGISTRY` to the in-memory store.
//! - Each transport is configured with the OTHER's pubkey in its peer allowlist; B dials A and
//!   A waits to accept (one direction is enough — the channel is bidirectional once up).
//!
//! Flow:
//! 1. A signs an `echo-daemon` manifest with its Abode authoring key and publishes
//!    `(manifest, artifact_bytes)` to its local registry over the bus.
//! 2. B sends a `RegistryOp::Fetch { artifact_hash }` addressed to
//!    `Address::Node(NODE_A, registry_id_on_a)`. The envelope crosses the wire through the
//!    handshake-authenticated TCP channel; A's transport re-routes it locally; A's registry
//!    replies via `reply_to` (which the transport rewrote to a `Node(NODE_B, …)` address); A's
//!    transport ships the reply back; B's transport delivers it to B's probe.
//! 3. B's kernel admits the fetched manifest (real ed25519 verify + artifact-bytes hash recompute)
//!    and loads it via the safe loader (native-from-bytes spills to a tempfile, dlopens).
//! 4. B sends a payload to the loaded creature; the reply confirms the creature is running on B.
//!
//! Exit (a): step 4 returns the correct reply.
//! Exit (d): step 1 + step 2 prove publish/fetch round-trip with integrity + auth gates honored
//! at both ends.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Bus, Deadline, Dispatch, Ed25519Verifier, InboxReceiver, NodeId, Role, StubSigner,
    Topic,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply};
use sanctum::Kernel;
use sha2::{Digest, Sha256};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

mod support;
use support::native_cdylib;

const NODE_A: &str = "node-A";
const NODE_B: &str = "node-B";

/// Multiplier on every wall-clock budget the test uses. Valgrind slows process execution
/// ~10–50×; setting `GAWD_SLOW_TEST=N` lets the valgrind harness (tests/memcheck/m2-valgrind.sh)
/// scale all timeouts uniformly without forking the test for that case. Default 1 = native
/// speed; valgrind script sets it to 30.
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

fn free_loopback_pair() -> (u16, u16) {
    let a = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port A");
    let b = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port B");
    let ports = (
        a.local_addr().expect("port A local addr").port(),
        b.local_addr().expect("port B local addr").port(),
    );
    drop((a, b));
    ports
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

struct KernelCleanup {
    kernels: Vec<Arc<Kernel>>,
    deadline_ms: u64,
}

impl KernelCleanup {
    fn new(deadline: Duration) -> Self {
        let deadline_ms = deadline.as_millis().min(u64::MAX as u128) as u64;
        Self { kernels: Vec::new(), deadline_ms }
    }

    fn push(&mut self, kernel: &Arc<Kernel>) {
        self.kernels.push(kernel.clone());
    }
}

impl Drop for KernelCleanup {
    fn drop(&mut self) {
        for kernel in &self.kernels {
            kernel.shutdown_all(Deadline::from_millis(self.deadline_ms));
        }
    }
}

fn boot_manifest(name: &str) -> Manifest {
    // Boot creatures (transport, registry) admit via the `load_instance` path which skips the
    // artifact-bytes check; they still need a manifest the policy will accept. We give them an
    // author the policy allowlists at construction time (passed alongside the Abode key below).
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn signed_boot_manifest(name: &str, abode: &Ed25519KeyMaterial) -> Manifest {
    let mut m = boot_manifest(name);
    m.provenance.author = Some(abode.public_hex().to_string());
    let sig = abode.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

fn signed_artifact_manifest(
    name: &str,
    artifact_bytes: &[u8],
    abode: &Ed25519KeyMaterial,
) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(abode.public_hex().to_string());
    m.provenance.build_hash = Some(sha256_hex(artifact_bytes));
    let sig = abode.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

#[test]
fn end_to_end_ship_admit_load_run_across_two_nodes() {
    let (port_a, port_b) = free_loopback_pair();
    let mut cleanup = KernelCleanup::new(scaled(Duration::from_millis(1500)));

    // ---- keys ----
    // Three keys: A's node key (transport auth), B's node key (transport auth), and an Abode key
    // representing "the author of this creature" — which is what the receiving policy's allowlist
    // gates.
    let node_a_key = Ed25519KeyMaterial::from_seed([10u8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([11u8; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([42u8; 32]).unwrap();
    // The operator-policy allowlist on both kernels: the Abode key (artifact author) AND each
    // node's *own* node key for the in-process boot creatures (transport, registry) which we sign
    // with the node key for symmetry.
    let allowlist_a = vec![abode.public_hex().to_string(), node_a_key.public_hex().to_string()];
    let allowlist_b = vec![abode.public_hex().to_string(), node_b_key.public_hex().to_string()];

    // ---- kernel A ----
    let k_a = kernel(allowlist_a);
    cleanup.push(&k_a);
    let (events_a, _events_bus_a, rx_events_a) = k_a.open_endpoint(Capabilities::default());
    k_a.subscribe(Topic::new(Topic::PROPRIOCEPTION), events_a);
    let registry_a = k_a
        .load_instance(
            signed_boot_manifest("registry-mem", &node_a_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry-A admits");
    k_a.bind_role(Role::new(Role::REGISTRY), registry_a);

    let transport_a_cfg = TransportConfig {
        self_key: node_a_key.clone(),
        self_node: NodeId(NODE_A.into()),
        listen_addr: format!("127.0.0.1:{port_a}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_B.into()),
            pubkey_hex: node_b_key.public_hex().to_string(),
            dial_addr: None, // passive; B dials us
        }],
    };
    let transport_a = k_a
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_a_key),
            Box::new(TransportTcp::new(transport_a_cfg)),
        )
        .expect("transport-A admits");
    k_a.bind_role(Role::new(Role::TRANSPORT), transport_a);

    // ---- kernel B ----
    let k_b = kernel(allowlist_b);
    cleanup.push(&k_b);
    let (events_b, _events_bus_b, rx_events_b) = k_b.open_endpoint(Capabilities::default());
    k_b.subscribe(Topic::new(Topic::PROPRIOCEPTION), events_b);
    let _registry_b = k_b
        .load_instance(
            signed_boot_manifest("registry-mem", &node_b_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry-B admits");
    let transport_b_cfg = TransportConfig {
        self_key: node_b_key.clone(),
        self_node: NodeId(NODE_B.into()),
        listen_addr: format!("127.0.0.1:{port_b}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_A.into()),
            pubkey_hex: node_a_key.public_hex().to_string(),
            dial_addr: Some(format!("127.0.0.1:{port_a}")),
        }],
    };
    let transport_b = k_b
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_b_key),
            Box::new(TransportTcp::new(transport_b_cfg)),
        )
        .expect("transport-B admits");
    k_b.bind_role(Role::new(Role::TRANSPORT), transport_b);

    assert!(
        wait_for_peer_event(
            &rx_events_a,
            NODE_B,
            "peer_connected",
            scaled(Duration::from_secs(10))
        ),
        "A did not observe B connecting"
    );
    assert!(
        wait_for_peer_event(
            &rx_events_b,
            NODE_A,
            "peer_connected",
            scaled(Duration::from_secs(10))
        ),
        "B did not observe A connecting"
    );

    // ---- author the artifact on A + publish ----
    let echo_so = native_cdylib("echo_daemon");
    let echo_bytes = std::fs::read(&echo_so).expect("read echo-daemon .so");
    let echo_manifest = signed_artifact_manifest("echo-daemon", &echo_bytes, &abode);
    let expected_hash = sha256_hex(&echo_bytes);

    let (probe_a, bus_a, rx_a) = k_a.open_endpoint(Capabilities::default());
    let publish =
        RegistryOp::Publish { manifest: echo_manifest.clone(), artifact: echo_bytes.clone() };
    let publish_payload = serde_json::to_vec(&publish).unwrap();
    bus_a
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::REGISTRY)), publish_payload)
                .with_reply_to(Address::Creature(probe_a))
                .with_corr(1),
        )
        .expect("publish to local registry");
    // 5s is generous for a local handoff; the registry deserializes the hex-encoded artifact
    // (one JSON string token), inserts into a HashMap, and replies — sub-second on a debug build.
    // Under valgrind (GAWD_SLOW_TEST=30) this becomes 150s.
    let pub_reply_env = rx_a.recv_timeout(scaled(Duration::from_secs(5))).expect("publish reply");
    let pub_reply: RegistryReply = serde_json::from_slice(&pub_reply_env.payload).unwrap();
    let artifact_hash = match pub_reply {
        RegistryReply::Published { artifact_hash } => artifact_hash,
        other => panic!("expected Published, got {other:?}"),
    };
    // The registry indexes by artifact-bytes sha256 — same value `provenance.build_hash` carries,
    // distinct from `Manifest::content_address` (the identity-shape hash).
    assert_eq!(artifact_hash, expected_hash, "registry artifact_hash = sha256(artifact)");

    // ---- fetch from B over the wire ----
    let (probe_b, bus_b, rx_b) = k_b.open_endpoint(Capabilities::default());
    let fetch_op = RegistryOp::Fetch { artifact_hash: artifact_hash.clone() };
    let fetch_payload = serde_json::to_vec(&fetch_op).unwrap();

    // The peer-connected events above prove the transport writer is installed, so send one fetch and
    // wait for its correlated reply. Retrying here is counterproductive: the reply carries the debug
    // native artifact as JSON bytes, so repeated fetches can queue multiple large TCP frames and make
    // a slow CI host look like a transport failure.
    bus_b
        .send(
            Dispatch::to(Address::Node(NodeId(NODE_A.into()), registry_a), fetch_payload.clone())
                .with_reply_to(Address::Creature(probe_b))
                .with_corr(7),
        )
        .expect("send fetch over the node transport");
    let fetch_env = recv_with_corr(&rx_b, 7, scaled(Duration::from_secs(30)))
        .expect("fetch reply arrives across the wire");

    assert_eq!(fetch_env.header.corr, Some(7), "corr preserved across the wire");

    let reply: RegistryReply = serde_json::from_slice(&fetch_env.payload).unwrap();
    let (m_fetched, art_fetched) = match reply {
        RegistryReply::Fetched { manifest, artifact } => (manifest, artifact),
        other => panic!("expected Fetched across the wire, got {other:?}"),
    };
    assert_eq!(m_fetched, echo_manifest, "fetched manifest equals what A published");
    assert_eq!(art_fetched, echo_bytes, "fetched artifact bytes equal what A published");

    // ---- admit + load on B via the safe path ----
    // This is the ship→admit→load gate firing for real: B's verifier checks the signature
    // against B's policy allowlist; B's admission re-hashes the artifact bytes and compares to
    // the manifest's `build_hash`. Either failing here would surface as AdmissionRejected.
    let loaded_id = k_b
        .load(m_fetched, Artifact::Bytes(art_fetched))
        .expect("ship→admit→load on B succeeds for a properly authored creature");

    // ---- run on B ----
    // Give the transport threads a short settle window after the large fetch, then discard any
    // unrelated envelope before waiting for the first reply with corr=99.
    std::thread::sleep(scaled(Duration::from_millis(100)));
    while rx_b.recv_timeout(scaled(Duration::from_millis(50))).is_ok() {}

    bus_b
        .emit(
            Dispatch::to(Address::Creature(loaded_id), b"abc".to_vec())
                .with_reply_to(Address::Creature(probe_b))
                .with_corr(99),
        )
        .expect("send to loaded creature");
    let echo_reply = recv_with_corr(&rx_b, 99, scaled(Duration::from_secs(3)))
        .expect("loaded creature replies on B");
    assert_eq!(
        echo_reply.payload, b"cba",
        "echo-daemon authored on A, shipped to B, ran on B — and reversed the bytes"
    );

    // ---- cleanup ----
    // `cleanup` drives `shutdown_all` for both kernels on success and during assertion unwinds. That
    // joins transport listener/dialer/reader/writer threads so a failed assertion does not leave
    // leaked transport tids in the rest of the test process.
}

fn wait_for_peer_event(rx: &InboxReceiver, peer: &str, event: &str, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.schema == "peer_event" => {
                if let Ok(ev) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                    if ev.peer == peer && ev.event == event {
                        return true;
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    false
}

/// Drain envelopes off `rx` until one with the requested `corr` shows up, then return it. Earlier
/// envelopes are discarded — we don't want to hand the caller a stale fetch reply when they're
/// waiting on an echo reply.
fn recv_with_corr(
    rx: &aether::InboxReceiver,
    corr: u64,
    budget: Duration,
) -> Result<aether::Envelope, String> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.corr == Some(corr) => return Ok(env),
            Ok(_) => continue, // straggler from earlier dispatch — discard
            Err(_) => return Err("timeout waiting for corr".into()),
        }
    }
    Err("budget exhausted".into())
}
