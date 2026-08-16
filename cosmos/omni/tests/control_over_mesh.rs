//! **Remote control over the mesh**. Two nodes joined by `transport-tcp`;
//! node A drives node B's control plane by sending a `Verb` envelope to `Address::Node(B, B's
//! control id)` and reading the `VerbResult` back over the same authenticated transport. This is the
//! mechanism the MCP control-hub's remote mode rides: the Verb crosses to the peer's *own*
//! `ControlCore`, which runs it against its *own* kernel — no second protocol, no remote kernel
//! handle. Reuses the proven cross-node reply-rewrite path.
//!
//! Static ports 19_982 / 19_983 (distinct from the other tests' allocation table to avoid collisions).

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Deadline, Dispatch, NodeId, Role};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use transport_tcp::{PeerConfig, TransportConfig, TransportTcp};

use omni::{boot_control, boot_manifest, recv_corr, AiControl, Verb, VerbResult, CONTROL_SCHEMA};

const NODE_A: &str = "node-a";
const NODE_B: &str = "node-b";
const PORT_A: u16 = 19_982;
const PORT_B: u16 = 19_983;

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("mesh-test")),
        Arc::new(aether::StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    )
}

#[test]
fn node_a_drives_node_b_control_plane_over_the_mesh() {
    let a_key = Ed25519KeyMaterial::from_seed([0xA1; 32]).unwrap();
    let b_key = Ed25519KeyMaterial::from_seed([0xB2; 32]).unwrap();

    // ----- node B: control plane + an echo critter to message; B dials A is unnecessary (A dials B).
    let kb = kernel();
    let b_ai = Arc::new(AiControl::new(true)); // gate open so a remote mutation (send) is allowed
    let b_control = boot_control(&kb, &b_ai, None, None).expect("B control");
    let echo_b = kb
        .load(
            Manifest::new("echo-b", "0.1.0", Backend::Critter, "gawd_critter_v1"),
            Artifact::Bytes(b"fn handle(env) { env.payload }".to_vec()),
        )
        .expect("echo on B");
    let b_transport = kb
        .load_instance(
            boot_manifest("transport-tcp"),
            Box::new(TransportTcp::new(TransportConfig {
                self_key: b_key.clone(),
                self_node: NodeId(NODE_B.into()),
                listen_addr: format!("127.0.0.1:{PORT_B}"),
                peers: vec![PeerConfig {
                    node_id: NodeId(NODE_A.into()),
                    pubkey_hex: a_key.public_hex().to_string(),
                    dial_addr: None, // B is passive; A dials in
                }],
            })),
        )
        .expect("B transport");
    kb.bind_role(Role::new(Role::TRANSPORT), b_transport);

    // ----- node A: transport that dials B + a probe endpoint to drive B from.
    let ka = kernel();
    let a_transport = ka
        .load_instance(
            boot_manifest("transport-tcp"),
            Box::new(TransportTcp::new(TransportConfig {
                self_key: a_key.clone(),
                self_node: NodeId(NODE_A.into()),
                listen_addr: format!("127.0.0.1:{PORT_A}"),
                peers: vec![PeerConfig {
                    node_id: NodeId(NODE_B.into()),
                    pubkey_hex: b_key.public_hex().to_string(),
                    dial_addr: Some(format!("127.0.0.1:{PORT_B}")), // A dials B
                }],
            })),
        )
        .expect("A transport");
    ka.bind_role(Role::new(Role::TRANSPORT), a_transport);
    let (probe_id, probe_bus, probe_rx) = ka.open_endpoint(Capabilities::default());

    // Drive B's control plane from A: ship `verb` to Address::Node(B, B_control), reply to our probe.
    // Retry to ride out the handshake delay (an early send is dropped by the transport with no link).
    let drive = |corr: u64, verb: &Verb| -> Option<VerbResult> {
        let payload = serde_json::to_vec(verb).unwrap();
        let reply_capability = format!("mesh-control-capability-{corr}");
        for _ in 0..40 {
            let d = Dispatch::to(Address::Node(NodeId(NODE_B.into()), b_control), payload.clone())
                .with_schema(CONTROL_SCHEMA)
                .with_reply_to(Address::Creature(probe_id))
                .with_corr(corr)
                .with_commitment(reply_capability.clone());
            if probe_bus.send(d).is_ok() {
                if let Some(env) = recv_corr(&probe_rx, corr, Duration::from_millis(500)) {
                    assert_eq!(
                        env.header.commitment.as_deref(),
                        Some(reply_capability.as_str()),
                        "reply capability survives both authenticated transport rewrites"
                    );
                    return Some(serde_json::from_slice::<VerbResult>(&env.payload).unwrap());
                }
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        None
    };

    // (1) `status` — an inline read, answered by B's ControlCore over the mesh.
    let status = drive(1, &Verb::Status).expect("B answered status over the mesh");
    assert!(status.ok, "remote status ok: {:?}", status.json);
    assert_eq!(
        status.json.get("ai_allowed").and_then(|v| v.as_bool()),
        Some(true),
        "it is B's gate"
    );

    // (2) `send` to B's echo critter — an orchestration verb run on B's worker, reply over the mesh.
    let sent = drive(2, &Verb::Send { id: echo_b.0, text: "ping-from-a".into(), node: None })
        .expect("B answered send over the mesh");
    assert_eq!(
        sent.json.get("reply").and_then(|v| v.as_str()),
        Some("ping-from-a"),
        "B's echo replied"
    );

    ka.shutdown_all(Deadline::default());
    kb.shutdown_all(Deadline::default());
}
