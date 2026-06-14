//! `distribute` — the GAWD distribution path, live in your terminal.
//!
//! Two Sanctums on loopback, wired over real ed25519-authenticated TCP. Node **A** publishes a
//! creature into its registry. Node **B** issues a single `registry fetch-load` over its own control
//! plane — and that one operator command pulls the artifact in bounded GX chunks, integrity-checks
//! it (per-chunk + whole-file SHA-256), admits it, and loads it. Then B runs it.
//!
//! This is the cross-node ship → admit → load that `cosmos/sanctum/tests/m2_two_node.rs` proves over
//! real sockets — but as one command an operator (or an AI over MCP) types, instead of a hand-rolled
//! plan/pull/assemble loop. The verb that does it: `Verb::FetchLoad` in `cosmos/omni`.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier, InboxReceiver, NodeId,
    OriginEvent, OriginVerdict, Role, Topic, ORIGIN_EVENT_SCHEMA,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

use omni::{boot_control, boot_organs_with_monitor, recv_corr, AiControl, Verb, VerbResult};
use registry_mem::RegistryMem;

const NODE_A: &str = "node-A";
const NODE_B: &str = "node-B";
const CONTROL_SCHEMA: &str = "control_verb";

fn banner(title: &str) {
    println!("\n\x1b[1;36m== {title} ==\x1b[0m");
}
fn step(msg: &str) {
    println!("\x1b[2m·\x1b[0m {msg}");
}
fn ok(msg: &str) {
    println!("\x1b[32m✓\x1b[0m {msg}");
}
fn short(s: &str) -> String {
    s.chars().take(12).collect()
}

fn free_loopback_pair() -> (u16, u16) {
    let a = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port A");
    let b = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port B");
    let ports = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
    drop((a, b));
    ports
}

/// A node whose bus signer **is** its ed25519 node identity — the same key its transport
/// authenticates links with. That unification is what lets a peer verify this node's envelopes and
/// stamp a real `Verified` origin.
fn node_kernel(node_key: &Ed25519KeyMaterial) -> Arc<Kernel> {
    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(node_key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    );
    k.set_node_identity(node_key.public_hex().to_string());
    k
}

/// A Rhai critter that echoes its payload, padded with a leading comment so the artifact spans
/// several GX chunks at a small chunk size — so you can see the windowed pull, not a one-chunk
/// shortcut.
fn multichunk_echo_critter() -> Vec<u8> {
    let mut s = format!("// {}\n", "distribute ".repeat(700)); // ~8 KiB of comment
    s.push_str("fn handle(env) { env.payload }\n");
    s.into_bytes()
}

/// Wait (bounded) until `rx` sees a `peer_connected` proprioception event for `peer`.
fn wait_for_peer(rx: &InboxReceiver, peer: &str, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.schema == "peer_event" => {
                if let Ok(ev) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                    if ev.peer == peer && ev.event == "peer_connected" {
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

/// Drain the cross-node origin verdicts the transport published on PROPRIOCEPTION within `budget`.
fn collect_origin_verdicts(rx: &InboxReceiver, budget: Duration) -> Vec<OriginEvent> {
    let deadline = std::time::Instant::now() + budget;
    let mut out = Vec::new();
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.schema == ORIGIN_EVENT_SCHEMA => {
                if let Ok(ev) = serde_json::from_slice::<OriginEvent>(&env.payload) {
                    out.push(ev);
                }
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    out
}

/// Drive one verb over node B's bus: ship it to `Role::CONTROL` and decode the `VerbResult` reply.
fn control_b(kernel: &Kernel, corr: u64, verb: &Verb) -> Result<VerbResult, String> {
    let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
    let payload = serde_json::to_vec(verb).map_err(|e| e.to_string())?;
    bus.send(
        Dispatch::to(Address::Role(Role::new(Role::CONTROL)), payload)
            .with_schema(CONTROL_SCHEMA)
            .with_reply_to(Address::Creature(probe_id))
            .with_corr(corr),
    )
    .map_err(|e| format!("control envelope did not route: {e}"))?;
    let reply = recv_corr(&rx, corr, Duration::from_secs(45)).ok_or("no VerbResult within 45s")?;
    serde_json::from_slice::<VerbResult>(&reply.payload).map_err(|e| e.to_string())
}

/// Run the distribute demo to completion. Invoked by the `distribute` binary and by
/// `alpha demo distribute`.
pub fn run(_args: &[String]) {
    println!("\x1b[1mAlpha — distribution: one `fetch-load`, a creature crosses the wire and runs\x1b[0m");
    println!(
        "Two Sanctums on loopback over real ed25519 TCP. A publishes; B fetch-loads + runs.\n"
    );

    if let Err(e) = run_inner() {
        eprintln!("\n\x1b[31mdemo failed:\x1b[0m {e}");
        std::process::exit(1);
    }
}

fn run_inner() -> Result<(), String> {
    let (port_a, port_b) = free_loopback_pair();
    let node_a_key = Ed25519KeyMaterial::from_seed([10u8; 32]).map_err(|e| e.to_string())?;
    let node_b_key = Ed25519KeyMaterial::from_seed([11u8; 32]).map_err(|e| e.to_string())?;

    // ---- node A: a registry seeded with a published creature + a transport ----
    banner("Node A — publish a creature into the registry");
    let k_a = node_kernel(&node_a_key);
    let script = multichunk_echo_critter();
    let manifest = Manifest::new("echo-pulled", "0.2.0", Backend::Critter, "gawd_critter_v1");
    let registry_a_instance = RegistryMem::new();
    let artifact_hash = registry_a_instance.publish(manifest, script.clone());
    step(&format!(
        "published `echo-pulled` ({} bytes) → artifact_hash {}…",
        script.len(),
        short(&artifact_hash)
    ));
    let registry_a = k_a
        .load_instance(
            Manifest::new("registry-mem", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(registry_a_instance),
        )
        .map_err(|e| format!("registry-A: {e}"))?;
    k_a.bind_role(Role::new(Role::REGISTRY), registry_a);
    let transport_a = k_a
        .load_transport_instance(
            Manifest::new("transport-tcp", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(TransportTcp::new(TransportConfig {
                self_key: node_a_key.clone(),
                self_node: NodeId(NODE_A.into()),
                listen_addr: format!("127.0.0.1:{port_a}"),
                peers: vec![PeerConfig {
                    node_id: NodeId(NODE_B.into()),
                    pubkey_hex: node_b_key.public_hex().to_string(),
                    dial_addr: None, // passive; B dials us
                }],
            })),
        )
        .map_err(|e| format!("transport-A: {e}"))?;
    k_a.bind_role(Role::new(Role::TRANSPORT), transport_a);
    ok(&format!("node A up on 127.0.0.1:{port_a}, registry creature id={}", registry_a.0));

    // ---- node B: a full node with the control plane + a transport that dials A ----
    banner("Node B — boot the control plane + dial A");
    let k_b = node_kernel(&node_b_key);
    let critter_builder = boot_organs_with_monitor(&k_b, false)?;
    let ai = Arc::new(AiControl::new(true)); // the human at B grants allow-AI for this run
    boot_control(&k_b, &ai, Some(critter_builder), None)?;
    let (events_b, _bus_b, rx_events_b) = k_b.open_endpoint(Capabilities::default());
    k_b.subscribe(Topic::new(Topic::PROPRIOCEPTION), events_b);
    let transport_b = k_b
        .load_transport_instance(
            Manifest::new("transport-tcp", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(TransportTcp::new(TransportConfig {
                self_key: node_b_key.clone(),
                self_node: NodeId(NODE_B.into()),
                listen_addr: format!("127.0.0.1:{port_b}"),
                peers: vec![PeerConfig {
                    node_id: NodeId(NODE_A.into()),
                    pubkey_hex: node_a_key.public_hex().to_string(),
                    dial_addr: Some(format!("127.0.0.1:{port_a}")),
                }],
            })),
        )
        .map_err(|e| format!("transport-B: {e}"))?;
    k_b.bind_role(Role::new(Role::TRANSPORT), transport_b);
    step("waiting for the ed25519 handshake A↔B…");
    if !wait_for_peer(&rx_events_b, NODE_A, Duration::from_secs(10)) {
        return Err("B never saw A connect (handshake did not complete)".into());
    }
    ok("handshake complete — the peer-authenticated channel is up");

    // ---- the payoff: ONE fetch-load on B pulls + verifies + loads the creature from A ----
    banner("Node B — `registry fetch-load <hash> node-A <registry-id>`");
    step("B issues one control verb; under it: FetchGxPlan → windowed FetchGxChunk → assemble → admit → load");
    let res = control_b(
        &k_b,
        1,
        &Verb::FetchLoad {
            artifact_hash: artifact_hash.clone(),
            node: Some(NODE_A.to_string()),
            registry_id: Some(registry_a.0),
            realm: None,
            chunk_size: Some(1024), // small chunks → a real multi-chunk transfer
        },
    )?;
    if !res.ok {
        return Err(format!("fetch-load failed: {}", res.human));
    }
    let chunks = res.json.get("chunks").and_then(|v| v.as_u64()).unwrap_or(0);
    let bytes = res.json.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
    let loaded_id = res.json.get("creature_id").and_then(|v| v.as_u64()).ok_or("no creature id")?;
    ok(&format!(
        "pulled {bytes} bytes in {chunks} GX chunks over the wire, integrity-verified, admitted + loaded on B as id={loaded_id}"
    ));

    // ---- run it on B ----
    banner("Node B — run the fetched creature");
    let res =
        control_b(&k_b, 2, &Verb::Send { id: loaded_id, text: "it ran on B".into(), node: None })?;
    let reply = res.json.get("reply").and_then(|v| v.as_str()).unwrap_or_default();
    if !res.ok || !reply.contains("it ran on B") {
        return Err(format!("the fetched creature did not run: {}", res.human));
    }
    ok(&format!("sent → echoed: \"{reply}\" — the creature A published is now alive on B"));

    // ---- the new guarantee, made visible: who B believes it heard from ----
    banner("Cross-node attribution — who signed the traffic B received");
    let verdicts = collect_origin_verdicts(&rx_events_b, Duration::from_millis(500));
    let verified = verdicts
        .iter()
        .filter(|e| e.origin_node.0 == NODE_A && e.verdict == OriginVerdict::Verified)
        .count();
    if verified > 0 {
        ok(&format!(
            "B verified {verified} cross-node frame(s) under node-A's authenticated ed25519 key  →  origin: {NODE_A}  verdict: Verified"
        ));
        step("the origin is sealed into each delivered envelope and re-signed by B's fabric — a sending creature cannot forge it, and an on-path tamper flips it to BadSig");
    } else {
        step("no origin verdict captured in the drain window (timing only) — the asserted proof is in cosmos/sanctum/tests/cross_node_origin.rs");
    }

    // ---- teardown ----
    k_a.shutdown_all(Deadline::from_millis(1500));
    k_b.shutdown_all(Deadline::from_millis(1500));

    banner("Done");
    println!(
        "One operator command moved a creature across a real authenticated socket and ran it."
    );
    println!("The same path, hand-scripted over sockets, is proven in:");
    println!("  cosmos/sanctum/tests/m2_two_node.rs        (cross-node ship → admit → run)");
    println!("  cosmos/omni/tests/fetch_load_verb.rs       (the fetch-load verb, end-to-end)\n");
    Ok(())
}
