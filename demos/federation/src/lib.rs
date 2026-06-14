//! federation — the GAWD **federation fabric**, narrated, over real TCP on loopback.
//!
//! `walkthrough` shows one node's loop (author → compile → sign → run → migrate). This binary
//! shows the *other* dimension: **many Sanctums, in several Realms, talking to each other**. It boots
//! `--realms N` Realms (default 2) of `--sanctums M` each (default 2) as separate in-process kernels,
//! wires each to its neighbours with the real `transport-tcp` creature over ed25519-authenticated
//! loopback sockets, and then narrates, progressively:
//!
//! 1. **within a Realm (cross-node):** a worker Sanctum fetches an artifact from its Realm gateway's
//!    registry — over the peer-authenticated wire (the transport half of the `m2_two_node.rs` path;
//!    m2 additionally re-verifies artifact integrity at the load/admit step, which this demo leaves to
//!    `walkthrough`).
//! 2. **across Realms (Loop 5, Acculturate):** a gateway pulls a peer Realm's registry
//!    (anti-entropy), federates a **signed reputation** score and a **quarantine** notice to the peer
//!    gateway, and routes an **Omega-addressed** query into another Realm and back.
//!
//! Every step rides the exact code paths the integration tests prove
//! (`omega_federation_cross_node.rs`, `m2_two_node.rs`, `distributor_cross_node.rs`) — there is no
//! demo-only back door. Topology is bounded to 3×3 so the loopback mesh stays reliable.
//!
//! Run it:  `cargo run -p federation`            (2 Realms × 2 Sanctums)
//!          `cargo run -p federation -- --realms 3 --sanctums 2`

use std::collections::{HashMap, HashSet};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, InboxReceiver, NodeId, RealmId, Role,
    StubSigner, Topic,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

use bestiary::{BestiaryStore, DeterministicCurator, FsBestiaryStore};
use bestiary_daemon::{BestiaryConfig, BestiaryDaemon};
use omega_federator::FederatorMsg;
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply, SyncEntry};
use sha2::{Digest, Sha256};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

// ----- narration ---------------------------------------------------------------------------------

fn banner(title: &str) {
    println!("\n\x1b[1m{title}\x1b[0m");
    println!("{}", "─".repeat(title.chars().count()));
}
fn step(msg: &str) {
    println!("\x1b[36m▸\x1b[0m {msg}");
}
fn ok(msg: &str) {
    println!("  \x1b[32m✓\x1b[0m {msg}");
}
fn note(msg: &str) {
    println!("    {msg}");
}
fn short(s: &str) -> String {
    s.chars().take(12).collect()
}

// ----- timing scaffolding (mirrors the cross-node test harnesses) --------------------------------

/// `GAWD_SLOW_TEST=N` scales every budget (so the demo survives a valgrind/ASan run the way the
/// transport tests do). Default 1 = native speed.
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Reserve `n` distinct loopback ports up front (bind :0, read the port, drop the listener so the
/// transport can rebind it). Same pattern the cross-node test uses for its two ports.
fn free_loopback_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> =
        (0..n).map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve loopback port")).collect();
    listeners.iter().map(|l| l.local_addr().expect("local addr").port()).collect()
    // listeners drop here, freeing the ports for the transports to claim.
}

// ----- topology ----------------------------------------------------------------------------------

const REALM_NAMES: [&str; 3] = ["crew", "guests", "kin"];

/// The per-Realm artifact each gateway publishes (raw bytes — federation moves catalog entries +
/// trust signals; running a *fetched* creature is `walkthrough`'s job).
fn artifact_bytes(realm: &str) -> Vec<u8> {
    format!("creature-from-{realm}").into_bytes()
}
fn artifact_manifest(realm: &str) -> Manifest {
    Manifest::new(realm, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

/// One booted Sanctum.
struct Node {
    name: String,
    realm: String,
    kernel: Arc<Kernel>,
    registry_id: CreatureId,
    federator_id: Option<CreatureId>,
    /// A probe endpoint subscribed to PROPRIOCEPTION — used both to observe peer handshakes and to
    /// drive request/reply (every read is corr-filtered, so sense traffic is skipped).
    probe_id: CreatureId,
    bus: BusHandle,
    rx: InboxReceiver,
    /// Peer node names this node shares a direct TCP link with (for the handshake wait).
    peers: Vec<String>,
    /// The on-disk root of this node's durable Bestiary, when `ALPHA_DURABLE_BESTIARY` is set
    /// (removed at teardown). `None` for the default in-memory registry.
    bestiary_root: Option<PathBuf>,
}

/// Run the federation demo to completion over the given CLI args. Invoked by the `federation`
/// binary and by `alpha demo federation`.
pub fn run(args: &[String]) {
    let (realms, sanctums) = parse_args(args);

    println!("\x1b[1mAlpha — the GAWD federation fabric, live in your terminal\x1b[0m");
    println!(
        "{realms} Realm(s) × {sanctums} Sanctum(s) = {} nodes, each a separate kernel, wired over real",
        realms * sanctums
    );
    println!(
        "ed25519-authenticated TCP on loopback. (Bounded to 3×3 so the mesh stays reliable.)\n"
    );

    let nodes = match boot_topology(realms, sanctums) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("\n\x1b[31mboot failed:\x1b[0m {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = run_scenario(&nodes, realms, sanctums) {
        eprintln!("\n\x1b[31mdemo failed:\x1b[0m {e}");
        teardown(&nodes);
        std::process::exit(1);
    }

    teardown(&nodes);

    banner("Done");
    println!("Everything above ran against live kernels through the same transport · registry ·");
    println!("federator path the test suite uses. The proofs over real sockets:");
    println!("  sanctum/tests/omega_federation_cross_node.rs   (cross-Realm pull · reputation · quarantine · routing)");
    println!(
        "  sanctum/tests/m2_two_node.rs                      (within-Realm ship → admit → run)"
    );
    println!(
        "  sanctum/tests/distributor_cross_node.rs           (cross-node capability placement)\n"
    );
}

fn parse_args(args: &[String]) -> (usize, usize) {
    let mut realms = 2usize;
    let mut sanctums = 2usize;
    let mut it = args.iter().cloned();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--realms" => {
                realms = it.next().and_then(|s| s.parse().ok()).unwrap_or(realms);
            }
            "--sanctums" => {
                sanctums = it.next().and_then(|s| s.parse().ok()).unwrap_or(sanctums);
            }
            "-h" | "--help" => {
                println!("usage: federation [--realms N] [--sanctums M]   (N, M each clamped to 1..=3; default 2 2)");
                std::process::exit(0);
            }
            other => {
                eprintln!("federation: ignoring unknown arg `{other}`");
            }
        }
    }
    (realms.clamp(1, 3), sanctums.clamp(1, 3))
}

// ----- boot --------------------------------------------------------------------------------------

/// Build the `realms × sanctums` mesh. Sanctum 0 of each Realm is its **gateway** (runs the
/// `omega-federator`); the rest are **workers**. Links: each worker ↔ its gateway (a per-Realm
/// star), plus a full mesh among gateways (so any Realm can reach any other). For every link the
/// higher global index dials the lower; nodes boot in index order, so a dialer's target is always
/// already listening.
///
/// Each gateway is the in-process equivalent of one [`omega serve`](omega) process: its
/// `OMEGA_GATEWAY` binding is bound by [`omega::serve::boot_federator`] — the same recipe the binary
/// runs in production — so what this demo narrates and what an operator deploys cannot drift.
fn boot_topology(realms: usize, sanctums: usize) -> Result<Vec<Node>, String> {
    let n = realms * sanctums;
    let g = |r: usize, s: usize| r * sanctums + s; // global index
    let realm_of = |idx: usize| idx / sanctums;
    let sanctum_of = |idx: usize| idx % sanctums;
    let is_gateway = |idx: usize| sanctum_of(idx) == 0;
    let node_name = |idx: usize| {
        let r = realm_of(idx);
        if is_gateway(idx) {
            format!("{}-gw", REALM_NAMES[r])
        } else {
            format!("{}-w{}", REALM_NAMES[r], sanctum_of(idx))
        }
    };

    let node_keys: Vec<Ed25519KeyMaterial> = (0..n)
        .map(|idx| Ed25519KeyMaterial::from_seed([(idx as u8).wrapping_add(1); 32]))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("node key: {e}"))?;
    let abode_keys: Vec<Ed25519KeyMaterial> = (0..n)
        .map(|idx| Ed25519KeyMaterial::from_seed([(idx as u8).wrapping_add(101); 32]))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("abode key: {e}"))?;
    let ports = free_loopback_ports(n);

    // Adjacency: links[idx] = [(peer_idx, this_node_dials_peer)]. For each link (a, b) with a < b,
    // b dials a — and since nodes boot in index order, a is already listening when b dials.
    fn connect(links: &mut [Vec<(usize, bool)>], a: usize, b: usize) {
        links[a].push((b, false));
        links[b].push((a, true));
    }
    let mut links: Vec<Vec<(usize, bool)>> = vec![Vec::new(); n];
    for r in 0..realms {
        for s in 1..sanctums {
            connect(&mut links, g(r, 0), g(r, s)); // worker ↔ gateway
        }
    }
    for i in 0..realms {
        for j in (i + 1)..realms {
            connect(&mut links, g(i, 0), g(j, 0)); // gateway ↔ gateway
        }
    }

    banner("Booting the mesh");
    if std::env::var("ALPHA_DURABLE_BESTIARY").is_ok() {
        note("registry backend: durable bestiary-daemon (ALPHA_DURABLE_BESTIARY set) — on-disk, signed-log store");
    } else {
        note("registry backend: in-memory registry-mem (set ALPHA_DURABLE_BESTIARY=1 to run on the durable Bestiary)");
    }
    note("each gateway = one `omega serve` Sanctum in-process (its OMEGA_GATEWAY binding is omega::serve::boot_federator, the very recipe the binary runs); workers are `alpha node` Sanctums");
    let mut nodes: Vec<Node> = Vec::with_capacity(n);
    for idx in 0..n {
        let r = realm_of(idx);
        let realm = REALM_NAMES[r];
        let name = node_name(idx);
        let key = node_keys[idx].clone();

        // Each kernel allowlists its own node key — that's what signs its boot creatures.
        let kernel = Kernel::new(
            vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
            Arc::new(StubSigner::new(&name)),
            Arc::new(Ed25519Verifier),
            Arc::new(SignedPolicy::new(vec![key.public_hex().to_string()])),
            128,
        );

        // Probe + PROPRIOCEPTION subscription FIRST, so we never miss a peer-handshake event that
        // fires the instant the transport (loaded last) dials a node that is already up.
        let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
        kernel.subscribe(Topic::new(Topic::PROPRIOCEPTION), probe_id);

        // Registry — gateways seed their Realm's artifact (the federation target). With
        // ALPHA_DURABLE_BESTIARY set, bind the on-disk `bestiary-daemon` instead of the in-memory
        // stub; it serves every RegistryOp byte-identically, so the whole scenario runs unchanged on
        // a durable, signed-log store.
        let mut bestiary_root: Option<PathBuf> = None;
        let registry_id = if std::env::var("ALPHA_DURABLE_BESTIARY").is_ok() {
            let root = std::env::temp_dir()
                .join(format!("alpha-federation-bestiary-{}-{idx}", std::process::id()));
            let store = Arc::new(
                FsBestiaryStore::new(&root, abode_keys[idx].clone())
                    .map_err(|e| format!("{name}: bestiary store: {e}"))?,
            );
            if is_gateway(idx) {
                store
                    .put(&RealmId::new(realm), artifact_manifest(realm), artifact_bytes(realm))
                    .map_err(|e| format!("{name}: bestiary seed: {e}"))?;
            }
            bestiary_root = Some(root);
            let daemon = BestiaryDaemon::new(
                store,
                Arc::new(DeterministicCurator::default()),
                BestiaryConfig::local(),
            );
            kernel
                .load_instance(signed_boot_manifest("bestiary-daemon", &key), Box::new(daemon))
                .map_err(|e| format!("{name}: bestiary-daemon admits: {e}"))?
        } else {
            let registry = RegistryMem::new();
            if is_gateway(idx) {
                registry.publish_in(
                    RealmId::new(realm),
                    artifact_manifest(realm),
                    artifact_bytes(realm),
                );
            }
            kernel
                .load_instance(signed_boot_manifest("registry-mem", &key), Box::new(registry))
                .map_err(|e| format!("{name}: registry admits: {e}"))?
        };
        kernel.bind_role(Role::new(Role::REGISTRY), registry_id);

        // Federator (gateways only) — maps every *other* Realm to that Realm's gateway node. Each
        // gateway Sanctum here is the in-process equivalent of one `omega serve` process, so its
        // `OMEGA_GATEWAY` binding comes from the very recipe the binary runs in production —
        // `omega::serve::boot_federator` — rather than a demo-local copy. The manifest is the demo's
        // *signed* boot manifest (this kernel runs the strict `SignedPolicy`, not the binary's
        // `DevPolicy`), which is exactly why `boot_federator` takes the manifest as a parameter.
        let federator_id = if is_gateway(idx) {
            let mut realm_to_peer = HashMap::new();
            for (other_r, &other_name) in REALM_NAMES.iter().enumerate().take(realms) {
                if other_r != r {
                    realm_to_peer
                        .insert(RealmId::new(other_name), NodeId(format!("{other_name}-gw")));
                }
            }
            let fid = omega::serve::boot_federator(
                &kernel,
                signed_boot_manifest("omega-federator", &key),
                omega::serve::FederatorBootConfig {
                    self_node: NodeId(name.clone()),
                    self_realm: RealmId::new(realm),
                    local_registry: registry_id,
                    abode_key: abode_keys[idx].clone(),
                    realm_to_peer,
                },
            )
            .map_err(|e| format!("{name}: {e}"))?;
            Some(fid)
        } else {
            None
        };

        // Transport LAST — this is what dials, so everything it touches is already subscribed.
        let peers: Vec<PeerConfig> = links[idx]
            .iter()
            .map(|&(peer, dials)| PeerConfig {
                node_id: NodeId(node_name(peer)),
                pubkey_hex: node_keys[peer].public_hex().to_string(),
                dial_addr: if dials { Some(format!("127.0.0.1:{}", ports[peer])) } else { None },
            })
            .collect();
        let cfg = TransportConfig {
            self_key: key.clone(),
            self_node: NodeId(name.clone()),
            listen_addr: format!("127.0.0.1:{}", ports[idx]),
            peers,
        };
        let transport_id = kernel
            .load_instance(
                signed_boot_manifest("transport-tcp", &key),
                Box::new(TransportTcp::new(cfg)),
            )
            .map_err(|e| format!("{name}: transport admits: {e}"))?;
        kernel.bind_role(Role::new(Role::TRANSPORT), transport_id);

        let role = if is_gateway(idx) { "gateway" } else { "worker " };
        ok(&format!("{role} {name:<12} [realm {realm}] listening on 127.0.0.1:{}", ports[idx]));

        nodes.push(Node {
            name,
            realm: realm.to_string(),
            kernel,
            registry_id,
            federator_id,
            probe_id,
            bus,
            rx,
            peers: links[idx].iter().map(|&(peer, _)| node_name(peer)).collect(),
            bestiary_root,
        });
    }

    let total_links: usize = links.iter().map(Vec::len).sum::<usize>() / 2;
    step(&format!("waiting for all {total_links} TCP handshake(s) to authenticate…"));
    if !await_mesh(&nodes, scaled(Duration::from_secs(15))) {
        return Err("not every peer handshake completed in time".into());
    }
    ok("every link is up — the mesh is authenticated and routing");

    Ok(nodes)
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

/// Block until every node has observed a `peer_connected` event from each of its expected peers.
/// Both ends of a link observe the handshake, so degree(node) events per node confirms the mesh.
fn await_mesh(nodes: &[Node], budget: Duration) -> bool {
    for node in nodes {
        let expected: HashSet<&String> = node.peers.iter().collect();
        if expected.is_empty() {
            continue; // a lone node (1×1) has nothing to connect to
        }
        let mut seen: HashSet<String> = HashSet::new();
        let deadline = Instant::now() + budget;
        while seen.len() < expected.len() && Instant::now() < deadline {
            match node.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(env) if env.header.schema == "peer_event" => {
                    if let Ok(ev) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                        if ev.event == "peer_connected" && expected.contains(&ev.peer) {
                            seen.insert(ev.peer);
                        }
                    }
                }
                _ => continue,
            }
        }
        if seen.len() < expected.len() {
            return false;
        }
    }
    true
}

// ----- the narrated run --------------------------------------------------------------------------

fn run_scenario(nodes: &[Node], realms: usize, sanctums: usize) -> Result<(), String> {
    // --- Phase A: within a Realm (cross-node) --------------------------------------------------
    banner("Phase A · Within a Realm — a worker fetches from its gateway, over the wire");
    if sanctums < 2 {
        note("(only 1 Sanctum per Realm — run with `--sanctums 2` to see the cross-node fetch.)");
    } else {
        let gw = &nodes[0]; // realm 0 gateway
        let worker = &nodes[1]; // realm 0, sanctum 1
        let hash = sha256_hex(&artifact_bytes(&gw.realm));
        step(&format!(
            "{} asks {} (a different node) for artifact {}… in Realm `{}`, via Address::Node",
            worker.name,
            gw.name,
            short(&hash),
            gw.realm,
        ));
        let op =
            RegistryOp::Fetch { artifact_hash: hash.clone(), realm: Some(RealmId::new(&gw.realm)) };
        let reply = roundtrip(
            worker,
            Address::Node(NodeId(gw.name.clone()), gw.registry_id),
            op,
            7001,
            scaled(Duration::from_secs(10)),
        )
        .ok_or("no fetch reply across the wire")?;
        match reply {
            RegistryReply::Fetched { artifact, .. } => ok(&format!(
                "fetched {} bytes (\"{}\") over the peer-authenticated TCP channel — admission (the integrity gate) runs at load time, which walkthrough shows",
                artifact.len(),
                String::from_utf8_lossy(&artifact)
            )),
            other => return Err(format!("expected Fetched across the wire, got {other:?}")),
        }
    }

    // --- Phase B / C: across Realms (Loop 5, Acculturate) --------------------------------------
    banner("Phase B · Across Realms — pull · reputation · quarantine · routing (Loop 5)");
    if realms < 2 {
        note("(only 1 Realm — run with `--realms 2` to see federation between Realms.)");
        return Ok(());
    }

    let gw0 = &nodes[0]; // realm 0 gateway (we drive from here)
    let gw1 = &nodes[sanctums]; // realm 1 gateway = global index 1*sanctums
    let realm0 = gw0.realm.clone();
    let realm1 = gw1.realm.clone();
    let fed0 = gw0.federator_id.ok_or("realm 0 gateway has no federator")?;
    let fed1 = gw1.federator_id.ok_or("realm 1 gateway has no federator")?;
    let hash0 = sha256_hex(&artifact_bytes(&realm0));
    let hash1 = sha256_hex(&artifact_bytes(&realm1));

    // C1: gw0 pulls realm1 → learns realm1's artifact, tagged with realm1.
    step(&format!("{} pulls Realm `{realm1}` from {} (anti-entropy)…", gw0.name, gw1.name));
    drive_federator(
        gw0,
        fed0,
        FederatorMsg::PullFrom {
            source_realm: RealmId::new(&realm1),
            peer_node: NodeId(gw1.name.clone()),
            peer_registry: gw1.registry_id,
        },
        2001,
    )?;
    if !poll_entries(
        gw0,
        Address::Creature(gw0.registry_id),
        Some(RealmId::new(&realm1)),
        |es| es.iter().any(|e| e.artifact_hash == hash1 && e.realm == RealmId::new(&realm1)),
        scaled(Duration::from_secs(10)),
    ) {
        return Err(format!("{} never learned {realm1}'s artifact via pull", gw0.name));
    }
    ok(&format!(
        "{}'s registry now lists `{realm1}`'s artifact, tagged with its home Realm",
        gw0.name
    ));

    // C2: gw1 pulls realm0 (so realm1 has realm0's artifact to attach a score to).
    step(&format!(
        "{} pulls Realm `{realm0}` from {} (setting up the reputation target)…",
        gw1.name, gw0.name
    ));
    drive_federator_at(
        gw0,
        Address::Node(NodeId(gw1.name.clone()), fed1),
        FederatorMsg::PullFrom {
            source_realm: RealmId::new(&realm0),
            peer_node: NodeId(gw0.name.clone()),
            peer_registry: gw0.registry_id,
        },
        2002,
    )?;
    if !poll_entries(
        gw0,
        Address::Node(NodeId(gw1.name.clone()), gw1.registry_id),
        Some(RealmId::new(&realm0)),
        |es| es.iter().any(|e| e.artifact_hash == hash0 && e.realm == RealmId::new(&realm0)),
        scaled(Duration::from_secs(10)),
    ) {
        return Err(format!("{} never learned {realm0}'s artifact", gw1.name));
    }
    ok(&format!("{} now holds `{realm0}`'s artifact (ready to be scored)", gw1.name));

    // C3: gw0 federates a signed reputation score for realm0's artifact to gw1.
    step(&format!(
        "{} federates a signed reputation score (0.95) for `{realm0}`'s artifact to {}…",
        gw0.name, gw1.name
    ));
    drive_federator(
        gw0,
        fed0,
        FederatorMsg::FederateReputation {
            artifact_hash: hash0.clone(),
            realm: RealmId::new(&realm0),
            score: 0.95,
            peer_node: NodeId(gw1.name.clone()),
            peer_federator: fed1,
        },
        2003,
    )?;
    if !poll_entries(
        gw0,
        Address::Node(NodeId(gw1.name.clone()), gw1.registry_id),
        Some(RealmId::new(&realm0)),
        |es| {
            es.iter().any(|e| {
                e.artifact_hash == hash0
                    && e.reputation.as_ref().is_some_and(|rep| {
                        (rep.score - 0.95).abs() < 1e-6
                            && rep.attesting_realm == Some(RealmId::new(&realm0))
                    })
            })
        },
        scaled(Duration::from_secs(10)),
    ) {
        return Err("reputation score did not propagate (signed) to the peer Realm".into());
    }
    ok(&format!(
        "{} verified the observer signature, weighed it, and recorded 0.95 tagged with `{realm0}`",
        gw1.name
    ));

    // C4: gw0 federates a quarantine notice for the same artifact.
    step(&format!(
        "{} federates a quarantine notice for `{realm0}`'s artifact to {}…",
        gw0.name, gw1.name
    ));
    drive_federator(
        gw0,
        fed0,
        FederatorMsg::FederateQuarantine {
            artifact_hash: hash0.clone(),
            realm: RealmId::new(&realm0),
            reason: "apoptosis observed at home".into(),
            peer_node: NodeId(gw1.name.clone()),
            peer_federator: fed1,
        },
        2004,
    )?;
    if !poll_entries(
        gw0,
        Address::Node(NodeId(gw1.name.clone()), gw1.registry_id),
        Some(RealmId::new(&realm0)),
        |es| {
            es.iter().any(|e| {
                e.artifact_hash == hash0
                    && e.quarantine.as_ref().is_some_and(|q| q.reason.contains("apoptosis"))
            })
        },
        scaled(Duration::from_secs(10)),
    ) {
        return Err("quarantine notice did not propagate to the peer Realm".into());
    }
    ok(&format!("{} marked the artifact quarantined — the cross-Realm immune signal (the path Loop 4 reacts to)", gw1.name));

    // C5: Omega-addressed routing — a query into realm1 from realm0, routed by gw0's federator.
    step(&format!(
        "{} sends an Omega-addressed query into Realm `{realm1}` (routed by its federator)…",
        gw0.name
    ));
    let routed = roundtrip(
        gw0,
        Address::Omega {
            realm: RealmId::new(&realm1),
            target: Box::new(Address::Creature(gw1.registry_id)),
        },
        RegistryOp::ListEntries { realm: Some(RealmId::new(&realm1)) },
        2005,
        scaled(Duration::from_secs(10)),
    )
    .ok_or("no reply to the Omega-addressed query")?;
    match routed {
        RegistryReply::Entries { entries } if entries.iter().any(|e| e.artifact_hash == hash1) => {
            ok(&format!("the query reached `{realm1}` and returned its artifact — cross-Realm routing, no manual addressing"))
        }
        other => return Err(format!("Omega-routed query returned the wrong thing: {other:?}")),
    }

    // C6: with a third Realm, prove the gateway mesh reaches it too.
    if realms >= 3 {
        let gw2 = &nodes[2 * sanctums];
        let realm2 = gw2.realm.clone();
        let hash2 = sha256_hex(&artifact_bytes(&realm2));
        step(&format!(
            "{} pulls a *third* Realm `{realm2}` from {} (the gateway mesh scales)…",
            gw0.name, gw2.name
        ));
        drive_federator(
            gw0,
            fed0,
            FederatorMsg::PullFrom {
                source_realm: RealmId::new(&realm2),
                peer_node: NodeId(gw2.name.clone()),
                peer_registry: gw2.registry_id,
            },
            2006,
        )?;
        if !poll_entries(
            gw0,
            Address::Creature(gw0.registry_id),
            Some(RealmId::new(&realm2)),
            |es| es.iter().any(|e| e.artifact_hash == hash2 && e.realm == RealmId::new(&realm2)),
            scaled(Duration::from_secs(10)),
        ) {
            return Err(format!("{} never learned {realm2}'s artifact via the mesh", gw0.name));
        }
        ok(&format!("{} now lists artifacts from all {realms} Realms", gw0.name));
    }

    Ok(())
}

// ----- request/reply helpers (corr-filtered, like `omni` + the cross-node tests) --------------

/// Send a `FederatorMsg` control op to this node's *own* federator and wait for the `Accepted` ack.
fn drive_federator(
    node: &Node,
    federator: CreatureId,
    msg: FederatorMsg,
    corr: u64,
) -> Result<(), String> {
    drive_federator_at(node, Address::Creature(federator), msg, corr)
}

/// Send a `FederatorMsg` control op to `to` (possibly a cross-node `Address::Node`) and wait for the
/// `Accepted` ack on `node`'s probe.
fn drive_federator_at(
    node: &Node,
    to: Address,
    msg: FederatorMsg,
    corr: u64,
) -> Result<(), String> {
    node.bus
        .send(
            Dispatch::to(to, msg.to_bytes())
                .with_schema(omega_federator::SCHEMA)
                .with_corr(corr)
                .with_reply_to(Address::Creature(node.probe_id)),
        )
        .map_err(|e| format!("federator dispatch: {e}"))?;
    match recv_corr(&node.rx, corr, scaled(Duration::from_secs(8))) {
        Some(payload) => match FederatorMsg::parse(&payload) {
            Ok(FederatorMsg::Accepted { .. }) => Ok(()),
            Ok(FederatorMsg::Rejected { reason }) => Err(format!("federator rejected: {reason}")),
            Ok(other) => Err(format!("unexpected federator reply: {other:?}")),
            Err(e) => Err(format!("federator reply parse: {e}")),
        },
        None => Err("no ack from federator".into()),
    }
}

/// Send a `RegistryOp` to `to` and return the parsed `RegistryReply` (corr-filtered).
fn roundtrip(
    node: &Node,
    to: Address,
    op: RegistryOp,
    corr: u64,
    budget: Duration,
) -> Option<RegistryReply> {
    node.bus
        .send(
            Dispatch::to(to, serde_json::to_vec(&op).ok()?)
                .with_schema("registry.op")
                .with_corr(corr)
                .with_reply_to(Address::Creature(node.probe_id)),
        )
        .ok()?;
    let payload = recv_corr(&node.rx, corr, budget)?;
    serde_json::from_slice::<RegistryReply>(&payload).ok()
}

/// Poll a registry (local or cross-node) with `ListEntries` until `pred` holds or the budget expires.
fn poll_entries<F: Fn(&[SyncEntry]) -> bool>(
    node: &Node,
    to: Address,
    realm: Option<RealmId>,
    pred: F,
    budget: Duration,
) -> bool {
    let deadline = Instant::now() + budget;
    let mut corr = 9_000u64;
    while Instant::now() < deadline {
        corr += 1;
        if let Some(RegistryReply::Entries { entries }) = roundtrip(
            node,
            to.clone(),
            RegistryOp::ListEntries { realm: realm.clone() },
            corr,
            Duration::from_secs(2),
        ) {
            if pred(&entries) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Wait (bounded) for the reply correlated by `corr`, skipping stray sense/late envelopes; returns
/// its payload bytes.
fn recv_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env.payload),
            _ => continue,
        }
    }
    None
}

fn teardown(nodes: &[Node]) {
    for node in nodes {
        node.kernel.shutdown_all(Deadline::from_millis(1500));
        if let Some(root) = &node.bestiary_root {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}
