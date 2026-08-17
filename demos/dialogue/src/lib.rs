//! dialogue — two reference agents holding a conversation **across a Realm boundary**, narrated,
//! over real TCP on loopback.
//!
//! `federation` shows catalogues, reputation, and quarantine crossing between Realms. This demo shows
//! the thing those rails were laid for: **application traffic — a live, multi-turn agent conversation
//! — crossing a Realm boundary through the Omega gateway.** It is the in-process dress rehearsal for
//! the v0.5.0 headline ("AIs genuinely interacting across the mesh"): swap the reference agents for
//! LLM-backed ones and the same path carries two models collaborating across Realms.
//!
//! Topology (two Sanctums, two Realms, real `transport-tcp` over ed25519 loopback):
//! - **crew** (Realm A): an `omega-federator` (the OMEGA_GATEWAY) + a `dialogue-initiator` that opens
//!   conversations with a peer named by a plain [`Address`] — here `Omega{guests, …}`.
//! - **guests** (Realm B): a **stateful** conversational agent (a `dialogue-responder` over a
//!   reference responder that *remembers how many turns* the conversation has run).
//!
//! Each turn the initiator on crew sends a SEER `dialogue` Query addressed into Realm `guests`; the
//! federator routes it across the boundary; the agent answers, its reply rides `reply_to` back, and
//! the agent's turn counter climbs — an agent holding state across turns, conversing across the mesh.
//!
//! Every step rides the exact code the integration tests prove (`omega_app_routing_cross_node.rs`,
//! `dialogue_seam.rs`, `distributor_cross_realm.rs`); there is no demo-only back door.
//!
//! This release also shipped, with their own tests: **cross-Realm placement** (`distributor_cross_realm`),
//! **persistent critter memory** (the script tier now carries state across calls), and a **registry
//! eviction policy** (a bounded catalog that keeps accepting fresh artifacts) — the rest of the rails
//! the v0.5.0 story stands on.
//!
//! Run it:  `cargo run -p dialogue`

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, InboxReceiver, NodeId, RealmId, Role,
    StubSigner, Topic,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

use dialogue_initiator::{DialogueInitiator, RESULT_SCHEMA, START_SCHEMA};
use dialogue_responder::{DialogueResponder, Responder};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
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

/// `GAWD_SLOW_TEST=N` scales every transport budget, bounded to 1..=64.
fn slow_factor() -> u32 {
    const MAX_SLOW_FACTOR: u32 = 64;
    static FACTOR: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

    *FACTOR.get_or_init(|| match std::env::var("GAWD_SLOW_TEST") {
        Ok(raw) => match raw.parse::<u32>() {
            Ok(value) => {
                let bounded = value.clamp(1, MAX_SLOW_FACTOR);
                if bounded != value {
                    eprintln!(
                        "dialogue: GAWD_SLOW_TEST={value} is outside 1..={MAX_SLOW_FACTOR}; using {bounded}"
                    );
                }
                bounded
            }
            Err(_) => {
                eprintln!(
                    "dialogue: invalid GAWD_SLOW_TEST={raw:?}; expected an integer in 1..={MAX_SLOW_FACTOR}, using 1"
                );
                1
            }
        },
        Err(std::env::VarError::NotPresent) => 1,
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("dialogue: non-Unicode GAWD_SLOW_TEST; using 1");
            1
        }
    })
}
fn scaled(d: Duration) -> Duration {
    d.saturating_mul(slow_factor())
}

/// Reserve `n` distinct loopback ports up front (bind :0, read the port, drop the listener so the
/// transport can rebind it). Same pattern the cross-node tests use.
fn free_loopback_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> =
        (0..n).map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve loopback port")).collect();
    listeners.iter().map(|l| l.local_addr().expect("local addr").port()).collect()
}

const CREW: &str = "crew";
const GUESTS: &str = "guests";
const NODE_CREW: &str = "crew-sanctum";
const NODE_GUESTS: &str = "guests-sanctum";

/// The conversational agent on the peer Realm: a stateful [`Responder`] that **remembers how many
/// turns** the conversation has run. Interior mutability (an atomic), so each turn climbs even though
/// the trait hands it `&self`. The reference echo responder is stateless; this one shows the other
/// half of the v0.5.0 story — an agent that carries state across a conversation.
struct ConversationalAgent {
    turns: AtomicU64,
}

impl Responder for ConversationalAgent {
    fn respond(&self, prompt: &str) -> String {
        let n = self.turns.fetch_add(1, Ordering::Relaxed) + 1;
        format!("(turn {n} with you) I heard: \"{prompt}\"")
    }
}

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("dialogue-demo")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

fn signed_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

fn transport_cfg(
    node: &str,
    port: u16,
    key: &Ed25519KeyMaterial,
    peer: &str,
    peer_pub: &Ed25519KeyMaterial,
    dial: Option<u16>,
) -> TransportConfig {
    TransportConfig {
        self_key: key.clone(),
        self_node: NodeId(node.into()),
        listen_addr: format!("127.0.0.1:{port}"),
        peers: vec![PeerConfig {
            node_id: NodeId(peer.into()),
            pubkey_hex: peer_pub.public_hex().to_string(),
            dial_addr: dial.map(|p| format!("127.0.0.1:{p}")),
        }],
    }
}

fn wait_for_peer(rx: &InboxReceiver, peer: &str, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.schema == "peer_event" => {
                if let Ok(ev) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                    if ev.peer == peer && ev.event == "peer_connected" {
                        return true;
                    }
                }
            }
            _ => continue,
        }
    }
    false
}

/// Drive one conversation turn: the probe opens a dialogue with `prompt`; the initiator carries it
/// across the Realm boundary to the agent on `guests`, the agent answers, and the reply is relayed
/// back. Returns the agent's reply text.
fn say(
    bus: &BusHandle,
    rx: &InboxReceiver,
    initiator: CreatureId,
    corr: u64,
    prompt: &str,
) -> Option<String> {
    bus.send(
        Dispatch::to(Address::Creature(initiator), prompt.as_bytes().to_vec())
            .with_schema(START_SCHEMA)
            .with_corr(corr)
            .with_reply_to(Address::Creature(bus.id())),
    )
    .ok()?;
    let deadline = Instant::now() + scaled(Duration::from_secs(8));
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == RESULT_SCHEMA => {
                return String::from_utf8(env.payload).ok();
            }
            _ => continue,
        }
    }
    None
}

pub fn run(_args: &[String]) {
    banner("dialogue — two agents conversing across a Realm boundary");
    note("crew (Realm A) ── ed25519 TCP ── guests (Realm B)");
    note(
        "an initiator on crew opens a conversation with a stateful agent on guests, through Omega.",
    );

    let ports = free_loopback_ports(2);
    let (port_crew, port_guests) = (ports[0], ports[1]);
    let crew_key = Ed25519KeyMaterial::from_seed([0x11; 32]).unwrap();
    let guests_key = Ed25519KeyMaterial::from_seed([0x22; 32]).unwrap();

    // ---- Realm B (guests): the conversational agent ----------------------------------------------
    banner("1. boot Realm `guests` — the agent that will be spoken to");
    let guests = kernel(vec![guests_key.public_hex().to_string()]);
    let g_transport = guests
        .load_instance(
            signed_manifest("transport-tcp", &guests_key),
            Box::new(TransportTcp::new(transport_cfg(
                NODE_GUESTS,
                port_guests,
                &guests_key,
                NODE_CREW,
                &crew_key,
                Some(port_crew), // guests dials crew
            ))),
        )
        .expect("guests transport admits");
    guests.bind_role(Role::new(Role::TRANSPORT), g_transport);

    let agent_id = guests
        .load_instance(
            signed_manifest("conversational-agent", &guests_key),
            Box::new(DialogueResponder::new(Box::new(ConversationalAgent {
                turns: AtomicU64::new(0),
            }))),
        )
        .expect("agent admits");
    ok(&format!("a stateful conversational agent is live on `guests` as creature #{}", agent_id.0));

    // ---- Realm A (crew): the federator + the initiator -------------------------------------------
    banner("2. boot Realm `crew` — the gateway + the initiator");
    let crew = kernel(vec![crew_key.public_hex().to_string()]);
    // Subscribe before the transport can accept the guests dial. Peer events are best-effort topic
    // traffic, so opening this endpoint later could miss an already-completed handshake and make a
    // healthy demo time out. Keep the same bus/rx for the conversation below.
    let (_probe, bus, rx) = crew.open_endpoint(Capabilities::default());
    crew.router().subscribe(Topic::new(Topic::PROPRIOCEPTION), bus.id());
    let c_transport = crew
        .load_instance(
            signed_manifest("transport-tcp", &crew_key),
            Box::new(TransportTcp::new(transport_cfg(
                NODE_CREW,
                port_crew,
                &crew_key,
                NODE_GUESTS,
                &guests_key,
                None, // crew is passive; guests dials in
            ))),
        )
        .expect("crew transport admits");
    crew.bind_role(Role::new(Role::TRANSPORT), c_transport);

    let registry_id = crew
        .load_instance(signed_manifest("registry-mem", &crew_key), Box::new(RegistryMem::new()))
        .expect("crew registry admits");
    crew.bind_role(Role::new(Role::REGISTRY), registry_id);

    // The federator maps Realm `guests` to the guests Sanctum, so an Omega-addressed envelope
    // resolves across the boundary. This directly wires the same OmegaFederator + OMEGA_GATEWAY
    // role/config seam used by `omega serve`; unlike `federation`, it does not call the server's
    // shared boot helper.
    let mut realm_to_peer = std::collections::HashMap::new();
    realm_to_peer.insert(RealmId::new(GUESTS), NodeId(NODE_GUESTS.into()));
    let federator_id = crew
        .load_instance(
            signed_manifest("omega-federator", &crew_key),
            Box::new(OmegaFederator::new(FederatorConfig {
                self_node: NodeId(NODE_CREW.into()),
                self_realm: RealmId::new(CREW),
                local_registry: registry_id,
                abode_key: Ed25519KeyMaterial::from_seed([0x19; 32]).unwrap(),
                realm_to_peer,
                weigher: Box::new(RoundRobinReputation::new()),
            })),
        )
        .expect("crew federator admits");
    crew.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);

    // The initiator's peer is the agent on the OTHER Realm — named by a plain Omega address. This one
    // field is the whole seam: a local `Creature`, a cross-node `Node`, or this cross-Realm `Omega`.
    let peer = Address::Omega {
        realm: RealmId::new(GUESTS),
        target: Box::new(Address::Creature(agent_id)),
    };
    let initiator_id = crew
        .load_instance(
            signed_manifest("dialogue-initiator", &crew_key),
            Box::new(DialogueInitiator::new(peer).with_corr_seed(1)),
        )
        .expect("initiator admits");
    ok(&format!(
        "an initiator is live on `crew` as creature #{}, peer = Omega(guests, creature #{})",
        initiator_id.0, agent_id.0
    ));

    // ---- the conversation ------------------------------------------------------------------------
    banner("3. open the mesh — wait for the cross-Realm handshake");
    // On any failure past this point, shut both Sanctums down and exit non-zero — the same fail-loud
    // discipline `demos/walkthrough` and `demos/federation` use, so `alpha demo dialogue` (and CI)
    // actually catch a cross-mesh regression instead of printing "done" over a broken run.
    let bail = |code: i32| -> ! {
        crew.shutdown_all(Deadline::from_millis(1500));
        guests.shutdown_all(Deadline::from_millis(1500));
        std::process::exit(code);
    };

    if !wait_for_peer(&rx, NODE_GUESTS, scaled(Duration::from_secs(5))) {
        eprintln!("  ✗ crew↔guests handshake did not complete; aborting demo");
        bail(1);
    }
    ok("crew ↔ guests authenticated link is up");

    banner("4. converse — each turn crosses the Realm boundary, the agent remembers");
    let prompts = ["hello, neighbour", "what's it like over there?", "talk again soon"];
    for (i, prompt) in prompts.iter().enumerate() {
        let turn = i + 1;
        step(&format!("crew → guests:  \"{prompt}\""));
        let Some(reply) = say(&bus, &rx, initiator_id, turn as u64, prompt) else {
            eprintln!("  ✗ no reply within the window on turn {turn}");
            bail(1);
        };
        // Check the entire deterministic reply, not only its turn marker: this proves both state
        // continuity and byte-exact prompt delivery across the Realm boundary.
        let expected = format!("(turn {turn} with you) I heard: \"{prompt}\"");
        if reply != expected {
            eprintln!("  ✗ turn {turn} reply was {reply:?}; expected byte-exact {expected:?}");
            bail(1);
        }
        ok(&format!("guests → crew:  {reply}"));
        note("the turn rode Omega(guests, …) across the boundary; the reply's turn-count climbed.");
    }

    banner("done");
    note("Each turn was a SEER `dialogue` Query addressed into another Realm, routed by the Omega");
    note(
        "gateway, answered by a stateful agent whose turn-count climbed — application traffic, not",
    );
    note(
        "just catalogue federation, crossing the mesh. That is the seam the v0.5.0 headline rides:",
    );
    note("replace the agents with LLM-backed ones and they collaborate across Realms with no new wire.");

    crew.shutdown_all(Deadline::from_millis(1500));
    guests.shutdown_all(Deadline::from_millis(1500));
}
