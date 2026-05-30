//! **The "coming alive" loops composed.** One `#[test]` proves the four mechanisms
//! (migration, federation, selection, defense) **compose into one continuous flow on
//! a single self**, chained over a shared registry. It is the analogue of `v02_end_to_end`.
//!
//! ## Why in-process
//!
//! The dedicated suites already
//! prove every seam *across the wire*: `abode_migrate_cross_node` (migration over transport-tcp + cross
//! Realm), `omega_federation_cross_node` (pull + signed reputation + quarantine, A↔B), plus
//! the in-process `fitness_selection_local` (selection) and `immune_response_local` (defense). What no test
//! proves is that the four mechanisms **compose** — that one self can migrate, federate, select, and
//! defend on the same bus without the creatures stepping on each other. So this test composes them
//! **in-process on one Sanctum** (two `registry-mem` instances stand in for the source/destination
//! catalogs the federator moves entries between). No transport → no handshake-timing flakiness; the
//! cross-node reality is already covered. The continuous thread is a single artifact — the
//! `reverse-daemon`'s content address — that the migrated self knows about, the federator pulls, the
//! selector promotes, and the defender leaves alone (a *different* specimen is quarantined).
//!
//! ## The composed flow (four phases, one kernel)
//!
//! 1. **The self moves.** A source migrator holds the self's state (which names the
//!    reverse-daemon's hash) and hands it off to a destination migrator; source → `Migrated`,
//!    destination → `Authoritative`.
//! 2. **Realms see each other.** A federator pulls the `reverse-daemon` entry from the source
//!    registry into the destination registry (anti-entropy), then ships a signed reputation delta
//!    (score 0.9) that lands on the destination entry — peer reputation, stored unsigned (provenance
//!    = attesting Realm).
//! 3. **The fit are promoted.** A fitness-selector watches a live reverse-daemon creature,
//!    observes its successful handles, and on `Tick` writes a **signed, self-verifying promotion**
//!    onto the destination entry — upgrading the federated unsigned reputation into a checkable,
//!    heritable promotion.
//! 4. **The hostile are quarantined, the fit are spared.** A loaded specimen hits a `hard`
//!    budget breach; the immune-response quarantines *its* entry while the reverse-daemon's
//!    promotion stays intact and verifiable — **defense ≠ selection**, on the same registry.
//!
//! This is a **wiring/composition test**, not a stress test (the dedicated suites hammer each
//! seam). It proves the substrate is *alive* across Loops 2/4/5 — end to
//! end, in one place.

use std::sync::Arc;
use std::time::{Duration, Instant};

use abode_migrator::{AbodeMigrator, MigratorMsg, PermissiveRestorePolicy};
use aether::{
    Address, BudgetVector, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope,
    InboxReceiver, NodeId, Outcome, RealmId, Role, StubSigner, Topic,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use fitness_selector::{FitnessSelector, SelectorConfig, SelectorMsg};
use immune_response::{ImmuneConfig, ImmuneMsg, ImmuneResponse};
use omega_federator::{FederatorConfig, FederatorMsg, OmegaFederator, UnitWeigher};
use policy_quarantine_trust_all::TrustAllQuarantine;
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply};
use sanctum::{BudgetSignalEvent, Kernel};
use scorer_success_rate::SuccessRateScorer;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use std::collections::HashMap;

const SELF_NODE: &str = "v03-node";
const REALM: &str = "v03-wrap";

// ----- scaling (valgrind-friendly, shared with the other composed-loop suites) -------------------------------

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

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

/// Reverses its payload — the live "reverse-daemon" creature whose handles the selector scores.
struct Reverser;
impl Creature for Reverser {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
}

/// A trivial creature that is the defense specimen — exists only to be watched + quarantined.
struct Specimen;
impl Creature for Specimen {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

fn recv_match<T, F: Fn(&Envelope) -> Option<T>>(
    rx: &InboxReceiver,
    corr: u64,
    f: F,
    budget: Duration,
) -> Option<T> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) => {
                if let Some(v) = f(&env) {
                    return Some(v);
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

/// Poll the destination registry until `pred` holds on the `(REALM, hash)` entry, or time out.
#[allow(clippy::too_many_arguments)] // test helper: explicit bus/rx/probe/predicate/budget params
fn poll_entry<F: Fn(&registry_mem::SyncEntry) -> bool>(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    probe_id: CreatureId,
    registry_id: CreatureId,
    hash: &str,
    mut corr: u64,
    pred: F,
    budget: Duration,
) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        corr += 1;
        let _ = bus.send(
            Dispatch::to(
                Address::Creature(registry_id),
                serde_json::to_vec(&RegistryOp::ListEntries { realm: Some(RealmId::new(REALM)) })
                    .unwrap(),
            )
            .with_schema("registry.op")
            .with_corr(corr)
            .with_reply_to(Address::Creature(probe_id)),
        );
        let got = recv_match(
            rx,
            corr,
            |env| serde_json::from_slice::<RegistryReply>(&env.payload).ok(),
            Duration::from_millis(500),
        );
        if let Some(RegistryReply::Entries { entries }) = got {
            if let Some(e) = entries.iter().find(|e| e.artifact_hash == hash) {
                if pred(e) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    false
}

#[test]
fn v03_end_to_end_loop_proves_m9_m10_m11_m12_compose() {
    let abode = Ed25519KeyMaterial::from_seed([0x03u8; 32]).unwrap();
    let abode_pub = abode.public_hex().to_string();
    let node_key = Ed25519KeyMaterial::from_seed([0xC3u8; 32]).unwrap();

    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("v03-wrap")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![abode_pub.clone(), node_key.public_hex().to_string()])),
        256,
    );
    let realm = RealmId::new(REALM);

    // ----- the source registry, pre-seeded with the reverse-daemon entry (the federation subject) -
    let registry_src = RegistryMem::new();
    let reverse_hash = registry_src.publish_in(
        realm.clone(),
        Manifest::new("reverse-daemon", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        b"reverse-daemon-artifact-bytes".to_vec(),
    );
    let registry_src_id = k
        .load_instance(signed_boot_manifest("registry-src", &node_key), Box::new(registry_src))
        .expect("registry-src admits");
    // ----- the destination registry (federation merges here; selection + defense write here) ------
    let registry_dst_id = k
        .load_instance(
            signed_boot_manifest("registry-dst", &node_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry-dst admits");

    let (probe_id, probe, rx) = k.open_endpoint(Capabilities::default());

    // =============================================================================================
    // Phase 1 — the self moves. Source migrator hands off state (which names reverse_hash) to
    // the destination migrator (in-process; destination_node == self collapses to local addressing).
    // =============================================================================================
    let dest_migrator = AbodeMigrator::new(
        NodeId(SELF_NODE.into()),
        abode.clone(),
        Box::new(PermissiveRestorePolicy),
    );
    let dest_mig_id = k
        .load_instance(
            signed_boot_manifest("abode-migrator-dst", &node_key),
            Box::new(dest_migrator),
        )
        .expect("dest migrator admits");
    let src_migrator = AbodeMigrator::new(
        NodeId(SELF_NODE.into()),
        abode.clone(),
        Box::new(PermissiveRestorePolicy),
    );
    let src_mig_id = k
        .load_instance(
            signed_boot_manifest("abode-migrator-src", &node_key),
            Box::new(src_migrator),
        )
        .expect("src migrator admits");
    k.bind_role(Role::new(Role::ABODE_MIGRATOR), src_mig_id);

    // The self's state names the reverse-daemon — the thread tying the four phases together.
    let self_state = format!("self.knows.reverse_daemon={reverse_hash}").into_bytes();
    probe
        .send(
            Dispatch::to(
                Address::Creature(src_mig_id),
                MigratorMsg::SetState { payload: self_state }.to_bytes(),
            )
            .with_schema(abode_migrator::SCHEMA)
            .with_corr(901)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("SetState sends");
    recv_match(
        &rx,
        901,
        |e| MigratorMsg::parse(&e.payload).ok().filter(|m| matches!(m, MigratorMsg::StateSet)),
        scaled(Duration::from_secs(3)),
    )
    .expect("StateSet ack");

    probe
        .send(
            Dispatch::to(
                Address::Creature(src_mig_id),
                MigratorMsg::Migrate {
                    destination_node: NodeId(SELF_NODE.into()),
                    destination_migrator: dest_mig_id,
                }
                .to_bytes(),
            )
            .with_schema(abode_migrator::SCHEMA)
            .with_corr(902)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Migrate sends");
    let migrated_to = recv_match(
        &rx,
        902,
        |e| match MigratorMsg::parse(&e.payload).ok()? {
            MigratorMsg::MigrateAck { migrated_to } => Some(migrated_to),
            _ => None,
        },
        scaled(Duration::from_secs(4)),
    )
    .expect("MigrateAck received");
    assert_eq!(
        migrated_to,
        NodeId(SELF_NODE.into()),
        "M9: the self handed off to the destination body"
    );

    // Destination is now authoritative for the migrated state.
    probe
        .send(
            Dispatch::to(Address::Creature(dest_mig_id), MigratorMsg::StatusQuery.to_bytes())
                .with_schema(abode_migrator::SCHEMA)
                .with_corr(903)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("StatusQuery sends");
    let dest_state = recv_match(
        &rx,
        903,
        |e| match MigratorMsg::parse(&e.payload).ok()? {
            MigratorMsg::StatusReply { state, payload_len, .. } => Some((state, payload_len)),
            _ => None,
        },
        scaled(Duration::from_secs(3)),
    )
    .expect("dest StatusReply");
    assert_eq!(dest_state.0, "authoritative", "M9: destination owns the self after hand-off");
    assert!(dest_state.1 > 0, "M9: the migrated state arrived non-empty");

    // =============================================================================================
    // Phase 2 — Realms see each other. A federator pulls the reverse-daemon entry from the
    // source registry into the destination registry, then a signed reputation delta lands on it.
    // =============================================================================================
    let mut realm_to_peer = HashMap::new();
    realm_to_peer.insert(realm.clone(), NodeId(SELF_NODE.into()));
    let federator = OmegaFederator::new(FederatorConfig {
        self_node: NodeId(SELF_NODE.into()),
        self_realm: realm.clone(),
        local_registry: registry_dst_id,
        abode_key: abode.clone(),
        realm_to_peer,
        weigher: Box::new(UnitWeigher),
    });
    let federator_id = k
        .load_instance(signed_boot_manifest("omega-federator", &node_key), Box::new(federator))
        .expect("federator admits");
    k.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);

    // Pull the source catalog into the destination registry (anti-entropy; peer_node == self).
    probe
        .send(
            Dispatch::to(
                Address::Creature(federator_id),
                FederatorMsg::PullFrom {
                    source_realm: realm.clone(),
                    peer_node: NodeId(SELF_NODE.into()),
                    peer_registry: registry_src_id,
                }
                .to_bytes(),
            )
            .with_schema(omega_federator::SCHEMA)
            .with_corr(910)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("PullFrom sends");
    assert!(
        poll_entry(
            &probe,
            &rx,
            probe_id,
            registry_dst_id,
            &reverse_hash,
            1000,
            |_| true,
            scaled(Duration::from_secs(4))
        ),
        "M10: the reverse-daemon entry was federated from the source registry into the destination"
    );

    // Ship a signed reputation delta (the federator signs with the Abode key; peer_federator == self
    // so it ingests its own delta — proving the signed-delta → verify → registry path composes).
    probe
        .send(
            Dispatch::to(
                Address::Creature(federator_id),
                FederatorMsg::FederateReputation {
                    artifact_hash: reverse_hash.clone(),
                    realm: realm.clone(),
                    score: 0.9,
                    peer_node: NodeId(SELF_NODE.into()),
                    peer_federator: federator_id,
                }
                .to_bytes(),
            )
            .with_schema(omega_federator::SCHEMA)
            .with_corr(911)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("FederateReputation sends");
    assert!(
        poll_entry(
            &probe, &rx, probe_id, registry_dst_id, &reverse_hash, 2000,
            |e| e.reputation.as_ref().is_some_and(|r| (r.score - 0.9).abs() < 1e-6 && r.signed_by.is_none()),
            scaled(Duration::from_secs(4)),
        ),
        "M10: a signed reputation delta landed on the entry as unsigned peer reputation (score 0.9)"
    );

    // =============================================================================================
    // Phase 3 — the fit are promoted. A fitness-selector watches a live reverse-daemon, scores
    // its successful handles, and on Tick writes a SIGNED promotion onto the destination entry.
    // =============================================================================================
    let reverse_id = k
        .load_instance(signed_boot_manifest("reverse-daemon", &node_key), Box::new(Reverser))
        .expect("reverse-daemon admits");
    let selector = FitnessSelector::new(SelectorConfig {
        self_realm: realm.clone(),
        local_registry: registry_dst_id,
        abode_key: abode.clone(),
        threshold: 0.5,
        scorer: Box::new(SuccessRateScorer),
    });
    let selector_id = k
        .load_instance(signed_boot_manifest("fitness-selector", &node_key), Box::new(selector))
        .expect("selector admits");
    k.bind_role(Role::new(Role::FITNESS_SELECTOR), selector_id);

    // Passive relay (no drain thread → no fitness of its own → no self-feedback; the anti-feedback rule).
    let (relay_id, relay_bus, relay_rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::FITNESS), relay_id);

    // Watch the reverse-daemon, mapped to the federated registry entry.
    probe
        .send(
            Dispatch::to(
                Address::Creature(selector_id),
                SelectorMsg::Watch {
                    module: reverse_id.0,
                    realm: realm.clone(),
                    artifact_hash: reverse_hash.clone(),
                }
                .to_bytes(),
            )
            .with_schema(fitness_selector::SCHEMA)
            .with_corr(920)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Watch sends");
    recv_match(
        &rx,
        920,
        |e| {
            SelectorMsg::parse(&e.payload)
                .ok()
                .filter(|m| matches!(m, SelectorMsg::Watching { .. }))
        },
        scaled(Duration::from_secs(3)),
    )
    .expect("Watching ack");

    // Drive the reverse-daemon so the kernel emits real fitness events.
    for i in 0..5 {
        probe
            .send(Dispatch::to(Address::Creature(reverse_id), format!("ping-{i}").into_bytes()))
            .expect("ping sends");
    }
    // Relay the reverse-daemon's fitness events to the selector (the passive operator glue).
    let mut forwarded = 0usize;
    let relay_deadline = Instant::now() + scaled(Duration::from_secs(5));
    while forwarded < 3 && Instant::now() < relay_deadline {
        match relay_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(env) if env.header.schema == fitness_selector::FITNESS_EVENT_SCHEMA => {
                let v: serde_json::Value = match serde_json::from_slice(&env.payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("module").and_then(|m| m.as_u64()) == Some(reverse_id.0) {
                    relay_bus
                        .send(
                            Dispatch::to(Address::Creature(selector_id), env.payload.clone())
                                .with_schema(fitness_selector::FITNESS_EVENT_SCHEMA),
                        )
                        .expect("relay forward");
                    forwarded += 1;
                }
            }
            _ => continue,
        }
    }
    assert!(
        forwarded >= 3,
        "the relay must forward the reverse-daemon's fitness events (got {forwarded})"
    );

    // Tick → signed promotion.
    probe
        .send(
            Dispatch::to(Address::Creature(selector_id), SelectorMsg::Tick.to_bytes())
                .with_schema(fitness_selector::SCHEMA)
                .with_corr(921)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Tick sends");
    let promoted = recv_match(
        &rx,
        921,
        |e| match SelectorMsg::parse(&e.payload).ok()? {
            SelectorMsg::Ticked { promoted, .. } => Some(promoted),
            _ => None,
        },
        scaled(Duration::from_secs(3)),
    )
    .expect("Ticked reply");
    assert_eq!(
        promoted,
        vec![reverse_id.0],
        "M11: the reverse-daemon was promoted (success_rate 1.0 ≥ 0.5)"
    );

    // The destination entry now carries a SIGNED, self-verifying promotion (upgraded from the
    // federated unsigned reputation) — heredity made checkable.
    assert!(
        poll_entry(
            &probe,
            &rx,
            probe_id,
            registry_dst_id,
            &reverse_hash,
            3000,
            |e| e.reputation.as_ref().is_some_and(|r| {
                r.signed_by.as_deref() == Some(abode_pub.as_str())
                    && r.promotion_verifies(&reverse_hash, &RealmId::new(REALM), &Ed25519Verifier)
            }),
            scaled(Duration::from_secs(4)),
        ),
        "M11: the federated entry now carries a signed promotion that verifies"
    );

    // =============================================================================================
    // Phase 4 — the hostile are quarantined, the fit are spared. A specimen hits a hard budget
    // breach → its entry is quarantined; the reverse-daemon's promotion stays intact (defense ≠
    // selection).
    // =============================================================================================
    // Publish a specimen entry in the destination registry, and load the specimen creature.
    let specimen_hash = {
        // publish via the registry creature so the entry lives in registry_dst.
        probe
            .send(
                Dispatch::to(
                    Address::Creature(registry_dst_id),
                    serde_json::to_vec(&RegistryOp::PublishInRealm {
                        manifest: Manifest::new(
                            "specimen",
                            "0.1.0",
                            Backend::Daemon,
                            "gawd_creature_v1",
                        ),
                        artifact: b"specimen-artifact-bytes".to_vec(),
                        realm: realm.clone(),
                    })
                    .unwrap(),
                )
                .with_schema("registry.op")
                .with_corr(930)
                .with_reply_to(Address::Creature(probe_id)),
            )
            .expect("publish specimen");
        recv_match(
            &rx,
            930,
            |e| match serde_json::from_slice::<RegistryReply>(&e.payload).ok()? {
                RegistryReply::PublishedInRealm { artifact_hash, .. } => Some(artifact_hash),
                _ => None,
            },
            scaled(Duration::from_secs(3)),
        )
        .expect("specimen published")
    };
    let specimen_id = k
        .load_instance(signed_boot_manifest("specimen", &node_key), Box::new(Specimen))
        .expect("specimen admits");

    let immune = ImmuneResponse::new(ImmuneConfig {
        self_node: NodeId(SELF_NODE.into()),
        local_registry: registry_dst_id,
        trust: Box::new(TrustAllQuarantine),
        propagation: None,
    });
    let immune_id = k
        .load_instance(signed_boot_manifest("immune-response", &node_key), Box::new(immune))
        .expect("immune-response admits");
    k.bind_role(Role::new(Role::IMMUNE_RESPONSE), immune_id);
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), immune_id);

    // Watch the specimen.
    probe
        .send(
            Dispatch::to(
                Address::Creature(immune_id),
                ImmuneMsg::Watch {
                    module: specimen_id.0,
                    realm: realm.clone(),
                    artifact_hash: specimen_hash.clone(),
                }
                .to_bytes(),
            )
            .with_schema(immune_response::SCHEMA)
            .with_corr(931)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Watch specimen");
    recv_match(
        &rx,
        931,
        |e| ImmuneMsg::parse(&e.payload).ok().filter(|m| matches!(m, ImmuneMsg::Watching { .. })),
        scaled(Duration::from_secs(3)),
    )
    .expect("Watching specimen ack");

    // Inject a hard budget breach for the specimen on the PROPRIOCEPTION topic (the test stands in
    // for the engine that would emit it on a real breach — same wire).
    let signal = BudgetSignalEvent {
        module: specimen_id.0,
        level: "hard".into(),
        kind: "fuel".into(),
        vector: BudgetVector {
            consumed: 9_999,
            limit: 1_000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 0,
            envelopes_since_load: 2,
        },
    };
    probe
        .send(
            Dispatch::to(
                Address::Topic(Topic::new(Topic::PROPRIOCEPTION)),
                serde_json::to_vec(&signal).unwrap(),
            )
            .with_schema("budget_signal"),
        )
        .expect("budget signal publishes");

    // The specimen entry is quarantined…
    assert!(
        poll_entry(
            &probe,
            &rx,
            probe_id,
            registry_dst_id,
            &specimen_hash,
            4000,
            |e| e.quarantine.as_ref().is_some_and(|q| q.reason.contains("hard budget breach")),
            scaled(Duration::from_secs(4)),
        ),
        "M12: the specimen's hard budget breach quarantined its entry"
    );

    // …and the reverse-daemon is UNTOUCHED — still promoted, never quarantined (defense ≠ selection).
    assert!(
        poll_entry(
            &probe, &rx, probe_id, registry_dst_id, &reverse_hash, 5000,
            |e| e.quarantine.is_none()
                && e.reputation.as_ref().is_some_and(|r| r.promotion_verifies(&reverse_hash, &RealmId::new(REALM), &Ed25519Verifier)),
            scaled(Duration::from_secs(3)),
        ),
        "M12: the promoted reverse-daemon is spared — defense quarantines the hostile, selection keeps the fit"
    );

    k.shutdown_all(Deadline::from_millis(1500));
}
