//! **Loop 4 (Defend / immune system), in-process.**
//!
//! Three properties, no transport (cross-Realm quarantine propagation is the federator's path,
//! exercised there; the immune-response is the *decider* — what to quarantine and when — which is a node-local
//! concern plus a trust-gated inbound seam):
//!
//! 1. `immune_response_local_hard_budget_breach_quarantines_a_watched_creature` — the **real**
//!    Loop-4 sensing chain: the immune-response subscribes to [`Topic::PROPRIOCEPTION`] (the dual of
//!    the fitness-selector — proprioception is *not* per-handle, so the direct subscription is safe), watches a
//!    creature, and when a `hard` budget signal for that creature arrives on the topic it writes a
//!    [`RegistryOp::MarkQuarantine`] onto the registry. We inject the budget signal as the kernel's
//!    own [`BudgetSignalEvent`] bytes (the test stands in for the engine that would emit it on a real
//!    breach — the same wire), then read the registry back and prove the entry is quarantined.
//!
//! 2. `defense_overrides_selection` — the headline **selection↔defense interaction** through the real
//!    admission gate: an entry that is *both* a verified promotion *and* quarantined is
//!    **refused** by `QuarantineAwarePolicy` (quarantine first) and **admitted** by
//!    `PreferPromotedPolicy` (which never reads the quarantine slot). Same bytes, same registry,
//!    opposite verdict — defense and selection are different operator stances, neither the fabric's.
//!
//! 3. `quarantine_is_reversible_t5` — a re-publish of the same `(realm, artifact_hash)` clears the
//!    quarantine marker; the quarantine-aware policy then admits the re-earned promotion (T5).

use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, BudgetVector, Deadline, Dispatch, InboxReceiver, NodeId, RealmId, Role, StubSigner,
    Topic,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use immune_response::{ImmuneConfig, ImmuneMsg, ImmuneResponse};
use policy_prefer_promoted::PreferPromotedPolicy;
use policy_quarantine_aware::QuarantineAwarePolicy;
use policy_quarantine_trust_all::TrustAllQuarantine;
use policy_signed::SignedPolicy;
use registry_mem::{QuarantineNotice, RegistryMem, RegistryOp, RegistryReply, ReputationScore};
use sanctum::{BudgetSignalEvent, Kernel, KernelError};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

// ----- scaffolding ----------------------------------------------------------------------------

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

/// A trivial responder — exists only to be watched (the immune-response acts on the *kernel's*
/// sense of it, not on anything it returns).
struct Pinger;
impl aether::Creature for Pinger {
    fn bind(&mut self, _ctx: aether::CreatureCtx) {}
    fn handle(&mut self, _env: aether::Envelope) -> aether::Outcome {
        aether::Outcome::none()
    }
}

fn recv_immune_reply<F: Fn(&ImmuneMsg) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<ImmuneMsg> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env)
                if env.header.corr == Some(corr)
                    && env.header.schema == immune_response::SCHEMA =>
            {
                if let Ok(msg) = ImmuneMsg::parse(&env.payload) {
                    if pred(&msg) {
                        return Some(msg);
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

// =================================================================================================
// (1) the real Loop-4 sensing chain
// =================================================================================================

#[test]
fn immune_response_local_hard_budget_breach_quarantines_a_watched_creature() {
    let node_key = Ed25519KeyMaterial::from_seed([0xB9u8; 32]).unwrap();

    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m12-local")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        128,
    );

    // Registry pre-seeded with the entry the target's quarantine will land on (the in-process target
    // has no real artifact bytes; the artifact_hash is the registry key the operator knows it by —
    // exactly what the watch map records). Seed BEFORE moving it into the kernel.
    let realm = RealmId::new("crew");
    let registry = RegistryMem::new();
    let target_hash = registry.publish_in(
        realm.clone(),
        Manifest::new("target-creature", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        b"target-artifact-bytes".to_vec(),
    );
    let registry_id = k
        .load_instance(signed_boot_manifest("registry", &node_key), Box::new(registry))
        .expect("registry admits");

    // The watched creature.
    let target_id = k
        .load_instance(signed_boot_manifest("target", &node_key), Box::new(Pinger))
        .expect("target admits");

    // The immune-response: trust-all (irrelevant to a local trigger), no propagation, writing to
    // the local registry.
    let immune = ImmuneResponse::new(ImmuneConfig {
        self_node: NodeId("node-A".into()),
        local_registry: registry_id,
        trust: Box::new(TrustAllQuarantine),
        propagation: None,
    });
    let immune_id = k
        .load_instance(signed_boot_manifest("immune-response", &node_key), Box::new(immune))
        .expect("immune-response admits");
    k.bind_role(Role::new(Role::IMMUNE_RESPONSE), immune_id);
    // The real Loop-4 sensing wiring: subscribe to PROPRIOCEPTION. SAFE — proprioception is
    // lifecycle + budget, never per-handle, so handling one never produces another (the dual of
    // the fitness-selector's anti-feedback rule; see the immune-response module docs).
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), immune_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    // ----- Watch the target ---------------------------------------------------------------------
    let watch_corr = 1u64;
    probe_bus
        .send(
            Dispatch::to(
                Address::Creature(immune_id),
                ImmuneMsg::Watch {
                    module: target_id.0,
                    realm: realm.clone(),
                    artifact_hash: target_hash.clone(),
                }
                .to_bytes(),
            )
            .with_schema(immune_response::SCHEMA)
            .with_corr(watch_corr)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Watch sends");
    recv_immune_reply(
        &probe_rx,
        watch_corr,
        |m| matches!(m, ImmuneMsg::Watching { module } if *module == target_id.0),
        scaled(Duration::from_secs(3)),
    )
    .expect("Watching ack");

    // ----- Inject a hard budget signal for the target on the PROPRIOCEPTION topic ----------------
    // The test stands in for the engine that would emit this on a real fuel/mem/wall breach — same
    // wire (`sanctum::BudgetSignalEvent`, schema "budget_signal", on the PROPRIOCEPTION topic). The
    // kernel fans it out to every PROPRIOCEPTION subscriber, including the immune-response.
    let signal = BudgetSignalEvent {
        creature: target_id.0,
        level: "hard".into(),
        kind: "fuel".into(),
        vector: BudgetVector {
            consumed: 10_000,
            limit: 5_000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 0,
            envelopes_since_load: 3,
        },
    };
    probe_bus
        .send(
            Dispatch::to(
                Address::Topic(Topic::new(Topic::PROPRIOCEPTION)),
                serde_json::to_vec(&signal).unwrap(),
            )
            .with_schema("budget_signal"),
        )
        .expect("budget signal publishes");

    // ----- Read the registry back: the target is quarantined ------------------------------------
    let mut quarantined = false;
    let poll_deadline = Instant::now() + scaled(Duration::from_secs(4));
    let mut list_corr = 100u64;
    while !quarantined && Instant::now() < poll_deadline {
        list_corr += 1;
        probe_bus
            .send(
                Dispatch::to(
                    Address::Creature(registry_id),
                    serde_json::to_vec(&RegistryOp::ListEntries { realm: Some(realm.clone()) })
                        .unwrap(),
                )
                .with_schema("registry.op")
                .with_corr(list_corr)
                .with_reply_to(Address::Creature(probe_id)),
            )
            .expect("ListEntries sends");
        let got = {
            let d = Instant::now() + Duration::from_millis(500);
            let mut found = None;
            while Instant::now() < d {
                match probe_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(env) if env.header.corr == Some(list_corr) => {
                        found = serde_json::from_slice::<RegistryReply>(&env.payload).ok();
                        break;
                    }
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
            found
        };
        if let Some(RegistryReply::Entries { entries }) = got {
            if let Some(entry) = entries.iter().find(|e| e.artifact_hash == target_hash) {
                if let Some(q) = &entry.quarantine {
                    assert!(q.reason.contains("hard budget breach"), "reason: {}", q.reason);
                    assert!(q.reason.contains("fuel"), "reason names the dimension: {}", q.reason);
                    assert_eq!(q.attesting_peers, vec!["node-A".to_string()], "flagged by us");
                    quarantined = true;
                }
            }
        }
        if !quarantined {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert!(quarantined, "the watched creature's hard breach must quarantine it on the registry");

    k.shutdown_all(Deadline::from_millis(1500));
}

// =================================================================================================
// (2) defense overrides selection — the headline selection<->defense interaction
// =================================================================================================

fn candidate_manifest(hash: &str, realm: &RealmId) -> Manifest {
    let mut m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.build_hash = Some(hash.to_string());
    m.provenance.realm = Some(realm.clone());
    m
}

/// Admission evidence the kernel would hand a policy — irrelevant to the registry-consulting
/// quarantine-aware / prefer-promoted policies (they read the registry, not the evidence).
fn admission_evidence() -> sanctum::Admission {
    sanctum::Admission {
        signature_present: true,
        signature_valid: true,
        content_address_declared: None,
        content_address_matches: None,
        artifact_hash_declared: true,
        artifact_hash_matches: Some(true),
        had_artifact: true,
    }
}

/// Seed a shared registry with one entry that is BOTH a verified promotion AND quarantined.
/// Returns (registry, hash, realm, bytes).
fn seed_promoted_and_quarantined() -> (Arc<RegistryMem>, String, RealmId, Vec<u8>) {
    let registry = Arc::new(RegistryMem::new());
    let realm = RealmId::new("crew");
    let selector_key = Ed25519KeyMaterial::from_seed([0x5Au8; 32]).unwrap();
    let bytes = b"promoted-and-quarantined-bytes".to_vec();
    let hash = registry.publish_in(
        realm.clone(),
        Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        bytes.clone(),
    );
    // A verified promotion.
    let score = 0.95f32;
    let sig =
        selector_key.sign(&ReputationScore::promotion_payload(&hash, &realm, score, Some(&realm)));
    registry.attest_fitness(
        &realm,
        &hash,
        ReputationScore {
            score,
            attesting_realm: Some(realm.clone()),
            signed_by: Some(selector_key.public_hex().to_string()),
            signature: Some(sig),
        },
    );
    // …and a quarantine marker (as the immune-response would have written).
    registry.mark_quarantine(
        &realm,
        &hash,
        QuarantineNotice {
            reason: "hard budget breach (fuel)".into(),
            attesting_peers: vec!["node-A".into()],
        },
    );
    (registry, hash, realm, bytes)
}

#[test]
fn defense_overrides_selection() {
    use sanctum::Policy;
    let (registry, hash, realm, bytes) = seed_promoted_and_quarantined();
    let ev = admission_evidence();

    // ----- The crisp contrast: SAME entry, OPPOSITE verdict, asserted DIRECTLY on each policy. ---
    // Direct `admit()` is the unambiguous proof of the headline: the kernel-load assertions below
    // route the REJECT side through the real gate, but the ADMIT side through `Kernel::load` would
    // pass for the wrong reason (the bogus `Artifact::Bytes` fails to `dlopen` *after* admission, so
    // a no-op policy would satisfy `!AdmissionRejected` too — the admit half is independently proven).
    // So we assert the verdict itself, not "the kernel didn't reject at the admission stage".
    assert!(
        QuarantineAwarePolicy::new(registry.clone(), 0.8)
            .admit(&candidate_manifest(&hash, &realm), &ev)
            .is_err(),
        "quarantine-aware REJECTS the promoted-but-quarantined entry (defense first)"
    );
    assert!(
        PreferPromotedPolicy::new(registry.clone(), 0.8)
            .admit(&candidate_manifest(&hash, &realm), &ev)
            .is_ok(),
        "prefer-promoted ADMITS the same entry (it never reads the quarantine slot) — defense and \
         selection are different policy stances, not substrate gates"
    );

    // ----- Through the real admission gate: defense REJECTS at admission (before the engine). -----
    let defended = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m12-defended")),
        Arc::new(Ed25519Verifier),
        Arc::new(QuarantineAwarePolicy::new(registry.clone(), 0.8)),
        64,
    );
    let res = defended.load(candidate_manifest(&hash, &realm), Artifact::Bytes(bytes.clone()));
    assert!(
        matches!(res, Err(KernelError::AdmissionRejected(_))),
        "a quarantined creature must be refused by quarantine-aware even though it is promoted; got {res:?}"
    );

    // ----- The prefer-promoted gate is LIVE and DISCRIMINATING, not a no-op. ----------------------
    // Seed an un-promoted, un-quarantined entry and prove the SAME `selecting` kernel rejects IT at
    // admission. This is the selection-side belt-and-suspenders (fitness_selection_local lines 383-391): it rules
    // out the "the gate passes everything" reading of the admit-side assertion above.
    let unpromoted_bytes = b"unpromoted-bytes".to_vec();
    let unpromoted_hash = registry.publish_in(
        realm.clone(),
        Manifest::new("unpromoted", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        unpromoted_bytes.clone(),
    );
    let selecting = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m12-selecting")),
        Arc::new(Ed25519Verifier),
        Arc::new(PreferPromotedPolicy::new(registry.clone(), 0.8)),
        64,
    );
    let res = selecting
        .load(candidate_manifest(&unpromoted_hash, &realm), Artifact::Bytes(unpromoted_bytes));
    assert!(
        matches!(res, Err(KernelError::AdmissionRejected(_))),
        "prefer-promoted REJECTS an un-promoted creature at admission — so the gate is live and \
         discriminating, and the admit of the promoted entry above is a real admission, not a no-op; got {res:?}"
    );

    defended.shutdown_all(Deadline::from_millis(500));
    selecting.shutdown_all(Deadline::from_millis(500));
}

// =================================================================================================
// (3) quarantine is reversible (T5)
// =================================================================================================

#[test]
fn quarantine_is_reversible_t5() {
    // A pure registry + policy property (no kernel needed): a re-publish of the same key clears the
    // quarantine marker, so the quarantine-aware policy admits the re-earned promotion.
    let (registry, hash, realm, bytes) = seed_promoted_and_quarantined();
    let policy = QuarantineAwarePolicy::new(registry.clone(), 0.8);
    let evidence = admission_evidence();

    use sanctum::Policy;
    assert!(
        policy.admit(&candidate_manifest(&hash, &realm), &evidence).is_err(),
        "quarantined → rejected"
    );

    // Re-publish the SAME bytes (clears both signals — T5), then re-earn the promotion.
    let hash2 = registry.publish_in(
        realm.clone(),
        Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        bytes,
    );
    assert_eq!(hash2, hash, "same bytes → same key");
    let selector_key = Ed25519KeyMaterial::from_seed([0x5Au8; 32]).unwrap();
    let score = 0.95f32;
    let sig =
        selector_key.sign(&ReputationScore::promotion_payload(&hash, &realm, score, Some(&realm)));
    registry.attest_fitness(
        &realm,
        &hash,
        ReputationScore {
            score,
            attesting_realm: Some(realm.clone()),
            signed_by: Some(selector_key.public_hex().to_string()),
            signature: Some(sig),
        },
    );
    assert!(
        policy.admit(&candidate_manifest(&hash, &realm), &evidence).is_ok(),
        "quarantine cleared by re-publish → admits (T5 reversibility)"
    );
}
