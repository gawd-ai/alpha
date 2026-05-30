//! **Loop 2 (author → select → promote), in-process.**
//!
//! Two properties, no transport (selection is a node-local concern; cross-Realm reputation
//! is the federator's job, exercised elsewhere):
//!
//! 1. `fitness_promotion_local` — the **real** Loop-2 chain end-to-end: a watched creature handles
//!    envelopes → the kernel publishes its fitness on [`Topic::FITNESS`] → a *passive* relay
//!    forwards those events to the `fitness-selector` (the selector must NOT subscribe to FITNESS
//!    itself — it would feed on its own events; see the creature's module docs) → on `Tick` the
//!    selector scores by the injected `SuccessRateScorer`, signs the promotion, and writes
//!    [`RegistryOp::AttestFitness`] onto the registry. We then read the registry back and prove the
//!    stored score carries a signature that **verifies** for that entry (heredity).
//!
//! 2. `prefer_promoted_is_a_policy_choice_not_a_substrate_gate` — the **T7** contrast: the same
//!    un-promoted manifest is *admitted* by `AllowAll` and *refused* by `PreferPromotedPolicy`, and
//!    a verified promotion is admitted by the latter. Selection pressure lives in the injected
//!    policy, never in the fabric.

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, Deadline, Dispatch, Envelope, InboxReceiver, Outcome, RealmId,
    Role, StubSigner, Topic,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use fitness_selector::{FitnessSelector, SelectorConfig, SelectorMsg};
use policy_prefer_promoted::PreferPromotedPolicy;
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply, ReputationScore};
use sanctum::{Admission, Kernel, KernelError, Policy};
use scorer_success_rate::SuccessRateScorer;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest, Verifier};

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

/// A trivial responder: replies to nothing, returns `Outcome::none()`. Every handle is still
/// counted "useful" by the kernel (`!dispatches.is_empty() || budget_signal.is_none()` → true with
/// no budget signal), so each envelope it handles yields a `Fitness { ok: true }` on the topic.
struct Pinger;
impl Creature for Pinger {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

fn recv_selector_reply<F: Fn(&SelectorMsg) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<SelectorMsg> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env)
                if env.header.corr == Some(corr)
                    && env.header.schema == fitness_selector::SCHEMA =>
            {
                if let Ok(msg) = SelectorMsg::parse(&env.payload) {
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
// fitness_promotion_local — the real Loop-2 chain
// =================================================================================================

#[test]
fn fitness_promotion_local_real_signal_drives_a_signed_promotion() {
    let abode = Ed25519KeyMaterial::from_seed([0xA9u8; 32]).unwrap();
    let abode_pub = abode.public_hex().to_string();
    let node_key = Ed25519KeyMaterial::from_seed([0xB9u8; 32]).unwrap();

    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m11-local")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        128,
    );

    // Registry pre-seeded with the entry the target's promotion will land on. (An in-process target
    // has no real artifact bytes; the artifact_hash is just the registry key the operator knows it
    // by — exactly what the watch map records.) Seed BEFORE moving it into the kernel.
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

    // The selector: success-rate criterion, promote at >= 0.5, sign with the Abode key.
    let selector = FitnessSelector::new(SelectorConfig {
        self_realm: realm.clone(),
        local_registry: registry_id,
        abode_key: abode.clone(),
        threshold: 0.5,
        scorer: Box::new(SuccessRateScorer),
    });
    let selector_id = k
        .load_instance(signed_boot_manifest("fitness-selector", &node_key), Box::new(selector))
        .expect("selector admits");
    k.bind_role(Role::new(Role::FITNESS_SELECTOR), selector_id);

    // The PASSIVE relay: a bare endpoint subscribed to FITNESS. No drain thread → it generates no
    // fitness of its own → no feedback. It forwards only the *watched* target's events to the
    // selector (re-addressed as a "fitness"-schema Creature envelope). This is the operator wiring
    // the selector's docs prescribe.
    let (_relay_id, relay_bus, relay_rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::FITNESS), _relay_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    // ----- Watch the target ---------------------------------------------------------------------
    let watch_corr = 1u64;
    probe_bus
        .send(
            Dispatch::to(
                Address::Creature(selector_id),
                SelectorMsg::Watch {
                    module: target_id.0,
                    realm: realm.clone(),
                    artifact_hash: target_hash.clone(),
                }
                .to_bytes(),
            )
            .with_schema(fitness_selector::SCHEMA)
            .with_corr(watch_corr)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Watch sends");
    recv_selector_reply(
        &probe_rx,
        watch_corr,
        |m| matches!(m, SelectorMsg::Watching { module } if *module == target_id.0),
        scaled(Duration::from_secs(3)),
    )
    .expect("Watching ack");

    // ----- Drive the target so the kernel emits real fitness events -----------------------------
    const PINGS: usize = 5;
    for i in 0..PINGS {
        probe_bus
            .send(Dispatch::to(Address::Creature(target_id), format!("ping-{i}").into_bytes()))
            .expect("ping sends");
    }

    // Relay loop (the passive operator glue): forward the target's fitness events to the selector.
    // Collect until we've forwarded at least 3 (enough to make success_rate stable at 1.0); a
    // generous deadline keeps it non-flaky without requiring all PINGS.
    let mut forwarded = 0usize;
    let deadline = std::time::Instant::now() + scaled(Duration::from_secs(5));
    while forwarded < 3 && std::time::Instant::now() < deadline {
        match relay_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(env) if env.header.schema == fitness_selector::FITNESS_EVENT_SCHEMA => {
                // Only forward the watched target's events (never the selector's own — that would be
                // the feedback the relay exists to prevent).
                let v: serde_json::Value = match serde_json::from_slice(&env.payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("module").and_then(|m| m.as_u64()) == Some(target_id.0) {
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
    // Require the full target (matching the loop's goal): proving the *multi-event* accumulation
    // path, not just a single lucky event. In-process delivery of PINGS=5 events is near-instant, so
    // collecting 3 within the 5s (scaled) deadline is not a flake risk — but it is a stronger claim
    // than `>= 1` (which a 1-of-1 success rate would satisfy without exercising accumulation).
    assert!(
        forwarded >= 3,
        "the relay must forward the multiple fitness events the kernel emits for the target (got {forwarded})"
    );

    // ----- Tick → promotion ---------------------------------------------------------------------
    let tick_corr = 2u64;
    probe_bus
        .send(
            Dispatch::to(Address::Creature(selector_id), SelectorMsg::Tick.to_bytes())
                .with_schema(fitness_selector::SCHEMA)
                .with_corr(tick_corr)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Tick sends");
    let ticked = recv_selector_reply(
        &probe_rx,
        tick_corr,
        |m| matches!(m, SelectorMsg::Ticked { .. }),
        scaled(Duration::from_secs(3)),
    )
    .expect("Ticked reply");
    match ticked {
        SelectorMsg::Ticked { evaluated, promoted } => {
            assert_eq!(evaluated, 1, "the watched target was evaluated");
            assert_eq!(promoted, vec![target_id.0], "success_rate 1.0 ≥ 0.5 → promoted");
        }
        other => panic!("expected Ticked, got {other:?}"),
    }

    // ----- Read the registry back: the promotion is stored + its signature verifies -------------
    // Poll ListEntries until the reputation appears (the AttestFitness was dispatched in the same
    // Outcome as Ticked, so it's already in the registry's FIFO inbox ahead of this query — the
    // poll is belt-and-suspenders).
    let mut verified = false;
    let poll_deadline = std::time::Instant::now() + scaled(Duration::from_secs(3));
    let mut list_corr = 100u64;
    while !verified && std::time::Instant::now() < poll_deadline {
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
        // Read the matching registry reply.
        let got = {
            let d = std::time::Instant::now() + Duration::from_millis(500);
            let mut found = None;
            while std::time::Instant::now() < d {
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
                if let Some(rep) = &entry.reputation {
                    assert!(
                        (rep.score - 1.0).abs() < 1e-6,
                        "promoted at the observed success rate"
                    );
                    assert_eq!(rep.signed_by.as_deref(), Some(abode_pub.as_str()));
                    assert_eq!(rep.attesting_realm, Some(realm.clone()));
                    assert!(
                        rep.promotion_verifies(&target_hash, &realm, &Ed25519Verifier),
                        "the stored promotion signature verifies for its entry"
                    );
                    verified = true;
                }
            }
        }
        if !verified {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert!(verified, "the signed promotion must land on the registry and verify");

    k.shutdown_all(Deadline::from_millis(1500));
}

// =================================================================================================
// prefer_promoted — selection pressure is a policy choice (T7)
// =================================================================================================

/// A permissive policy local to this test (the substrate ships none as a default).
struct AllowAll;
impl Policy for AllowAll {
    fn admit(&self, _m: &Manifest, _e: &Admission) -> Result<(), String> {
        Ok(())
    }
}

fn candidate_manifest(hash: &str, realm: &RealmId) -> Manifest {
    let mut m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.build_hash = Some(hash.to_string());
    m.provenance.realm = Some(realm.clone());
    m
}

#[test]
fn prefer_promoted_is_a_policy_choice_not_a_substrate_gate() {
    let selector_key = Ed25519KeyMaterial::from_seed([0x5Au8; 32]).unwrap();
    let realm = RealmId::new("crew");

    // A shared registry: one promoted entry (signed), one merely-published (un-promoted).
    let registry = Arc::new(RegistryMem::new());

    let promoted_bytes = b"promoted-candidate-bytes".to_vec();
    let promoted_hash = registry.publish_in(
        realm.clone(),
        Manifest::new("promoted", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        promoted_bytes.clone(),
    );
    let score = 0.95f32;
    let sig = selector_key.sign(&ReputationScore::promotion_payload(
        &promoted_hash,
        &realm,
        score,
        Some(&realm),
    ));
    registry.attest_fitness(
        &realm,
        &promoted_hash,
        ReputationScore {
            score,
            attesting_realm: Some(realm.clone()),
            signed_by: Some(selector_key.public_hex().to_string()),
            signature: Some(sig),
        },
    );

    let unpromoted_bytes = b"unpromoted-candidate-bytes".to_vec();
    let unpromoted_hash = registry.publish_in(
        realm.clone(),
        Manifest::new("unpromoted", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        unpromoted_bytes.clone(),
    );

    // ----- With PreferPromotedPolicy: promoted passes the gate, un-promoted is refused ----------
    let strict = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m11-prefer")),
        Arc::new(Ed25519Verifier),
        Arc::new(PreferPromotedPolicy::new(registry.clone(), 0.8)),
        64,
    );

    // The promoted candidate passes admission (the bogus bytes then fail to load as a real .so —
    // that's an Engine error, NOT an AdmissionRejected; the gate is what we assert on).
    let res = strict
        .load(candidate_manifest(&promoted_hash, &realm), Artifact::Bytes(promoted_bytes.clone()));
    assert!(
        !matches!(res, Err(KernelError::AdmissionRejected(_))),
        "a verified, at-threshold promotion must pass the prefer-promoted gate; got {res:?}"
    );

    // The un-promoted candidate is refused AT admission (policy errs before the engine runs).
    let res = strict.load(
        candidate_manifest(&unpromoted_hash, &realm),
        Artifact::Bytes(unpromoted_bytes.clone()),
    );
    assert!(
        matches!(res, Err(KernelError::AdmissionRejected(_))),
        "an un-promoted creature must be refused by prefer-promoted; got {res:?}"
    );

    // ----- With AllowAll: the SAME un-promoted manifest is admitted (T7) -------------------------
    // The substrate enforces no selection of its own — only the injected policy does.
    let permissive = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m11-allow")),
        Arc::new(Ed25519Verifier),
        Arc::new(AllowAll),
        64,
    );
    let res = permissive
        .load(candidate_manifest(&unpromoted_hash, &realm), Artifact::Bytes(unpromoted_bytes));
    assert!(
        !matches!(res, Err(KernelError::AdmissionRejected(_))),
        "with AllowAll bound, the un-promoted creature admits — selection is a policy choice, not a \
         substrate gate; got {res:?}"
    );

    // Sanity: the verifier-level contract the policy relies on (an independent check the stored
    // promotion really is verifiable, in case the policy path above passed for the wrong reason).
    let entry = registry.fetch_in(&realm, &promoted_hash).unwrap();
    let rep = entry.reputation.unwrap();
    let v: &dyn Verifier = &Ed25519Verifier;
    assert!(rep.promotion_verifies(&promoted_hash, &realm, v));

    strict.shutdown_all(Deadline::from_millis(500));
    permissive.shutdown_all(Deadline::from_millis(500));
}
