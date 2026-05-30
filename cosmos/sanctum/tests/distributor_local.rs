//! Single-Sanctum integration tests for `distributor-requirements`.
//!
//! Three tests, all single-Sanctum (no transport-tcp), all exercising the distributor keystone:
//!
//! - **`distributor_local_match`** — two creatures with distinct advertised cpu,
//!   `Intent{requires: cpu>=2}` routes to the matching one via the SEER `placement` topic consult.
//! - **`distributor_no_match`** — requirements no advertised embodiment satisfies →
//!   structured `NoProviderReply`, not a panic, not a silent drop.
//! - **`distributor_fan_out`** — multiple matches, distributor's [`PickModel::RoundRobin`]
//!   picks; tests assert *the substrate did not pick* — the choice is observable as the
//!   distributor's model cycling.
//! - **`distributor_consult_fires_for_n1_local`** (S4 mitigation) — even with one local
//!   advertiser, the SEER consult traffic is on the bus; cross-node placement doesn't
//!   retrofit a synchronous local code path.
//!
//! The cross-node test lives in `distributor_cross_node.rs` and uses static ports 19_920/19_921.

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Intent, NodeId, Outcome, Role, StubSigner, StubVerifier,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use distributor_requirements::{
    Distributor, NoProviderReason, NoProviderReply, PickModel, SCHEMA_NO_PROVIDER,
};
use embodiment_advertiser::{EmbodimentAdvertiser, OfferEntry};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use seer::{topics::placement, SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use sigil::{Backend, Capabilities, Manifest};

// ----- shared scaffolding -----------------------------------------------------------------------

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m7-test")),
        Arc::new(StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn boot_manifest(name: &str) -> Manifest {
    // DevPolicy admits any well-formed manifest; no signing needed.
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

const NODE_SELF: &str = "node-self";

/// A tiny tagged echo: replies with `tag + payload reversed`. Lets a test tell which target
/// answered by reading the prefix.
struct TaggedEcho {
    tag: u8,
}

impl TaggedEcho {
    fn new(tag: u8) -> Self {
        TaggedEcho { tag }
    }
}

impl Creature for TaggedEcho {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let mut reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        let mut out = vec![self.tag];
        out.append(&mut reversed);
        Outcome::reply(&env, out)
    }
}

/// Wait for an envelope matching `corr` and `schema_pred`. Drops anything else (proprio, late
/// SEER traffic, etc.).
fn recv_match<F: Fn(&Envelope) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    schema_pred: F,
    budget: Duration,
) -> Option<Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && schema_pred(&env) => return Some(env),
            _ => continue,
        }
    }
    None
}

/// Reusable single-Sanctum topology builder. Returns the kernel + ids + the probe's bus/rx.
struct LocalSetup {
    kernel: Arc<Kernel>,
    distributor_id: CreatureId,
    advertiser_id: CreatureId,
    /// Tagged-echo target ids in offer order. Held so the kernel doesn't unload them mid-test, even
    /// when individual tests don't read it (the dead_code allow is intentional).
    #[allow(dead_code)]
    echo_ids: Vec<CreatureId>,
    probe_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_local(offers: Vec<(u32, &'static str)>, model: PickModel) -> LocalSetup {
    // offers: Vec<(cpu, tag_for_echo_payload)>. Each becomes a TaggedEcho + an OfferEntry whose
    // embodiment's `cpu` matches `cpu`. The `tag` is the byte the echo prepends — lets the test
    // identify which target answered.
    let k = kernel();

    // 1) Load N tagged echo creatures, one per offer.
    let mut echo_ids = Vec::with_capacity(offers.len());
    for (cpu, tag) in &offers {
        let echo = TaggedEcho::new(tag.as_bytes()[0]);
        let id = k
            .load_instance(boot_manifest(&format!("echo-cpu-{cpu}")), Box::new(echo))
            .expect("echo loads");
        echo_ids.push(id);
    }

    // 2) Load the advertiser with one OfferEntry per echo, each tagging its declared cpu.
    let offer_entries: Vec<OfferEntry> = offers
        .iter()
        .zip(echo_ids.iter())
        .map(|((cpu, _tag), id)| OfferEntry {
            creature_id: *id,
            embodiment: placement::Embodiment {
                cpu: *cpu,
                mem_bytes: 4 * 1024 * 1024 * 1024,
                accelerators: vec![],
                jurisdiction: Some("us".into()),
                connectivity: Some("wired".into()),
                sensors: vec![],
            },
        })
        .collect();
    let advertiser = EmbodimentAdvertiser::new(NodeId(NODE_SELF.into()), offer_entries);
    let advertiser_id = k
        .load_instance(boot_manifest("embodiment-advertiser"), Box::new(advertiser))
        .expect("advertiser loads");

    // 3) Load the distributor, bound to Intent.
    let distributor = Distributor::new(
        NodeId(NODE_SELF.into()),
        vec![advertiser_id],
        vec![],
        model,
        10_000, // consult corr seed — distinct from test-chosen Intent corrs
        1024,   // max_pending — generous; integration tests don't exercise eviction
    );
    let distributor_id = k
        .load_instance(boot_manifest("distributor-requirements"), Box::new(distributor))
        .expect("distributor loads");
    k.bind_role(Role::new(Role::DISTRIBUTOR), distributor_id);

    // 4) Probe endpoint.
    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    LocalSetup { kernel: k, distributor_id, advertiser_id, echo_ids, probe_id, probe_bus, probe_rx }
}

/// Count journal entries where envelopes flowed *to* the advertiser (the SEER consult traffic).
/// S4 mitigation lives or dies by this count being non-zero after every Intent.
fn placement_consult_envelopes_seen(
    k: &Kernel,
    advertiser_id: CreatureId,
    distributor_id: CreatureId,
) -> usize {
    k.router()
        .journal_snapshot()
        .iter()
        .filter(|e| {
            matches!(&e.to, Address::Creature(id) if *id == advertiser_id)
                && matches!(&e.from, Address::Creature(id) if *id == distributor_id)
        })
        .count()
}

// ----- test #2 — local match --------------------------------------------------------------------

#[test]
fn distributor_local_match() {
    // Two echo creatures: one advertised at cpu:1, one at cpu:2. Intent requires cpu>=2. The
    // distributor consults via SEER `placement`; the advertiser answers with only the cpu:2 offer;
    // the distributor routes the Intent to the cpu:2 echo. The reply comes back to the probe.
    let s = boot_local(vec![(1, "1"), (2, "2")], PickModel::FirstFit);

    s.probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent {
                    outcome: "reverse-string".into(),
                    requirements: vec!["cpu >= 2".into()],
                }),
                b"abcd".to_vec(),
            )
            .with_reply_to(Address::Creature(s.probe_id))
            .with_corr(1),
        )
        .expect("Intent admits + routes to bound distributor");

    let reply = recv_match(&s.probe_rx, 1, |e| e.payload.starts_with(b"2"), Duration::from_secs(2))
        .expect("reply from the cpu:2 echo arrives");
    // Tagged echo: prepends its tag byte to the reversed payload.
    assert_eq!(reply.payload, b"2dcba", "cpu>=2 routed to the cpu:2 echo, which reverses");
    // S4: the consult must have flowed (envelopes from distributor to advertiser observable).
    assert!(
        placement_consult_envelopes_seen(&s.kernel, s.advertiser_id, s.distributor_id) >= 1,
        "S4: placement consult must fire — no SEER traffic observed on bus"
    );

    s.kernel.shutdown_all(Deadline::from_millis(500));
}

// ----- test #4 — no match -----------------------------------------------------------------------

#[test]
fn distributor_no_match() {
    // One advertised cpu:2 offer. Intent demands cpu>=16. Advertiser answers with empty matches;
    // distributor emits a NoProviderReply to the originator's reply_to. **Not a panic, not a
    // silent drop** — the structured-reply contract is what an orchestrator binds to.
    let s = boot_local(vec![(2, "2")], PickModel::FirstFit);

    s.probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent {
                    outcome: "reverse-string".into(),
                    requirements: vec!["cpu >= 16".into()],
                }),
                b"abcd".to_vec(),
            )
            .with_reply_to(Address::Creature(s.probe_id))
            .with_corr(2),
        )
        .expect("Intent routes to distributor");

    let reply = recv_match(
        &s.probe_rx,
        2,
        |e| e.header.schema == SCHEMA_NO_PROVIDER,
        Duration::from_secs(2),
    )
    .expect("NoProvider reply arrives");

    let parsed = NoProviderReply::parse(&reply.payload).expect("NoProviderReply parses");
    assert_eq!(parsed.outcome, "reverse-string");
    assert_eq!(parsed.requirements, vec!["cpu >= 16"]);
    assert_eq!(parsed.advertisers_consulted, 1);
    assert_eq!(parsed.advertisers_answered, 1);
    assert_eq!(
        parsed.reason,
        NoProviderReason::EveryAdvertiserEmpty,
        "advertiser answered empty → EveryAdvertiserEmpty variant"
    );

    s.kernel.shutdown_all(Deadline::from_millis(500));
}

// ----- test #5 — fan-out (the substrate did not pick) -----------------------------------------

#[test]
fn distributor_fan_out() {
    // Three offers, all match `cpu >= 1`. PickModel::RoundRobin → three back-to-back Intents
    // route to three different targets in cursor order. The substrate itself didn't pick — the
    // observable selection is the distributor's PickModel cycling.
    let s = boot_local(vec![(4, "A"), (4, "B"), (4, "C")], PickModel::RoundRobin);

    // Drive three Intents, collect which tag came back each time.
    let mut tags_in_order: Vec<u8> = Vec::new();
    for (i, corr) in [3u64, 4, 5].iter().enumerate() {
        s.probe_bus
            .send(
                Dispatch::to(
                    Address::Intent(Intent {
                        outcome: "reverse-string".into(),
                        requirements: vec!["cpu >= 1".into()],
                    }),
                    format!("payload-{i}").into_bytes(),
                )
                .with_reply_to(Address::Creature(s.probe_id))
                .with_corr(*corr),
            )
            .expect("Intent routes");
        // Echo's payload format: tag-byte + reversed-original. The first byte is the tag.
        let reply =
            recv_match(&s.probe_rx, *corr, |e| !e.payload.is_empty(), Duration::from_secs(2))
                .expect("echo replies");
        tags_in_order.push(reply.payload[0]);
    }

    // Three different targets, in deterministic round-robin order (the distributor's model picked,
    // not the substrate). The advertiser tagged offers in insertion order (A=tag 'A', B='B',
    // C='C'); RoundRobin cursor starts at 0 → A, B, C.
    assert_eq!(
        tags_in_order,
        vec![b'A', b'B', b'C'],
        "RoundRobin cycles through advertised offers — the distributor's model, not the substrate, made the choice"
    );

    // Three Intents = three consult round-trips = at least three SEER queries to the advertiser.
    assert!(
        placement_consult_envelopes_seen(&s.kernel, s.advertiser_id, s.distributor_id) >= 3,
        "three Intents must produce three SEER consults"
    );

    s.kernel.shutdown_all(Deadline::from_millis(500));
}

// ----- test #9 — S4 mitigation: consult fires even for N=1 local --------------------------------

#[test]
fn distributor_consult_fires_for_n1_local() {
    // One local advertiser, one offer that matches. The SEER consult must still fire — the wire
    // shape doesn't degrade to a synchronous "local optimization" path. Cross-node placement
    // composes the same shape across nodes without retrofitting the local case.
    let s = boot_local(vec![(8, "X")], PickModel::FirstFit);

    s.probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent {
                    outcome: "reverse-string".into(),
                    requirements: vec!["cpu >= 4".into()],
                }),
                b"abc".to_vec(),
            )
            .with_reply_to(Address::Creature(s.probe_id))
            .with_corr(11),
        )
        .expect("Intent routes");
    let reply =
        recv_match(&s.probe_rx, 11, |e| e.payload.starts_with(b"X"), Duration::from_secs(2))
            .expect("echo replies");
    assert_eq!(reply.payload, b"Xcba");

    // The S4 mitigation invariant, asserted directly on the consult corr rather than on a fragile
    // before/after journal-count delta: at least one SEER envelope flowed from
    // distributor → advertiser carrying the consult-seed corr (>=10_000) — proof the consult fired
    // on the bus even though there was only one possible answer. Pinning on the corr range is
    // strictly stronger than "the count went up by one": it identifies the envelope as *consult*
    // traffic (an unrelated distributor→advertiser envelope, were one ever to exist, wouldn't carry
    // a >=10_000 corr), so there's nothing left for the delta check to add. Cross-node placement
    // composes onto this same consult shape without rewriting the local path.
    let saw_consult_corr = s.kernel.router().journal_snapshot().iter().any(|e| {
        matches!(&e.from, Address::Creature(id) if *id == s.distributor_id)
            && matches!(&e.to, Address::Creature(id) if *id == s.advertiser_id)
            && e.corr.is_some_and(|c| c >= 10_000)
    });
    assert!(
        saw_consult_corr,
        "S4: a consult envelope (corr >=10_000) must flow distributor → advertiser even for N=1 local"
    );

    s.kernel.shutdown_all(Deadline::from_millis(500));
}

// ----- composability sanity: round-robin reference creature still works in isolation ------------

#[test]
fn round_robin_distributor_reference_still_works_isolated() {
    // `cosmos/creatures/prototypes/distributors/distributor-roundrobin` (the minimal reference) is
    // preserved and still works in isolation, proving IoC composability — two distributor creatures
    // can coexist; the operator picks one via `bind_role`. This test loads the reference distributor (not the
    // requirements-matching one) and proves it still routes Intents.
    use distributor_roundrobin::RoundRobinDistributor;

    let k = kernel();
    let echo = TaggedEcho::new(b'r');
    let echo_id = k.load_instance(boot_manifest("echo-r"), Box::new(echo)).expect("echo loads");

    let distributor = RoundRobinDistributor::with_targets(vec![echo_id]);
    let distributor_id = k
        .load_instance(boot_manifest("distributor-roundrobin"), Box::new(distributor))
        .expect("round-robin distributor loads");
    k.bind_role(Role::new(Role::DISTRIBUTOR), distributor_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent { outcome: "x".into(), requirements: vec![] }),
                b"hi".to_vec(),
            )
            .with_reply_to(Address::Creature(probe_id))
            .with_corr(42),
        )
        .expect("Intent routes to round-robin distributor");
    let reply = recv_match(&probe_rx, 42, |e| !e.payload.is_empty(), Duration::from_secs(1))
        .expect("reply arrives");
    assert_eq!(reply.payload, b"rih", "round-robin → echo → reversed with tag");

    k.shutdown_all(Deadline::from_millis(500));
}

// ----- silence the unused-import warnings the test fixtures don't otherwise touch --------------
//
// `SeerEnvelope`, `SeerKind`, `SeerTopic`, `SEER_SCHEMA` are pulled into scope for any test that
// wants to construct or assert on SEER envelopes directly (none currently — the substrate routes
// them and the test reads them via NoProviderReply / the journal). Keeping the imports so a
// future test that asserts on the consult body structure has them ready.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = SEER_SCHEMA;
    let _ = SeerTopic::Placement;
    let _ = SeerKind::Progress { stage: "x".into(), fraction: None, note: None };
    let _ = SeerEnvelope::progress(SeerTopic::Placement, 0, "x", None, None);
}
