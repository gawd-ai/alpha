//! `distributor-requirements` — the keystone Distributor creature.
//!
//! `cosmos/creatures/prototypes/distributors/distributor-roundrobin` is the minimal reference —
//! proof the `Role::DISTRIBUTOR` socket works end-to-end with a deliberately simple model. This
//! creature is the requirements-aware one: it makes the third governing loop concrete.
//!
//! ## What it does
//!
//! Bound to `Role::DISTRIBUTOR`: every [`Intent`] envelope hits its inbox. On receipt:
//!
//! 1. Parse `Intent.requirements` as [`placement::Predicate`] strings (the minimal predicate language).
//!    A predicate that fails to parse is dropped silently — a single garbage predicate doesn't
//!    sink the whole placement; advertisers see the surviving subset.
//! 2. Build a `corr` for this placement consult — distinct from the Intent's own `corr`, which
//!    belongs to the *original* requester's reply tracking. The placement consult is its own
//!    fire-and-correlate thread.
//! 3. Emit a `SeerEnvelope::Query` on [`SeerTopic::Placement`] to **every** known advertiser
//!    (local + peer). The Query's `reply_to` is set to this distributor, so answers come back
//!    here regardless of how many hops they crossed.
//! 4. Park the Intent in a pending table keyed by the consult `corr`, tracking how many answers
//!    are still expected.
//! 5. As answers arrive (subsequent `handle()` calls): accumulate the offers, decrement the
//!    expected count. **When all expected answers have arrived** (or when the
//!    `PickModel::FirstFit` model fires early on the first match), reconcile: apply the
//!    [`PickModel`], route the Intent to the picked target, drop the pending entry. If no offer
//!    matched after every answer: emit a structured "no provider" reply to the Intent's
//!    `reply_to` (NOT a panic, NOT a silent drop — see [`NoProviderReply`]).
//!
//! ## Why the consult fires even for N=1 local
//!
//! If the placement creature decided locally without consultation, cross-node placement would
//! have to retrofit the consult pattern into placement code. Instead, the SEER consult *always*
//! fires, even when there's exactly one local advertiser. The wire traffic is proof — the
//! substrate isn't pretending consult-less placement is the path. Peer fan-out is added without
//! changing the placement code path.
//!
//! ## What this creature deliberately doesn't do
//!
//! - **It doesn't time out.** A `placement` `Query` carries no deadline by default (the body
//!   defines no field). If a peer never answers, the pending Intent stays parked. Time is
//!   injected policy: an operator who wants a deadline binds a watchdog creature that emits a
//!   `Steer{kind: "abort"}` on the placement corr after T ms, and the distributor honors it
//!   (deferred — see `on_steer`).
//! - **It doesn't disambiguate by cost.** The bundled [`PickModel`]s (FirstFit / RoundRobin) are
//!   intentionally crude. "Best-fit by cpu headroom," "least-loaded," "verifiable-die for fair
//!   randomization" are operator-injected models.
//! - **It doesn't bridge across realms.** Peer advertisers are addressed directly via
//!   `Address::Node(peer, advertiser_module_id)`. The realm-gateway lets a distributor say
//!   "ask everyone in the realm" without a hardcoded peer list.
//! - **It doesn't introspect the kernel.** Local advertisers, peer advertisers, and the model are
//!   all operator-supplied at construction. The distributor adds no kernel responsibility.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Intent, NodeId, Outcome,
};
use seer::{topics::placement, SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use serde::{Deserialize, Serialize};

/// Schema string for SEER (re-exported for orchestrator-side consumers). Same constant the
/// advertiser uses.
pub const SCHEMA_SEER: &str = SEER_SCHEMA;

/// Schema string for the distributor's terminal "no provider" reply when the placement consult
/// finds no match. Distinct from SEER — this isn't an in-conversation envelope, it's the closing
/// reply to the *Intent's* originator.
pub const SCHEMA_NO_PROVIDER: &str = "distributor.no_provider";

/// Structured reason for a [`NoProviderReply`] — an orchestrator dispatches on the variant, not
/// on a substring of free-form prose. Adding a variant is a one-line change here + a producing
/// site in [`Distributor`]; existing orchestrators that don't recognize a new variant fail to
/// deserialize loudly rather than misclassify silently.
///
/// Wire form is externally tagged on `"kind"` (snake_case), so the JSON looks like
/// `{"kind":"no_advertisers"}` / `{"kind":"every_advertiser_empty"}` / …
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NoProviderReason {
    /// The distributor had zero advertisers bound (no local, no peers). Operator misconfig — the
    /// consult never fanned out because there was nowhere to fan to.
    NoAdvertisers,
    /// Every advertiser answered, each with an empty match list. No offer in the substrate
    /// satisfies the Intent's requirements; the originator likely needs to relax them.
    EveryAdvertiserEmpty,
    /// A [`SeerEnvelope`] with `kind: Steer{kind: "abort"}` arrived on the consult `corr` while
    /// the distributor was awaiting answers; the pending consult was dropped.
    Aborted,
    /// The pending table was at [`Distributor`]'s `max_pending` capacity when a new Intent
    /// arrived; the oldest pending consult (by `consult_corr` allocation order — the distributor
    /// keeps no wall-clock) was evicted to make room. The evicted *originator* receives this
    /// reply; the new Intent proceeds normally. Without this, a flaky peer that never answers
    /// would leak pending entries monotonically.
    PendingEvicted,
    /// An Intent reached the distributor before its `bind()` ran (a kernel-lifecycle bug). Without
    /// `me` the distributor can't set the consult `reply_to` to itself, so it can't fan out; rather
    /// than panic on the missing bind (the fabric-integrity floor would catch that via unload, but
    /// the originator would then silently lose the work), it replies with this reason.
    NotReady,
}

/// The reply emitted to the Intent's `reply_to` when reconciliation finds no matching embodiment.
/// Structured (not a panic, not a silent drop) so the originator can present it, retry with
/// different requirements, or escalate to a richer model.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NoProviderReply {
    /// Echo of the Intent's outcome so the originator can match this reply to the request.
    pub outcome: String,
    /// Echo of the Intent's requirements for the same reason.
    pub requirements: Vec<String>,
    /// How many advertisers were consulted.
    pub advertisers_consulted: u32,
    /// How many advertisers answered (may be less than consulted if some are still pending — but
    /// the distributor only reconciles after all answers arrive, so this normally equals
    /// `advertisers_consulted`).
    pub advertisers_answered: u32,
    /// Structured reason — orchestrators dispatch on the variant.
    pub reason: NoProviderReason,
    /// Free-form details for the operator's audit log. Elides from the wire when `None`; never
    /// part of any wire contract beyond "human prose."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl NoProviderReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The distributor's reconciliation model. The operator picks one at construction; the substrate
/// supplies none. Adding a new model is a one-arm addition here + a `Distributor::reconcile`
/// match arm. Each model is **a strategy, not a contract** — richer ones
/// (best-fit-by-headroom, verifiable-die, weighted-vote) drop in without changing the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickModel {
    /// First offer that matches wins. Reconciliation fires as soon as *any* advertiser answers
    /// with a non-empty match list — the rest of the consult is allowed to complete (the
    /// distributor doesn't cancel late answers; they're dropped silently on receipt). This is the
    /// "race = order" Loop-3 primitive.
    FirstFit,
    /// Round-robin across the *flattened set* of matches across every advertiser's answer. Forces
    /// the distributor to wait for every expected answer before picking. The cycle counter is
    /// per-distributor (stateful), so re-issuing the same Intent walks through the matches in
    /// turn.
    RoundRobin,
}

/// Pending state for one in-flight placement consult — keyed by the consult `corr` in
/// [`Distributor::pending`].
#[derive(Debug)]
struct Pending {
    /// The Intent envelope as-received. Held so we can replay reply_to/from/corr/payload to the
    /// chosen target verbatim.
    intent_env: Envelope,
    /// How many advertisers we sent the Query to. Reconciliation fires when `answered == expected`
    /// (or, under [`PickModel::FirstFit`], when any answer carries a non-empty matches list).
    expected: u32,
    /// How many have answered so far. Increments on every well-formed Answer on this consult's corr.
    answered: u32,
    /// Accumulated offers across every answer. The reconciliation model decides what to do with the
    /// full set.
    offers: Vec<placement::EmbodimentOffer>,
}

/// The distributor creature itself.
pub struct Distributor {
    /// This distributor's own self-node — used to collapse `EmbodimentOffer.node == self_node` to
    /// local addressing. Cross-node otherwise.
    ///
    /// **Colocation contract (backlog X-2).** Every advertiser listed in `local_advertisers` MUST be
    /// constructed with this *same* `NodeId`. An advertiser tags each offer with its own `self_node`,
    /// and `reconcile` collapses `offer.node == self_node` to a local `Address::Creature`. If a
    /// colocated advertiser's `self_node` disagrees, its offers carry a different node string, so the
    /// distributor addresses a *same-Sanctum* target as `Address::Node(other, …)` and routes it out
    /// through `transport-tcp` — which has no peer named `other` and drops it. The two creatures are
    /// constructed independently, so the substrate can't check this; it's the operator's invariant
    /// (mirrored in `embodiment-advertiser`'s `new` doc).
    self_node: NodeId,
    /// Local advertiser creature ids (often a single one; multiple is fine — the consult fans out).
    /// Each MUST share this distributor's `self_node` — see that field's doc (X-2).
    local_advertisers: Vec<CreatureId>,
    /// Peer advertisers, addressed as `(peer NodeId, advertiser CreatureId on that peer)`. Static;
    /// the realm-gateway makes this dynamic.
    peer_advertisers: Vec<(NodeId, CreatureId)>,
    /// The operator's reconciliation model.
    model: PickModel,
    /// Pending consults, keyed by consult corr.
    pending: HashMap<u64, Pending>,
    /// Maximum number of pending consults the distributor will hold at once. When [`on_intent`]
    /// arrives at capacity, the oldest pending (by `consult_corr` — monotonic, so smallest=oldest)
    /// is evicted and a [`NoProviderReason::PendingEvicted`] reply is emitted to its originator.
    /// **`0` means unbounded** (the default; pick a real number in production — a
    /// flaky peer otherwise leaks pending entries forever).
    max_pending: usize,
    /// Round-robin cursor for [`PickModel::RoundRobin`] (per-distributor, not per-consult).
    rr_cursor: AtomicU64,
    /// Monotone source of consult corrs. Starts at a high seed so it doesn't collide with Intent
    /// corrs the originator might choose (which usually start small). Operator-configurable for
    /// tests that need determinism.
    next_consult_corr: AtomicU64,
    /// This distributor's own CreatureId — stashed at [`bind`] so outbound placement Queries can set
    /// `reply_to` to point back here regardless of how many transport hops an answer crosses.
    /// `None` before `bind` runs; the test-only `set_me_for_tests` populates it for unit tests
    /// that drive `handle` directly.
    me: Option<CreatureId>,
}

impl Distributor {
    /// Construct a distributor with explicit topology + model + corr seed + pending-table cap.
    /// `max_pending == 0` disables the cap (the default; pick a real number in production
    /// — a flaky peer that never answers otherwise leaks pending entries forever).
    pub fn new(
        self_node: NodeId,
        local_advertisers: Vec<CreatureId>,
        peer_advertisers: Vec<(NodeId, CreatureId)>,
        model: PickModel,
        consult_corr_seed: u64,
        max_pending: usize,
    ) -> Self {
        Distributor {
            self_node,
            local_advertisers,
            peer_advertisers,
            model,
            pending: HashMap::new(),
            max_pending,
            rr_cursor: AtomicU64::new(0),
            next_consult_corr: AtomicU64::new(consult_corr_seed),
            me: None,
        }
    }

    /// How many placement consults are currently in flight. Useful for tests + observability;
    /// **not** part of the wire contract.
    pub fn pending_consults(&self) -> usize {
        self.pending.len()
    }
}

impl Creature for Distributor {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Intent inbound → start a new placement consult.
        if let Address::Intent(_) = &env.header.to {
            return self.on_intent(env);
        }
        // SEER inbound → answer to a consult we issued. Topic-discriminate before parsing.
        if env.header.schema == SCHEMA_SEER {
            return self.on_seer(env);
        }
        // Anything else (proprio, stray) — silently ignore.
        Outcome::none()
    }
}

impl Distributor {
    fn on_intent(&mut self, env: Envelope) -> Outcome {
        // Allocate a consult corr distinct from the Intent's own corr (which routes the *final*
        // reply back to the original requester, not the placement consult traffic).
        let consult_corr = self.next_consult_corr.fetch_add(1, Ordering::Relaxed);

        // Pull the requirements off the Intent address. The Intent envelope carries them as
        // strings; the advertiser will parse — we ship verbatim so an advertiser with a richer
        // predicate vocabulary works without a distributor change.
        let (outcome, requirements) = match &env.header.to {
            Address::Intent(Intent { outcome, requirements }) => {
                (outcome.clone(), requirements.clone())
            }
            // Defensive — `handle` already gated on Address::Intent, so this branch is dead.
            _ => return Outcome::none(),
        };

        // Bind must have run (kernel lifecycle) before we can set the consult `reply_to` to
        // ourselves. If it hasn't, reply NotReady to the originator rather than panic on the
        // missing `me` (R9 floor). (`me` is `Some` on every real kernel-driven path.)
        let Some(me_id) = self.me else {
            return Outcome::send(self.build_no_provider(
                &env,
                &outcome,
                &requirements,
                0,
                0,
                NoProviderReason::NotReady,
                Some("distributor received an Intent before bind() ran"),
            ));
        };

        // Pending-pressure guard: if at capacity, evict the oldest pending (smallest consult_corr,
        // since allocation is monotonic via fetch_add) and emit a NoProviderReply for its
        // originator. Without this, a long-running node with a flaky peer that never answers
        // monotonically leaks pending entries; with it, the table is bounded and the abandoned
        // originator gets a structured reply rather than silent abandonment.
        let mut dispatches: Vec<Dispatch> = Vec::new();
        if self.max_pending > 0 && self.pending.len() >= self.max_pending {
            if let Some(&oldest) = self.pending.keys().min() {
                if let Some(p) = self.pending.remove(&oldest) {
                    let (o, r) = intent_fields(&p.intent_env);
                    dispatches.push(self.build_no_provider(
                        &p.intent_env,
                        &o,
                        &r,
                        p.expected,
                        p.answered,
                        NoProviderReason::PendingEvicted,
                        Some("pending table at max capacity; oldest evicted"),
                    ));
                }
            }
        }

        // Build the placement Query body. Advertisers parse `requirements` themselves (robustness
        // over strict-acceptance — see the advertiser docs).
        //
        // **The distributor deliberately does NOT validate requirements at entry.**
        // Requirements ship verbatim so an advertiser with a richer predicate vocabulary works
        // without a distributor change — validating here would reject predicates a future advertiser
        // *could* parse. The known consequence: a garbage predicate is dropped silently by each
        // advertiser, and an Intent whose requirements are *all* unparseable degrades to an
        // unconstrained request that fits any offer. That surfacing is intended (the advertiser owns
        // predicate semantics), not a gap to close in the distributor.
        let query_body = placement::QueryBody {
            requirements: requirements.clone(),
            outcome: Some(outcome.clone()),
        };

        // Outbound Queries' reply_to points at this distributor's own CreatureId (stashed at `bind`,
        // guarded above) so answers come back here regardless of how many transport hops they crossed.
        let reply_to_addr = Address::Creature(me_id);

        // Fan out: one Query per advertiser. All on the same consult corr / query_id=1 (the
        // model: Intent → one round of asks → reconcile; a future multi-round consultor allocates
        // more query_ids per corr).
        let mut expected: u32 = 0;

        // Local advertisers
        for adv in &self.local_advertisers {
            let q = SeerEnvelope::query(SeerTopic::Placement, consult_corr, 1, &query_body);
            dispatches.push(
                Dispatch::to(Address::Creature(*adv), q.to_bytes())
                    .with_schema(SCHEMA_SEER)
                    .with_corr(consult_corr)
                    .with_reply_to(reply_to_addr.clone()),
            );
            expected += 1;
        }
        // Peer advertisers
        for (peer, adv) in &self.peer_advertisers {
            let q = SeerEnvelope::query(SeerTopic::Placement, consult_corr, 1, &query_body);
            dispatches.push(
                Dispatch::to(Address::Node(peer.clone(), *adv), q.to_bytes())
                    .with_schema(SCHEMA_SEER)
                    .with_corr(consult_corr)
                    .with_reply_to(reply_to_addr.clone()),
            );
            expected += 1;
        }

        if expected == 0 {
            // No advertisers bound at all → immediate no_provider reply. Operator misconfig, not
            // a failure of the algorithm. (An eviction reply from above still rides alongside.)
            dispatches.push(self.build_no_provider(
                &env,
                &outcome,
                &requirements,
                0,
                0,
                NoProviderReason::NoAdvertisers,
                None,
            ));
            return Outcome { dispatches, budget_signal: None };
        }

        // Park the Intent for resumption when answers arrive.
        self.pending.insert(
            consult_corr,
            Pending { intent_env: env, expected, answered: 0, offers: Vec::new() },
        );

        Outcome { dispatches, budget_signal: None }
    }

    fn on_seer(&mut self, env: Envelope) -> Outcome {
        let seer = match SeerEnvelope::parse_bounded(&env.payload) {
            Ok(s) => s,
            Err(_) => return Outcome::none(),
        };
        if seer.topic != SeerTopic::Placement {
            return Outcome::none();
        }
        match seer.kind {
            SeerKind::Answer { query_id, body } => self.on_answer(seer.corr, query_id, body),
            // Steer/abort on the consult corr: drop the pending consult + emit no_provider with
            // reason "aborted". Mirrors agent-curious's Steer{abort} handling.
            SeerKind::Steer { kind, .. } if kind == "abort" => self.on_steer_abort(seer.corr),
            // Other kinds (Query inbound, Progress/Thought, non-abort Steer) — distributor isn't
            // on the answering side and doesn't render progress; silently ignore.
            _ => Outcome::none(),
        }
    }

    fn on_answer(&mut self, corr: u64, query_id: u64, body: serde_json::Value) -> Outcome {
        // query_id mismatch: stale or spoofed; ignore. (We always use query_id=1.)
        if query_id != 1 {
            return Outcome::none();
        }
        let answer: placement::AnswerBody = match serde_json::from_value(body) {
            Ok(b) => b,
            Err(_) => return Outcome::none(),
        };

        // Accumulate into the pending consult *in place* (no remove+reinsert churn on
        // each partial answer) — only take it out of the table once we're ready to reconcile.
        let ready = {
            let Some(p) = self.pending.get_mut(&corr) else {
                // Late answer for an already-reconciled or never-started consult; drop silently.
                return Outcome::none();
            };
            p.answered = p.answered.saturating_add(1);
            p.offers.extend(answer.matches);
            // FirstFit fires on the first offer; every other model waits for all expected answers.
            (matches!(self.model, PickModel::FirstFit) && !p.offers.is_empty())
                || p.answered >= p.expected
        };
        if ready {
            if let Some(p) = self.pending.remove(&corr) {
                return self.reconcile(p);
            }
        }
        Outcome::none()
    }

    fn on_steer_abort(&mut self, corr: u64) -> Outcome {
        let Some(p) = self.pending.remove(&corr) else {
            return Outcome::none();
        };
        let (outcome, requirements) = intent_fields(&p.intent_env);
        Outcome::send(self.build_no_provider(
            &p.intent_env,
            &outcome,
            &requirements,
            p.expected,
            p.answered,
            NoProviderReason::Aborted,
            None,
        ))
    }

    /// Pick from accumulated offers + route the Intent or emit no_provider.
    fn reconcile(&self, p: Pending) -> Outcome {
        let (outcome, requirements) = intent_fields(&p.intent_env);

        if p.offers.is_empty() {
            return Outcome::send(self.build_no_provider(
                &p.intent_env,
                &outcome,
                &requirements,
                p.expected,
                p.answered,
                NoProviderReason::EveryAdvertiserEmpty,
                None,
            ));
        }

        let pick_index = match self.model {
            PickModel::FirstFit => 0,
            PickModel::RoundRobin => {
                let cursor = self.rr_cursor.fetch_add(1, Ordering::Relaxed);
                (cursor as usize) % p.offers.len()
            }
        };
        let chosen = &p.offers[pick_index];

        // Collapse node==self_node to local addressing; otherwise build a peer Node address.
        let target_addr = if chosen.node == self.self_node.0 {
            Address::Creature(CreatureId(chosen.creature_id))
        } else {
            Address::Node(NodeId(chosen.node.clone()), CreatureId(chosen.creature_id))
        };

        // Preserve the Intent's original reply_to (so the chosen target replies to the *original*
        // requester, not back to the distributor) + the Intent's own corr + the Intent's payload
        // + schema. The distributor is a relay, not a participant.
        let reply_to = p
            .intent_env
            .header
            .reply_to
            .clone()
            .unwrap_or_else(|| p.intent_env.header.from.clone());
        let mut d = Dispatch::to(target_addr, p.intent_env.payload.clone())
            .with_schema(p.intent_env.header.schema.clone())
            .with_reply_to(reply_to);
        if let Some(c) = p.intent_env.header.corr {
            d = d.with_corr(c);
        }
        Outcome::send(d)
    }

    /// Build a NoProviderReply dispatch (does NOT wrap in Outcome). Used by both single-reply
    /// sites (`Outcome::send(build_no_provider(…))`) and the eviction site where the reply rides
    /// alongside the new consult fan-out in one Outcome.
    #[allow(clippy::too_many_arguments)] // deliberate: threads the reply-context fields through one site
    fn build_no_provider(
        &self,
        intent_env: &Envelope,
        outcome: &str,
        requirements: &[String],
        consulted: u32,
        answered: u32,
        reason: NoProviderReason,
        details: Option<&str>,
    ) -> Dispatch {
        let reply = NoProviderReply {
            outcome: outcome.to_string(),
            requirements: requirements.to_vec(),
            advertisers_consulted: consulted,
            advertisers_answered: answered,
            reason,
            details: details.map(|s| s.to_string()),
        };
        Dispatch::reply_to_env(intent_env, reply.to_bytes()).with_schema(SCHEMA_NO_PROVIDER)
    }
}

fn intent_fields(env: &Envelope) -> (String, Vec<String>) {
    match &env.header.to {
        Address::Intent(i) => (i.outcome.clone(), i.requirements.clone()),
        _ => (String::new(), Vec::new()),
    }
}

#[cfg(test)]
impl Distributor {
    /// For tests that drive `handle` directly (no kernel bind), set the `me` slot manually.
    /// `#[cfg(test)]`-gated so it isn't reachable from downstream non-test code.
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ====================================================================================================
// Tests
// ====================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{CreatureId, Header};

    fn intent_env(corr: u64, outcome: &str, requirements: Vec<&str>, payload: &[u8]) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Intent(Intent {
                    outcome: outcome.to_string(),
                    requirements: requirements.iter().map(|s| s.to_string()).collect(),
                }),
                reply_to: Some(Address::Creature(CreatureId(100))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: "text".into(),
            },
            payload: payload.to_vec(),
        }
    }

    fn answer_env(corr: u64, query_id: u64, matches: Vec<placement::EmbodimentOffer>) -> Envelope {
        let body = placement::AnswerBody { matches };
        let env = SeerEnvelope::answer(SeerTopic::Placement, corr, query_id, &body);
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(50)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SCHEMA_SEER.to_string(),
            },
            payload: env.to_bytes(),
        }
    }

    fn offer(node: &str, creature_id: u64, cpu: u32) -> placement::EmbodimentOffer {
        placement::EmbodimentOffer {
            node: node.to_string(),
            creature_id,
            embodiment: placement::Embodiment { cpu, ..Default::default() },
        }
    }

    fn make_dist(model: PickModel) -> Distributor {
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50)], // one local advertiser
            vec![],
            model,
            10_000, // consult corr seed
            1024,   // max_pending — generous; tests don't exercise eviction here
        );
        d.set_me_for_tests(CreatureId(7));
        d
    }

    #[test]
    fn intent_fan_out_emits_one_query_per_advertiser_and_parks() {
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50), CreatureId(51)],
            vec![(NodeId("node-B".into()), CreatureId(70))],
            PickModel::FirstFit,
            10_000,
            1024,
        );
        d.set_me_for_tests(CreatureId(7));

        let out = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"hi"));
        assert_eq!(out.dispatches.len(), 3, "two local + one peer queries");
        // All are SEER, all on the same consult corr.
        for q in &out.dispatches {
            assert_eq!(q.schema, SCHEMA_SEER);
            assert_eq!(q.corr, Some(10_000));
            // reply_to must point at the distributor so peer answers come back here.
            assert_eq!(q.reply_to, Some(Address::Creature(CreatureId(7))));
        }
        // First two go to local creature ids; third is a peer Node address.
        assert_eq!(out.dispatches[0].to, Address::Creature(CreatureId(50)));
        assert_eq!(out.dispatches[1].to, Address::Creature(CreatureId(51)));
        assert!(matches!(
            &out.dispatches[2].to,
            Address::Node(node, CreatureId(70)) if node.0 == "node-B"
        ));
        assert_eq!(d.pending_consults(), 1, "Intent parked");
    }

    #[test]
    fn intent_with_no_advertisers_replies_no_provider_immediately() {
        // Operator misconfig — no advertisers anywhere. The Intent must not be silently dropped;
        // the originator gets a structured NoProviderReply.
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![],
            vec![],
            PickModel::FirstFit,
            10_000,
            1024,
        );
        d.set_me_for_tests(CreatureId(7));

        let out = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"hi"));
        assert_eq!(out.dispatches.len(), 1, "single no_provider reply");
        let d0 = &out.dispatches[0];
        assert_eq!(d0.schema, SCHEMA_NO_PROVIDER);
        assert_eq!(d0.corr, Some(1), "originator's corr preserved on no_provider reply");
        let reply = NoProviderReply::parse(&d0.payload).unwrap();
        assert_eq!(reply.outcome, "reverse");
        assert_eq!(reply.requirements, vec!["cpu >= 4"]);
        assert_eq!(reply.advertisers_consulted, 0);
        assert_eq!(reply.advertisers_answered, 0);
        assert_eq!(reply.reason, NoProviderReason::NoAdvertisers);
    }

    #[test]
    fn intent_before_bind_replies_not_ready_and_parks_nothing() {
        // R9 fabric-integrity floor: an Intent that reaches the distributor before bind() ran
        // (me == None — a kernel-lifecycle race) must NOT panic. It instead
        // replies NoProviderReply{reason: NotReady} to the originator and parks nothing. This
        // is the one branch in on_intent the rest of the suite can't reach — every other test calls
        // set_me_for_tests first. Constructed WITHOUT it so `me` stays None.
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50)],
            vec![],
            PickModel::FirstFit,
            10_000,
            1024,
        );
        // Deliberately NOT calling set_me_for_tests — `me` is None, so the guard fires.

        let out = d.handle(intent_env(7, "reverse", vec!["cpu >= 4"], b"abc"));
        assert_eq!(out.dispatches.len(), 1, "single NotReady reply, no consult fan-out");
        let d0 = &out.dispatches[0];
        assert_eq!(d0.schema, SCHEMA_NO_PROVIDER);
        assert_eq!(d0.corr, Some(7), "originator's corr preserved on the NotReady reply");
        let reply = NoProviderReply::parse(&d0.payload).unwrap();
        assert_eq!(reply.reason, NoProviderReason::NotReady);
        assert!(reply.details.is_some(), "NotReady carries an audit hint");
        assert_eq!(
            d.pending_consults(),
            0,
            "the guard returns before pending.insert — nothing parked, no leak"
        );
    }

    #[test]
    fn first_fit_picks_first_offer_local_collapse() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"abc"));

        let out = d.handle(answer_env(
            10_000,
            1,
            vec![
                offer("node-A", 42, 8), // local — collapse
                offer("node-B", 99, 8), // peer
            ],
        ));
        assert_eq!(out.dispatches.len(), 1, "FirstFit picks one target");
        let routed = &out.dispatches[0];
        // First offer wins; node==self_node → Local addressing.
        assert_eq!(routed.to, Address::Creature(CreatureId(42)));
        // Intent payload + corr + reply_to preserved verbatim — distributor is a relay.
        assert_eq!(routed.payload, b"abc");
        assert_eq!(routed.corr, Some(1));
        assert_eq!(routed.reply_to, Some(Address::Creature(CreatureId(100))));
        assert_eq!(d.pending_consults(), 0, "pending consumed on reconciliation");
    }

    #[test]
    fn first_fit_picks_peer_address_when_offer_is_remote() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"abc"));

        let out = d.handle(answer_env(10_000, 1, vec![offer("node-B", 42, 8)]));
        let routed = &out.dispatches[0];
        assert!(matches!(
            &routed.to,
            Address::Node(node, CreatureId(42)) if node.0 == "node-B"
        ));
    }

    #[test]
    fn round_robin_waits_for_all_expected_then_cycles() {
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50), CreatureId(51)],
            vec![],
            PickModel::RoundRobin,
            10_000,
            1024,
        );
        d.set_me_for_tests(CreatureId(7));

        let out_intent = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"abc"));
        assert_eq!(out_intent.dispatches.len(), 2);

        // First answer: just an accumulator, NOT a reconcile (RoundRobin needs both).
        let out_a = d.handle(answer_env(10_000, 1, vec![offer("node-A", 42, 8)]));
        assert!(out_a.dispatches.is_empty(), "RoundRobin must wait for all expected answers");
        assert_eq!(d.pending_consults(), 1, "still parked after partial answers");

        // Second answer triggers reconciliation. RoundRobin cursor=0 → pick first.
        let out_b = d.handle(answer_env(10_000, 1, vec![offer("node-A", 99, 8)]));
        assert_eq!(out_b.dispatches.len(), 1);
        assert_eq!(out_b.dispatches[0].to, Address::Creature(CreatureId(42)));

        // Re-issue: cursor advances. New consult corr.
        let _ = d.handle(intent_env(2, "reverse", vec!["cpu >= 4"], b"abc"));
        let _ = d.handle(answer_env(10_001, 1, vec![offer("node-A", 42, 8)]));
        let out_c = d.handle(answer_env(10_001, 1, vec![offer("node-A", 99, 8)]));
        // Cursor was 0 last time, so this is 1 → second offer.
        assert_eq!(out_c.dispatches[0].to, Address::Creature(CreatureId(99)));
    }

    #[test]
    fn all_advertisers_return_empty_yields_structured_no_provider() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(7, "reverse", vec!["cpu >= 1000"], b"abc"));

        let out = d.handle(answer_env(10_000, 1, vec![])); // empty matches
        assert_eq!(out.dispatches.len(), 1);
        let reply = NoProviderReply::parse(&out.dispatches[0].payload).unwrap();
        assert_eq!(reply.outcome, "reverse");
        assert_eq!(reply.advertisers_consulted, 1);
        assert_eq!(reply.advertisers_answered, 1);
        assert_eq!(reply.reason, NoProviderReason::EveryAdvertiserEmpty);
    }

    #[test]
    fn answer_with_mismatched_query_id_is_silently_dropped() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(7, "reverse", vec!["cpu >= 4"], b"abc"));
        // query_id=999 doesn't match our query_id=1.
        let mut env = answer_env(10_000, 999, vec![offer("node-A", 42, 8)]);
        // Repack the payload with a different query_id.
        let body = placement::AnswerBody { matches: vec![offer("node-A", 42, 8)] };
        let seer = SeerEnvelope::answer(SeerTopic::Placement, 10_000, 999, &body);
        env.payload = seer.to_bytes();

        let out = d.handle(env);
        assert!(out.dispatches.is_empty(), "mismatched query_id → silent drop");
        assert_eq!(d.pending_consults(), 1, "pending preserved (legit answer may still arrive)");
    }

    #[test]
    fn answer_for_unknown_consult_corr_is_silently_dropped() {
        let mut d = make_dist(PickModel::FirstFit);
        let out = d.handle(answer_env(99_999, 1, vec![offer("node-A", 42, 8)]));
        assert!(out.dispatches.is_empty(), "unknown corr → silent drop, no panic");
    }

    #[test]
    fn steer_abort_drops_pending_emits_no_provider() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(7, "reverse", vec!["cpu >= 4"], b"abc"));
        assert_eq!(d.pending_consults(), 1);

        let steer = SeerEnvelope::steer(
            SeerTopic::Placement,
            10_000,
            "abort",
            &serde_json::json!({ "reason": "operator changed mind" }),
        );
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(50)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(10_000),
                commitment: None,
                schema: SCHEMA_SEER.to_string(),
            },
            payload: steer.to_bytes(),
        };
        let out = d.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].schema, SCHEMA_NO_PROVIDER);
        let reply = NoProviderReply::parse(&out.dispatches[0].payload).unwrap();
        assert_eq!(reply.reason, NoProviderReason::Aborted);
        assert_eq!(d.pending_consults(), 0);
    }

    #[test]
    fn drops_envelope_on_non_placement_topic_silently() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(7, "reverse", vec!["cpu >= 4"], b"abc"));

        // An Answer on the wrong topic must not reconcile.
        let body = placement::AnswerBody { matches: vec![offer("node-A", 42, 8)] };
        let wrong = SeerEnvelope::answer(SeerTopic::Authoring, 10_000, 1, &body);
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(50)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(10_000),
                commitment: None,
                schema: SCHEMA_SEER.to_string(),
            },
            payload: wrong.to_bytes(),
        };
        let out = d.handle(env);
        assert!(out.dispatches.is_empty(), "wrong-topic answer → silent drop");
        assert_eq!(d.pending_consults(), 1, "pending preserved across wrong-topic");
    }

    #[test]
    fn drops_malformed_seer_payload_silently_when_pending() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(7, "reverse", vec!["cpu >= 4"], b"abc"));

        let mut env = answer_env(10_000, 1, vec![offer("node-A", 42, 8)]);
        env.payload = b"not json at all".to_vec();
        let out = d.handle(env);
        assert!(out.dispatches.is_empty(), "garbage SEER → silent drop");
        assert_eq!(d.pending_consults(), 1);
    }

    #[test]
    fn drops_oversized_seer_payload_silently_when_pending() {
        let mut d = make_dist(PickModel::FirstFit);
        let _ = d.handle(intent_env(7, "reverse", vec!["cpu >= 4"], b"abc"));

        let mut env = answer_env(10_000, 1, vec![offer("node-A", 42, 8)]);
        env.payload = vec![b'{'; seer::MAX_SEER_ENVELOPE_BYTES + 1];
        let out = d.handle(env);
        assert!(out.dispatches.is_empty(), "oversized SEER → silent drop");
        assert_eq!(d.pending_consults(), 1);
    }

    #[test]
    fn consult_fires_even_for_single_local_advertiser_s4_mitigation() {
        // The S4 mitigation in code form. With exactly one local advertiser, the consult still
        // emits a Query (visible as the SeerEnvelope on the placement topic). Cross-node placement
        // doesn't retrofit a synchronous local code path into the SEER pattern.
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50)],
            vec![],
            PickModel::FirstFit,
            10_000,
            1024,
        );
        d.set_me_for_tests(CreatureId(7));

        let out = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"abc"));
        assert_eq!(out.dispatches.len(), 1, "exactly one Query");
        let q = &out.dispatches[0];
        assert_eq!(q.schema, SCHEMA_SEER, "SEER schema on the wire — the consult fires");
        let env = SeerEnvelope::parse(&q.payload).unwrap();
        assert_eq!(env.topic, SeerTopic::Placement);
        match env.kind {
            SeerKind::Query { query_id, .. } => assert_eq!(query_id, 1),
            other => panic!("expected Query, got {other:?}"),
        }
    }

    // --------- pending-pressure guard ---------------------------------------------------------

    #[test]
    fn pending_at_capacity_evicts_oldest_and_emits_no_provider() {
        // max_pending=2 — third Intent must evict the first (oldest by consult_corr; allocation is
        // monotonic via fetch_add). The evicted originator gets a NoProviderReply with
        // reason=PendingEvicted; the new Intent proceeds normally.
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50)],
            vec![],
            PickModel::FirstFit,
            10_000,
            2, // max_pending
        );
        d.set_me_for_tests(CreatureId(7));

        let _ = d.handle(intent_env(1, "reverse", vec!["cpu >= 4"], b"first"));
        let _ = d.handle(intent_env(2, "reverse", vec!["cpu >= 4"], b"second"));
        assert_eq!(d.pending_consults(), 2, "two pending after two intents at capacity");

        // Third Intent triggers eviction of the oldest (consult_corr 10_000, originator's corr=1).
        let out = d.handle(intent_env(3, "reverse", vec!["cpu >= 4"], b"third"));

        // Outcome carries: 1 evict NoProvider + 1 SEER Query (the new consult fan-out).
        assert_eq!(out.dispatches.len(), 2, "evict reply + new consult Query");
        let evict_reply = out
            .dispatches
            .iter()
            .find(|d| d.schema == SCHEMA_NO_PROVIDER)
            .expect("evict NoProvider in outcome");
        assert_eq!(evict_reply.corr, Some(1), "evicted originator's Intent corr preserved");
        let parsed = NoProviderReply::parse(&evict_reply.payload).expect("NoProviderReply parses");
        assert_eq!(parsed.reason, NoProviderReason::PendingEvicted);
        assert!(parsed.details.is_some(), "PendingEvicted carries audit details");

        // Pending re-stabilizes at 2: the oldest left, the new one parked.
        assert_eq!(d.pending_consults(), 2, "pending re-stabilized at max_pending");
    }

    #[test]
    fn max_pending_zero_means_unbounded_no_eviction() {
        // The escape hatch — max_pending=0 disables the cap (the default). Useful when an
        // operator opts into wherever the pending leak is acceptable (test fixtures, ephemeral
        // benchmarks).
        let mut d = Distributor::new(
            NodeId("node-A".into()),
            vec![CreatureId(50)],
            vec![],
            PickModel::FirstFit,
            10_000,
            0, // unbounded
        );
        d.set_me_for_tests(CreatureId(7));

        for i in 1..=10u64 {
            let _ = d.handle(intent_env(i, "reverse", vec!["cpu >= 4"], b"x"));
        }
        assert_eq!(d.pending_consults(), 10, "unbounded: no eviction at any size");
    }
}
