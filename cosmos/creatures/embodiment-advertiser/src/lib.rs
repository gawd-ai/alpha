//! `embodiment-advertiser` — the placement-topic SEER consumer.
//!
//! One advertiser per Sanctum. Configured at construction with:
//! - the Sanctum's `NodeId` (so answers can be tagged in the canonical local-or-peer form), and
//! - a list of `(CreatureId, Embodiment)` *offers* — the targets the operator has decided to expose
//!   to the placement market.
//!
//! On every inbound SEER envelope on the `placement` topic, the advertiser parses the requester's
//! requirement predicates (`cpu >= 2`, `accelerator contains nvidia`, …), checks each offer
//! against every predicate, and emits a single SEER `Answer` carrying every matching offer up to the
//! placement topic's shared answer cap.
//!
//! ## What this creature deliberately doesn't do (named, not pretended)
//!
//! - **It doesn't introspect the kernel.** The set of offers is operator-supplied at construction
//!   (or via a future `OfferUpdate` schema; deferred). The advertiser doesn't auto-discover loaded
//!   creatures; that would couple it to kernel internals and violate the three-job invariant.
//! - **It doesn't rank.** The order of `matches` in the answer is the order the offers were
//!   configured in. The distributor's reconciliation model is what decides "best"; the advertiser
//!   ships every fit and lets the model choose.
//! - **It doesn't time out.** A `deadline_ms` in the Query body (currently unused; reserved) is
//!   advisory — time is injected policy, never fabric. An advertiser that ignores deadline answers
//!   when it answers.
//! - **It doesn't bridge across nodes.** Each Sanctum runs its own advertiser. The distributor on
//!   one node addresses placement Queries to advertisers on peers (via `Address::Node(peer,
//!   advertiser_module_id)`) directly — transport-tcp delivers the Query; this advertiser
//!   processes it locally; its Answer (on the Query's `reply_to`) ships back via transport-tcp.
//!   The realm-gateway lets the distributor say "ask everyone in the realm" instead.
//! - **It doesn't filter by topic on the *outbound* path.** It only ever emits on `placement`, by
//!   construction — the inbound topic check is the discrimination gate.
//!
//! ## Topic isolation by creature discrimination
//!
//! The advertiser checks `seer.topic == SeerTopic::Placement` and silently drops envelopes on any
//! other topic. The substrate doesn't adjudicate cross-topic disputes; that's the consumer's call.
//! Mirrors the pattern in `agent-curious` (the authoring-topic consumer).

use aether::{Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome};
use seer::{topics::placement, SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};

/// Schema string the advertiser reads and writes — every conversation envelope is SEER, the topic
/// discriminates. Mirrors the convention in `agent-curious::schema::SEER`.
pub const SCHEMA_SEER: &str = SEER_SCHEMA;

/// Default maximum valid offers retained by one advertiser.
///
/// A placement answer is separately capped to [`placement::MAX_ANSWER_MATCHES`], but the configured
/// offer table is retained for the advertiser's lifetime and scanned on every Query. This default
/// leaves headroom for many local targets without letting a malformed config become permanent
/// unbounded state. Pass `0` to [`EmbodimentAdvertiser::with_max_offers`] for the explicit
/// lab/demo opt-out.
pub const DEFAULT_MAX_ADVERTISED_OFFERS: usize = 4096;

/// One offer the advertiser knows about — a target plus its embodiment metadata. The
/// `creature_id` is local to *this* advertiser's Sanctum; the advertiser tags it with its `self_node`
/// when answering so the distributor can map local-vs-peer addressing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferEntry {
    /// The local creature id this offer routes work to.
    pub creature_id: CreatureId,
    /// What this target advertises (cpu / mem / accelerators / jurisdiction / connectivity).
    pub embodiment: placement::Embodiment,
}

/// The advertiser creature.
///
/// Stateful only in the trivial sense (holds its config). Stateless across handle calls — every
/// inbound Query is matched against the same offer set, so reordering / retries don't affect
/// correctness.
pub struct EmbodimentAdvertiser {
    self_node: NodeId,
    offers: Vec<OfferEntry>,
}

impl EmbodimentAdvertiser {
    /// Construct an advertiser. `self_node` tags every answered offer so the distributor can map
    /// local-vs-peer addressing on receipt.
    ///
    /// Retains only shape-valid offers, up to [`DEFAULT_MAX_ADVERTISED_OFFERS`]. Invalid configured
    /// offers were never emitted; dropping them here keeps hostile or stale config from becoming
    /// long-lived retained state.
    ///
    /// **Colocation contract (backlog X-2).** A distributor that lists *this* advertiser in its
    /// `local_advertisers` MUST be constructed with the *same* `self_node`. The distributor collapses
    /// `offer.node == its self_node` to a local `Address::Creature`; a mismatch makes it treat a
    /// same-Sanctum target as a remote peer and route the placement through `transport-tcp` (which
    /// then drops it, having no such peer). See `distributor-requirements`'s `self_node` field doc
    /// for the full rationale.
    pub fn new(self_node: NodeId, offers: Vec<OfferEntry>) -> Self {
        Self::with_max_offers(self_node, offers, DEFAULT_MAX_ADVERTISED_OFFERS)
    }

    /// Construct an advertiser with an explicit retained-offer cap.
    ///
    /// `max_offers == 0` is the deliberate unbounded opt-out for lab/demo workloads. Invalid offer
    /// shapes are always dropped, because they cannot be routed safely and would otherwise remain in
    /// memory forever.
    pub fn with_max_offers(self_node: NodeId, offers: Vec<OfferEntry>, max_offers: usize) -> Self {
        let offers = retain_configured_offers(&self_node, offers, max_offers);
        EmbodimentAdvertiser { self_node, offers }
    }

    /// The advertiser's configured offer count. Useful for tests + observability.
    pub fn offer_count(&self) -> usize {
        self.offers.len()
    }
}

impl Creature for EmbodimentAdvertiser {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Advertiser only speaks SEER. Anything else (a probe poking the wrong address, a stray
        // proprio fan-out) is silently ignored — no Failed reply, no panic, no drop count.
        if env.header.schema != SCHEMA_SEER {
            return Outcome::none();
        }
        let seer = match SeerEnvelope::parse_bounded(&env.payload) {
            Ok(s) => s,
            // A malformed SeerEnvelope on the advertiser's inbox is hostile or buggy input. Drop
            // silently — answering "I couldn't parse you" would imply the substrate adjudicates
            // wire mismatches via this consumer, which it doesn't.
            Err(_) => return Outcome::none(),
        };
        // Topic isolation by creature discrimination. Same pattern as agent-curious.
        if seer.topic != SeerTopic::Placement {
            return Outcome::none();
        }
        match seer.kind {
            SeerKind::Query { query_id, body } => self.on_query(env, seer.corr, query_id, body),
            // The advertiser is on the *answering* side. Answer/Steer/Progress/Thought arriving
            // here would mean someone confused the advertiser for a distributor or orchestrator —
            // silently drop, conservative move.
            _ => Outcome::none(),
        }
    }
}

impl EmbodimentAdvertiser {
    fn on_query(
        &self,
        env: Envelope,
        corr: u64,
        query_id: u64,
        body: serde_json::Value,
    ) -> Outcome {
        let q: placement::QueryBody = match serde_json::from_value(body) {
            Ok(q) => q,
            // A malformed placement body is dropped silently for the same reason a malformed outer
            // SeerEnvelope is: the substrate doesn't have a "report-back-decoder-error" channel.
            Err(_) => return Outcome::none(),
        };
        if !query_shape_is_valid(&q) {
            return Outcome::none();
        }

        // Parse predicates. **Robustness over strict-acceptance**: a single garbage predicate
        // doesn't fail the whole query — we skip it and match against the rest. If *every*
        // predicate fails to parse, the only well-typed predicate set is the empty one, and every
        // offer matches (the request is unconstrained). That's the same shape as an Intent with no
        // requirements, which by convention means "anyone fits." An advertiser that wants strict
        // acceptance subscribes its own model in front.
        let predicates: Vec<placement::Predicate> =
            q.requirements.iter().filter_map(|s| placement::Predicate::parse(s).ok()).collect();

        let matches: Vec<placement::EmbodimentOffer> = self
            .offers
            .iter()
            .filter(|o| offer_entry_shape_is_valid(&self.self_node, o))
            .filter(|o| predicates.iter().all(|p| p.matches(&o.embodiment)))
            .take(placement::MAX_ANSWER_MATCHES)
            .map(|o| placement::EmbodimentOffer {
                node: self.self_node.0.clone(),
                creature_id: o.creature_id.0,
                embodiment: o.embodiment.clone(),
            })
            .collect();

        let answer_body = placement::AnswerBody { matches };
        let answer = SeerEnvelope::answer(SeerTopic::Placement, corr, query_id, &answer_body);

        // Reply to the Query's reply_to (the original distributor), falling back to the
        // immediate sender. This is the same pattern every consult-respond creature uses
        // (transport rewrites reply_to on cross-node so the answer ships back; this creature
        // never has to know whether the requester was local or peer).
        let dispatch = Dispatch::reply_to_env(&env, answer.to_bytes())
            .with_schema(SCHEMA_SEER)
            .with_corr(corr);
        Outcome::send(dispatch)
    }
}

fn query_shape_is_valid(q: &placement::QueryBody) -> bool {
    q.requirements.len() <= placement::MAX_QUERY_REQUIREMENTS
        && q.requirements
            .iter()
            .all(|r| label_is_bounded(r, placement::MAX_QUERY_REQUIREMENT_BYTES))
        && q.outcome
            .as_deref()
            .is_none_or(|outcome| label_is_bounded(outcome, placement::MAX_QUERY_OUTCOME_BYTES))
}

fn offer_entry_shape_is_valid(self_node: &NodeId, offer: &OfferEntry) -> bool {
    node_id_shape_is_valid(&self_node.0)
        && bounded_labels(&offer.embodiment.accelerators)
        && bounded_labels(&offer.embodiment.sensors)
        && optional_label_is_bounded(offer.embodiment.jurisdiction.as_deref())
        && optional_label_is_bounded(offer.embodiment.connectivity.as_deref())
}

fn node_id_shape_is_valid(node: &str) -> bool {
    !node.is_empty()
        && node.len() <= placement::MAX_OFFER_NODE_ID_BYTES
        && node.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn bounded_labels(labels: &[String]) -> bool {
    labels.len() <= placement::MAX_OFFER_LABELS
        && labels.iter().all(|s| label_is_bounded(s, placement::MAX_OFFER_LABEL_BYTES))
}

fn optional_label_is_bounded(label: Option<&str>) -> bool {
    label.is_none_or(|s| label_is_bounded(s, placement::MAX_OFFER_LABEL_BYTES))
}

fn label_is_bounded(label: &str, max_bytes: usize) -> bool {
    !label.bytes().any(|b| b == 0) && label.len() <= max_bytes
}

fn retain_configured_offers(
    self_node: &NodeId,
    offers: Vec<OfferEntry>,
    max_offers: usize,
) -> Vec<OfferEntry> {
    let valid = offers.into_iter().filter(|offer| offer_entry_shape_is_valid(self_node, offer));
    if max_offers == 0 {
        valid.collect()
    } else {
        valid.take(max_offers).collect()
    }
}

// ====================================================================================================
// Tests
// ====================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Header};

    fn nv_offer(id: u64, cpu: u32) -> OfferEntry {
        OfferEntry {
            creature_id: CreatureId(id),
            embodiment: placement::Embodiment {
                cpu,
                mem_bytes: 8 * 1024 * 1024 * 1024,
                accelerators: vec!["nvidia-a100".into()],
                jurisdiction: Some("us".into()),
                connectivity: Some("wired".into()),
                sensors: vec![],
            },
        }
    }

    fn plain_offer(id: u64, cpu: u32) -> OfferEntry {
        OfferEntry {
            creature_id: CreatureId(id),
            embodiment: placement::Embodiment {
                cpu,
                mem_bytes: 4 * 1024 * 1024 * 1024,
                accelerators: vec![],
                jurisdiction: Some("ca".into()),
                connectivity: Some("satellite".into()),
                sensors: vec![],
            },
        }
    }

    fn seer_env(corr: u64, payload: Vec<u8>) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(99)),
                reply_to: Some(Address::Creature(CreatureId(11))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SCHEMA_SEER.to_string(),
                origin: None,
            },
            payload,
        }
    }

    fn query_env(corr: u64, query_id: u64, requirements: Vec<&str>) -> Envelope {
        query_env_owned(corr, query_id, requirements.iter().map(|s| s.to_string()).collect(), None)
    }

    fn query_env_owned(
        corr: u64,
        query_id: u64,
        requirements: Vec<String>,
        outcome: Option<String>,
    ) -> Envelope {
        let body = placement::QueryBody { requirements, outcome };
        let q = SeerEnvelope::query(SeerTopic::Placement, corr, query_id, &body);
        seer_env(corr, q.to_bytes())
    }

    fn decode_answer(d: &Dispatch) -> (SeerEnvelope, placement::AnswerBody) {
        let env = SeerEnvelope::parse(&d.payload).expect("seer envelope");
        let body = match &env.kind {
            SeerKind::Answer { body, .. } => body.clone(),
            other => panic!("expected Answer, got {other:?}"),
        };
        let body: placement::AnswerBody = serde_json::from_value(body).expect("answer body");
        (env, body)
    }

    #[test]
    fn answers_query_with_matching_offers_only() {
        let adv = EmbodimentAdvertiser::new(
            NodeId("node-A".into()),
            vec![nv_offer(10, 8), plain_offer(11, 4)],
        );
        let mut a = adv;
        let out = a.handle(query_env(42, 1, vec!["cpu >= 8"]));
        assert_eq!(out.dispatches.len(), 1, "exactly one answer envelope per query");

        let (env, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(env.topic, SeerTopic::Placement);
        assert_eq!(env.corr, 42);
        match env.kind {
            SeerKind::Answer { query_id, .. } => assert_eq!(query_id, 1, "query_id preserved"),
            _ => unreachable!(),
        }
        assert_eq!(body.matches.len(), 1, "only the cpu=8 offer fits");
        assert_eq!(body.matches[0].creature_id, 10);
        assert_eq!(body.matches[0].node, "node-A");
        assert_eq!(body.matches[0].embodiment.cpu, 8);
    }

    #[test]
    fn answers_with_empty_matches_when_no_offer_fits() {
        // The empty-matches case is the no_match exit criterion: a positive "I heard you, nothing
        // fits" answer, distinguishable from "no answer received." The advertiser still answers.
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![plain_offer(10, 2)]);
        let out = a.handle(query_env(7, 1, vec!["cpu >= 16"]));
        assert_eq!(out.dispatches.len(), 1, "always answer, even when empty");
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert!(body.matches.is_empty(), "no offer satisfies cpu >= 16");
    }

    #[test]
    fn multi_predicate_intersection_filters_correctly() {
        let mut a = EmbodimentAdvertiser::new(
            NodeId("node-A".into()),
            vec![nv_offer(10, 8), plain_offer(11, 8)],
        );
        // Two offers both have cpu >= 8, but only the nvidia one has the accelerator.
        let out = a.handle(query_env(7, 1, vec!["cpu >= 4", "accelerator contains nvidia-a100"]));
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches.len(), 1);
        assert_eq!(body.matches[0].creature_id, 10);
    }

    #[test]
    fn unparseable_predicates_are_skipped_robustness_over_strict_acceptance() {
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![plain_offer(10, 4)]);
        // Garbage predicate is dropped silently; the surviving `cpu >= 2` matches the plain offer.
        let out = a.handle(query_env(7, 1, vec!["banana banana", "cpu >= 2"]));
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches.len(), 1, "one surviving predicate still matches");
    }

    #[test]
    fn no_requirements_means_every_offer_fits() {
        // An empty (or fully-garbage) predicate set is unconstrained — every offer matches.
        // Same shape as an Intent with no requirements.
        let mut a = EmbodimentAdvertiser::new(
            NodeId("node-A".into()),
            vec![nv_offer(10, 8), plain_offer(11, 4)],
        );
        let out = a.handle(query_env(7, 1, vec![]));
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches.len(), 2, "no constraints → both offers fit");
    }

    #[test]
    fn drops_oversized_placement_query_shape_silently() {
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        let requirements = vec!["cpu >= 1".to_string(); placement::MAX_QUERY_REQUIREMENTS + 1];
        let out = a.handle(query_env_owned(7, 1, requirements, None));
        assert!(out.dispatches.is_empty(), "too many requirements → silent drop");

        let out = a.handle(query_env_owned(
            8,
            1,
            vec!["r".repeat(placement::MAX_QUERY_REQUIREMENT_BYTES + 1)],
            None,
        ));
        assert!(out.dispatches.is_empty(), "oversized requirement → silent drop");
    }

    #[test]
    fn answer_matches_are_capped_to_shared_placement_limit() {
        let offers: Vec<_> =
            (0..=placement::MAX_ANSWER_MATCHES).map(|i| plain_offer(1_000 + i as u64, 4)).collect();
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), offers);

        let out = a.handle(query_env(7, 1, vec![]));

        assert_eq!(out.dispatches.len(), 1);
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches.len(), placement::MAX_ANSWER_MATCHES);
    }

    #[test]
    fn malformed_configured_offer_is_not_emitted() {
        let mut invalid = nv_offer(10, 8);
        invalid.embodiment.accelerators = vec!["x".repeat(placement::MAX_OFFER_LABEL_BYTES + 1)];
        let mut a =
            EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![invalid, plain_offer(11, 4)]);

        let out = a.handle(query_env(7, 1, vec![]));

        assert_eq!(out.dispatches.len(), 1);
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches.len(), 1);
        assert_eq!(body.matches[0].creature_id, 11);
    }

    #[test]
    fn configured_offers_are_sanitized_and_bounded_by_default() {
        let mut invalid = nv_offer(9, 8);
        invalid.embodiment.accelerators = vec!["x".repeat(placement::MAX_OFFER_LABEL_BYTES + 1)];
        let mut offers = vec![invalid];
        offers
            .extend((0..=DEFAULT_MAX_ADVERTISED_OFFERS).map(|i| plain_offer(10_000 + i as u64, 4)));

        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), offers);

        assert_eq!(
            a.offer_count(),
            DEFAULT_MAX_ADVERTISED_OFFERS,
            "invalid offer is dropped and valid retained offers stop at the default cap"
        );

        let out = a.handle(query_env(7, 1, vec![]));
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches.len(), placement::MAX_ANSWER_MATCHES);
        assert_eq!(body.matches[0].creature_id, 10_000);
    }

    #[test]
    fn zero_offer_cap_is_explicit_unbounded_opt_out() {
        let offers: Vec<_> = (0..=DEFAULT_MAX_ADVERTISED_OFFERS)
            .map(|i| plain_offer(20_000 + i as u64, 4))
            .collect();

        let a = EmbodimentAdvertiser::with_max_offers(NodeId("node-A".into()), offers, 0);

        assert_eq!(a.offer_count(), DEFAULT_MAX_ADVERTISED_OFFERS + 1);
    }

    #[test]
    fn drops_envelope_on_non_placement_topic_silently() {
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        // A Query on the authoring topic must not be answered by the placement advertiser. The
        // substrate doesn't adjudicate cross-topic via this creature.
        let q = SeerEnvelope::query(
            SeerTopic::Authoring,
            7,
            1,
            &serde_json::json!({ "question": "huh?" }),
        );
        let out = a.handle(seer_env(7, q.to_bytes()));
        assert!(out.dispatches.is_empty(), "wrong-topic envelope dropped silently");
    }

    #[test]
    fn drops_non_seer_schema_silently() {
        // An envelope addressed at the advertiser but with the wrong schema (e.g. a raw text
        // probe) is dropped silently — same rule as wrong topic. No panic, no reply.
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        let mut env = seer_env(1, b"raw".to_vec());
        env.header.schema = "text/plain".to_string();
        let out = a.handle(env);
        assert!(out.dispatches.is_empty());
    }

    #[test]
    fn drops_malformed_seer_payload_silently() {
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        let out = a.handle(seer_env(1, b"not json".to_vec()));
        assert!(out.dispatches.is_empty(), "garbage SEER payload → silent drop");
    }

    #[test]
    fn drops_oversized_seer_payload_silently() {
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        let out = a.handle(seer_env(1, vec![b'{'; seer::MAX_SEER_ENVELOPE_BYTES + 1]));
        assert!(out.dispatches.is_empty(), "oversized SEER payload → silent drop");
    }

    #[test]
    fn drops_malformed_placement_query_body_silently() {
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        let bogus_body = serde_json::json!({ "not_requirements": 42 });
        let q = SeerEnvelope::query(SeerTopic::Placement, 7, 1, &bogus_body);
        let out = a.handle(seer_env(7, q.to_bytes()));
        assert!(out.dispatches.is_empty(), "garbage body → silent drop");
    }

    #[test]
    fn ignores_answer_steer_progress_thought_on_placement_topic() {
        // An advertiser is on the answering side; non-Query SEER moves arriving at its address are
        // suspicious (someone confused it for a distributor) and dropped silently.
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);

        for kind_env in [
            SeerEnvelope::answer(SeerTopic::Placement, 1, 0, &serde_json::json!({})),
            SeerEnvelope::steer(SeerTopic::Placement, 1, "abort", &serde_json::json!({})),
            SeerEnvelope::progress(SeerTopic::Placement, 1, "stage", None, None),
            SeerEnvelope::thought(SeerTopic::Placement, 1, "internal", "noise"),
        ] {
            let out = a.handle(seer_env(1, kind_env.to_bytes()));
            assert!(out.dispatches.is_empty(), "non-Query kind on placement topic → silent drop");
        }
    }

    #[test]
    fn answer_routes_to_reply_to_then_falls_back_to_from() {
        // reply_to set → answer addressed there.
        let mut a = EmbodimentAdvertiser::new(NodeId("node-A".into()), vec![nv_offer(10, 8)]);
        let mut env = query_env(7, 1, vec!["cpu >= 4"]);
        env.header.reply_to = Some(Address::Creature(CreatureId(77)));
        let out = a.handle(env);
        assert_eq!(out.dispatches[0].to, Address::Creature(CreatureId(77)));

        // reply_to None → falls back to from.
        let mut env = query_env(8, 1, vec!["cpu >= 4"]);
        env.header.reply_to = None;
        env.header.from = Address::Creature(CreatureId(33));
        let out = a.handle(env);
        assert_eq!(out.dispatches[0].to, Address::Creature(CreatureId(33)));
    }

    #[test]
    fn answer_carries_self_node_for_local_or_peer_collapse() {
        // The advertiser tags every offer with its self_node. The distributor on receipt collapses
        // node==self_node to local addressing; otherwise constructs a peer Address::Node.
        let mut a = EmbodimentAdvertiser::new(NodeId("node-B".into()), vec![nv_offer(42, 4)]);
        let out = a.handle(query_env(1, 1, vec!["cpu >= 4"]));
        let (_, body) = decode_answer(&out.dispatches[0]);
        assert_eq!(body.matches[0].node, "node-B", "advertiser tags its self_node");
        assert_eq!(body.matches[0].creature_id, 42);
    }
}
