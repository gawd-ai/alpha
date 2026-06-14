//! `policy-origin` — a **reference** injected cross-node defense creature.
//!
//! The substrate ships the *mechanism*: the transport authenticates each peer link with ed25519,
//! verifies every inbound cross-node frame's signature under that authenticated key, and publishes a
//! non-enforcing [`OriginVerdict`] on
//! [`Topic::PROPRIOCEPTION`](aether::Topic::PROPRIOCEPTION). It never *acts* on a bad verdict — that
//! is policy. This creature is one reference response: it counts a peer's non-`Verified` verdicts
//! (a `BadSig` is forged/tampered content; an `Unresolved` is a trust desync) and, once a peer
//! crosses an injected threshold, pulls the **reversible** [`TransportCtl::Forget`] lever — dropping
//! it from the allowlist so it can neither send nor re-handshake until an operator re-`Connect`s it.
//!
//! It is the dual of [`immune-response`](../immune_response/index.html) for the *transport* surface:
//! that creature quarantines a misbehaving local artifact; this one evicts a misbehaving peer node.
//! **Neither is substrate.** An operator might instead log-and-page, rate-limit, demand a fresh
//! handshake, or escalate to a human — all the same shape on the same verdict stream. The fabric
//! ships the verdict + the (reversible) `Forget` lever; the decision is injected (IoC).
//!
//! Wiring is the usual reference shape: open an endpoint, subscribe it to `Topic::PROPRIOCEPTION`,
//! drain the inbox into [`handle`](OriginDefense::handle), and route the resulting dispatches —
//! `Forget` ops addressed to whoever fills [`Role::TRANSPORT`] — back onto
//! the bus.

use std::collections::{HashMap, HashSet};

use aether::{
    Address, Creature, CreatureCtx, Dispatch, Envelope, OriginEvent, OriginVerdict, Outcome, Role,
    MAX_SENSE_EVENT_BYTES, ORIGIN_EVENT_SCHEMA,
};
use transport_tcp::{TransportCtl, CTL_SCHEMA};

/// Default number of non-`Verified` verdicts from one peer before it is forgotten. Low enough to
/// react to a hostile peer, high enough to ride out a single transient desync.
pub const DEFAULT_FORGET_THRESHOLD: u32 = 3;

/// Default cap on distinct peer nodes tracked at once (bounds memory under hostile verdict traffic).
/// `0` is the explicit unbounded opt-out via [`OriginDefense::with_max_tracked_nodes`].
pub const DEFAULT_MAX_TRACKED_NODES: usize = 1_024;

/// A reference cross-node defense policy: forget a peer after repeated non-`Verified` origin verdicts.
pub struct OriginDefense {
    threshold: u32,
    max_tracked: usize,
    /// origin node id → count of non-`Verified` verdicts seen so far (cleared once we act).
    counts: HashMap<String, u32>,
    /// nodes already forgotten — we don't re-issue `Forget` (or keep counting) until re-admitted.
    forgotten: HashSet<String>,
}

impl OriginDefense {
    pub fn new() -> Self {
        OriginDefense {
            threshold: DEFAULT_FORGET_THRESHOLD,
            max_tracked: DEFAULT_MAX_TRACKED_NODES,
            counts: HashMap::new(),
            forgotten: HashSet::new(),
        }
    }

    /// Forget a peer after `n` non-`Verified` verdicts (clamped to at least 1).
    pub fn with_threshold(mut self, n: u32) -> Self {
        self.threshold = n.max(1);
        self
    }

    /// Cap the number of distinct tracked peers (`0` = unbounded; lab/demo opt-out).
    pub fn with_max_tracked_nodes(mut self, n: usize) -> Self {
        self.max_tracked = n;
        self
    }
}

impl Default for OriginDefense {
    fn default() -> Self {
        OriginDefense::new()
    }
}

impl Creature for OriginDefense {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Shared topic: only the transport's origin-verdict events are ours; ignore the rest.
        if env.header.schema != ORIGIN_EVENT_SCHEMA || env.payload.len() > MAX_SENSE_EVENT_BYTES {
            return Outcome::none();
        }
        let Ok(ev) = serde_json::from_slice::<OriginEvent>(&env.payload) else {
            return Outcome::none();
        };
        // `Verified` is the healthy path; `Local` never arrives here. Only a non-`Verified` verdict
        // is evidence a peer's traffic can't be trusted.
        if matches!(ev.verdict, OriginVerdict::Verified | OriginVerdict::Local) {
            return Outcome::none();
        }

        let node = ev.origin_node.0;
        if self.forgotten.contains(&node) {
            return Outcome::none(); // already acted; don't keep counting or re-issue Forget
        }
        // Bounded: at capacity, refuse to start tracking a *new* node (don't grow without bound);
        // already-tracked nodes keep accruing toward their threshold.
        if !self.counts.contains_key(&node)
            && self.max_tracked != 0
            && self.counts.len() >= self.max_tracked
        {
            return Outcome::none();
        }

        let count = self.counts.entry(node.clone()).or_insert(0);
        *count += 1;
        if *count < self.threshold {
            return Outcome::none();
        }

        // Threshold crossed: pull the reversible lever. Fire-and-forget to whoever fills TRANSPORT.
        self.forgotten.insert(node.clone());
        self.counts.remove(&node);
        let payload = TransportCtl::Forget { node_id: node }.to_bytes();
        Outcome::send(
            Dispatch::to(Address::Role(Role::new(Role::TRANSPORT)), payload)
                .with_schema(CTL_SCHEMA),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{CreatureId, Header, NodeId, Topic};

    fn verdict_env(node: &str, verdict: OriginVerdict) -> Envelope {
        let ev = OriginEvent {
            origin_node: NodeId(node.into()),
            target: CreatureId(5),
            corr: None,
            verdict,
        };
        Envelope {
            header: Header {
                from: Address::Kernel,
                to: Address::Topic(Topic::new(Topic::PROPRIOCEPTION)),
                reply_to: None,
                seq: 0,
                causal: Vec::new(),
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: ORIGIN_EVENT_SCHEMA.into(),
                origin: None,
            },
            payload: serde_json::to_vec(&ev).unwrap(),
        }
    }

    #[test]
    fn forgets_a_peer_once_bad_verdicts_cross_the_threshold() {
        let mut p = OriginDefense::new().with_threshold(2);
        assert!(p.handle(verdict_env("evil", OriginVerdict::BadSig)).dispatches.is_empty());
        let out = p.handle(verdict_env("evil", OriginVerdict::BadSig));
        assert_eq!(out.dispatches.len(), 1, "second BadSig crosses the threshold");
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Role(Role::new(Role::TRANSPORT)));
        assert_eq!(d.schema, CTL_SCHEMA);
        match TransportCtl::parse(&d.payload) {
            Some(TransportCtl::Forget { node_id }) => assert_eq!(node_id, "evil"),
            other => panic!("expected Forget, got {other:?}"),
        }
    }

    #[test]
    fn verified_verdicts_never_trigger_a_forget() {
        let mut p = OriginDefense::new().with_threshold(1);
        for _ in 0..5 {
            assert!(p.handle(verdict_env("good", OriginVerdict::Verified)).dispatches.is_empty());
        }
    }

    #[test]
    fn unresolved_counts_toward_the_threshold() {
        let mut p = OriginDefense::new().with_threshold(1);
        let out = p.handle(verdict_env("desynced", OriginVerdict::Unresolved));
        assert_eq!(out.dispatches.len(), 1, "an Unresolved peer is also forgotten at threshold");
    }

    #[test]
    fn a_forgotten_peer_is_not_re_issued() {
        let mut p = OriginDefense::new().with_threshold(1);
        assert_eq!(p.handle(verdict_env("evil", OriginVerdict::BadSig)).dispatches.len(), 1);
        // Further verdicts for the same node produce no new Forget (no spam) until re-admission.
        assert!(p.handle(verdict_env("evil", OriginVerdict::BadSig)).dispatches.is_empty());
    }
}
