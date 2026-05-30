//! Round-robin distributor — a **reference** injected Distributor (lever 6).
//!
//! The fabric ships *none* of its own; this is the minimal reference strategy that proves the
//! `Intent` socket works end-to-end. A real distributor would consult a registry, race N Somethings-
//! In-the-Loop, weigh placements against advertised embodiment, or pre-decide and ask only for show
//! — anything. The fabric does not care about the model; it cares only that *some* creature is
//! bound to the socket. If nothing is bound, the fabric supplies nothing (`NoProvider`).
//!
//! ## Status
//!
//! The **real** Distributor is
//! [`distributor-requirements`](../../../creatures/distributor-requirements) — a creature that
//! consults `seer::SeerEnvelope` on the `placement` topic, parses
//! `seer::topics::placement::Predicate`s, and reconciles embodiment offers from one or
//! more [`embodiment-advertiser`](../../../creatures/embodiment-advertiser)s. This round-robin
//! reference stays in the repo as: (a) the minimum-viable Distributor (still useful for tests that
//! don't want SEER overhead), and (b) the IoC-composability proof — two distributor creatures can
//! coexist; the operator picks one with `bind_role(Role::DISTRIBUTOR, …)`.

use std::sync::atomic::{AtomicUsize, Ordering};

use aether::{Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome};

pub struct RoundRobinDistributor {
    targets: Vec<CreatureId>,
    next: AtomicUsize,
}

impl RoundRobinDistributor {
    pub fn with_targets(targets: Vec<CreatureId>) -> Self {
        RoundRobinDistributor { targets, next: AtomicUsize::new(0) }
    }
}

impl Creature for RoundRobinDistributor {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Only resolve `Intent`-addressed envelopes — anything else isn't for the Distributor.
        if !matches!(&env.header.to, Address::Intent(_)) {
            return Outcome::none();
        }
        if self.targets.is_empty() {
            return Outcome::none();
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.targets.len();
        let target = self.targets[idx];

        // Preserve `reply_to` (falling back to `from`) so the chosen target can answer the *original*
        // requester directly — fire-and-correlate without proxying. Preserve `corr` too.
        let reply_to = env.reply_target();
        let mut d = Dispatch::to(Address::Creature(target), env.payload)
            .with_schema(env.header.schema)
            .with_reply_to(reply_to);
        if let Some(corr) = env.header.corr {
            d = d.with_corr(corr);
        }
        Outcome::send(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Header, Intent};

    fn intent_env(payload: &[u8], from: CreatureId) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(from),
                to: Address::Intent(Intent { outcome: "reverse".into(), requirements: vec![] }),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(13),
                commitment: None,
                schema: "text".into(),
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn distributes_intents_round_robin_and_preserves_reply_state() {
        let mut r = RoundRobinDistributor::with_targets(vec![CreatureId(10), CreatureId(20)]);
        let mut routed_to = Vec::new();
        for _ in 0..4 {
            let out = r.handle(intent_env(b"x", CreatureId(1)));
            assert_eq!(out.dispatches.len(), 1);
            routed_to.push(out.dispatches[0].to.clone());
            // reply_to defaults to `from` when the requester didn't set one.
            assert_eq!(out.dispatches[0].reply_to, Some(Address::Creature(CreatureId(1))));
            assert_eq!(out.dispatches[0].corr, Some(13));
        }
        assert_eq!(routed_to[0], Address::Creature(CreatureId(10)));
        assert_eq!(routed_to[1], Address::Creature(CreatureId(20)));
        assert_eq!(routed_to[2], Address::Creature(CreatureId(10))); // wraps
    }

    #[test]
    fn non_intent_envelopes_pass_through_as_no_op() {
        let mut r = RoundRobinDistributor::with_targets(vec![CreatureId(10)]);
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: b"x".to_vec(),
        };
        assert!(r.handle(env).dispatches.is_empty());
    }
}
