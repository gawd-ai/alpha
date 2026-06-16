//! `responder-budget` — the reference standing consumer for the SEER `budget` topic.
//!
//! The `budget` topic ([`seer::topics::budget`]) ships a typed grace-consult body
//! (`{ request_units, justification } → { granted, granted_units }`) for a creature that approaches
//! a limit and asks a policy creature for an extension. This reference responder grants up to a
//! **per-request ceiling**, optionally drawn from a **finite depleting pool**, and answers the
//! explicit granted/denied bit plus the units actually extended.
//!
//! It is the *stateful* exemplar of the standing-responder family: a finite pool means the verdict
//! depends on prior grants this run, so `decide` mutates `self`. The shape stays the same as the
//! stateless responders — only the decision differs.
//!
//! The answer's two fields keep the denied-vs-granted-zero ambiguity resolved (the topic's own
//! contract): `granted: false` is a denial; `granted: true, granted_units: 0` would be a deliberate
//! grant-nothing. This responder only ever emits `granted: true` when it extends a positive amount,
//! and `granted: false` when the ceiling is zero or the pool is exhausted.

use aether::{Creature, CreatureCtx, Envelope, Outcome};
use seer::{responder::respond_query, topics::budget, SeerTopic};

/// Maximum accepted `justification` length (bytes) — bounds a hostile Query's retained text.
pub const MAX_JUSTIFICATION_BYTES: usize = 4 * 1024;

/// The reference grace responder.
pub struct BudgetResponder {
    /// The most this responder will grant for any single request.
    per_request_ceiling: u64,
    /// The remaining shared pool. `None` is an unbounded pool (every request gets up to the
    /// ceiling); `Some(n)` depletes as grants are made and denies once exhausted.
    remaining: Option<u64>,
}

impl BudgetResponder {
    /// An unbounded-pool responder: every request is granted up to `per_request_ceiling`.
    pub fn with_ceiling(per_request_ceiling: u64) -> Self {
        BudgetResponder { per_request_ceiling, remaining: None }
    }

    /// A finite-pool responder: grants up to `per_request_ceiling` per request, drawn from a shared
    /// `pool` that depletes across requests. Once the pool can't cover a positive grant it denies.
    pub fn with_pool(per_request_ceiling: u64, pool: u64) -> Self {
        BudgetResponder { per_request_ceiling, remaining: Some(pool) }
    }

    /// Units left in the pool (`None` = unbounded). Useful for tests + observability.
    pub fn remaining(&self) -> Option<u64> {
        self.remaining
    }

    fn decide(&mut self, q: budget::QueryBody) -> budget::AnswerBody {
        let want = q.request_units.min(self.per_request_ceiling);
        let grant = match self.remaining {
            Some(rem) => want.min(rem),
            None => want,
        };
        if let Some(rem) = self.remaining.as_mut() {
            *rem -= grant;
        }
        // A zero grant — ceiling of zero, or an exhausted pool — is a denial, never a grant-nothing.
        budget::AnswerBody { granted: grant > 0, granted_units: grant }
    }
}

impl Creature for BudgetResponder {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        respond_query::<budget::QueryBody, budget::AnswerBody>(
            &env,
            SeerTopic::Budget,
            |q| q.justification.len() <= MAX_JUSTIFICATION_BYTES,
            |q| self.decide(q),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Header};
    use seer::{SeerEnvelope, SeerKind};

    fn seer_env(payload: Vec<u8>) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(99)),
                reply_to: Some(Address::Creature(CreatureId(11))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: seer::SCHEMA.to_string(),
                origin: None,
            },
            payload,
        }
    }

    fn query(units: u64) -> Envelope {
        let body = budget::QueryBody { request_units: units, justification: "near cap".into() };
        seer_env(SeerEnvelope::query(SeerTopic::Budget, 7, 1, &body).to_bytes())
    }

    fn verdict(out: &Outcome) -> budget::AnswerBody {
        let env = SeerEnvelope::parse(&out.dispatches[0].payload).unwrap();
        match env.kind {
            SeerKind::Answer { body, .. } => serde_json::from_value(body).unwrap(),
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn grants_up_to_the_per_request_ceiling() {
        let mut r = BudgetResponder::with_ceiling(100);
        let v = verdict(&r.handle(query(40)));
        assert!(v.granted && v.granted_units == 40, "asked under ceiling → full grant");
        let v = verdict(&r.handle(query(250)));
        assert!(v.granted && v.granted_units == 100, "asked over ceiling → capped at ceiling");
    }

    #[test]
    fn zero_ceiling_denies() {
        let mut r = BudgetResponder::with_ceiling(0);
        let v = verdict(&r.handle(query(10)));
        assert!(!v.granted && v.granted_units == 0, "zero ceiling is a denial, not grant-nothing");
    }

    #[test]
    fn finite_pool_depletes_then_denies() {
        let mut r = BudgetResponder::with_pool(100, 150);
        assert_eq!(verdict(&r.handle(query(100))).granted_units, 100);
        assert_eq!(r.remaining(), Some(50));
        // Next request is ceiling-capped at 100 but pool-capped at 50.
        let v = verdict(&r.handle(query(100)));
        assert!(v.granted && v.granted_units == 50, "pool caps the second grant");
        assert_eq!(r.remaining(), Some(0));
        // Pool exhausted → denial.
        let v = verdict(&r.handle(query(10)));
        assert!(!v.granted && v.granted_units == 0, "exhausted pool denies");
    }

    #[test]
    fn oversized_justification_is_dropped() {
        let mut r = BudgetResponder::with_ceiling(100);
        let body = budget::QueryBody {
            request_units: 1,
            justification: "x".repeat(MAX_JUSTIFICATION_BYTES + 1),
        };
        let env = seer_env(SeerEnvelope::query(SeerTopic::Budget, 7, 1, &body).to_bytes());
        assert!(r.handle(env).dispatches.is_empty(), "oversized justification → silent drop");
    }
}
