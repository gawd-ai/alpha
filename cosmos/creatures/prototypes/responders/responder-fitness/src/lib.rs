//! `responder-fitness` — the reference standing consumer for the SEER `fitness` topic.
//!
//! The `fitness` topic ([`seer::topics::fitness`]) ships a typed selection-consult body
//! (`{ candidate_hash, criterion } → { score }`) — Loop 2's selection signal, where a selector asks
//! N raters how well a content-addressed candidate performs and reconciles their scores. This
//! reference responder answers one rater's view: it runs an **injected [`Rater`]** and returns a
//! score clamped to `[0.0, 1.0]`.
//!
//! Following the codebase's injected-model convention (mirrors `fitness-selector`'s `FitnessScorer`),
//! the scoring *model* is a `Box<dyn Rater>` the operator supplies; the fabric ships only the
//! standing-responder mechanism. The crate includes a [`ConstantRater`] for a fixed baseline and so
//! tests/demos have something to load.
//!
//! **Fail-closed on non-finite scores.** A `Rater` that returns `NaN` or `±∞` (a bug, or hostile
//! injected model) folds to `0.0` rather than propagating a poison value a downstream selector might
//! treat as "infinitely fit." This is the same hazard `fitness-selector` guards at the reconcile
//! step — guarded here too, at the source.

use aether::{Creature, CreatureCtx, Envelope, Outcome};
use seer::{responder::respond_query, topics::fitness, SeerTopic};

/// Maximum accepted `candidate_hash` length (bytes).
pub const MAX_CANDIDATE_HASH_BYTES: usize = 256;
/// Maximum accepted `criterion` length (bytes).
pub const MAX_CRITERION_BYTES: usize = 1024;

/// The injected scoring model. A rater sees the whole Query (candidate identity + criterion) and
/// returns a raw score; the responder clamps it to `[0, 1]` and folds non-finite values to `0`.
///
/// `Send` so a rater can be moved into a creature loaded on the kernel's executor — matching the
/// bound on `fitness-selector`'s `FitnessScorer`.
pub trait Rater: Send {
    /// Score `q.candidate_hash` against `q.criterion`. May return any `f32`; the responder
    /// sanitizes it (clamp + non-finite fold) before it reaches the wire.
    fn score(&self, q: &fitness::QueryBody) -> f32;
}

/// A rater that returns the same score for every candidate — a fixed baseline for tests/demos and
/// the simplest possible reference model.
pub struct ConstantRater(pub f32);

impl Rater for ConstantRater {
    fn score(&self, _q: &fitness::QueryBody) -> f32 {
        self.0
    }
}

/// The reference fitness responder.
pub struct FitnessResponder {
    rater: Box<dyn Rater>,
}

impl FitnessResponder {
    /// Construct with an injected rater.
    pub fn new(rater: Box<dyn Rater>) -> Self {
        FitnessResponder { rater }
    }

    /// Construct with a [`ConstantRater`] — every candidate scores `score`.
    pub fn constant(score: f32) -> Self {
        FitnessResponder { rater: Box::new(ConstantRater(score)) }
    }

    fn decide(&self, q: fitness::QueryBody) -> fitness::AnswerBody {
        let raw = self.rater.score(&q);
        // Fail-closed: a non-finite score is treated as the worst score, never propagated.
        let score = if raw.is_finite() { raw.clamp(0.0, 1.0) } else { 0.0 };
        fitness::AnswerBody { score }
    }
}

impl Creature for FitnessResponder {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        respond_query::<fitness::QueryBody, fitness::AnswerBody>(
            &env,
            SeerTopic::Fitness,
            |q| {
                !q.candidate_hash.is_empty()
                    && q.candidate_hash.len() <= MAX_CANDIDATE_HASH_BYTES
                    && q.criterion.len() <= MAX_CRITERION_BYTES
            },
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

    fn query(hash: &str, criterion: &str) -> Envelope {
        let body = fitness::QueryBody {
            candidate_hash: hash.to_string(),
            criterion: criterion.to_string(),
        };
        seer_env(SeerEnvelope::query(SeerTopic::Fitness, 7, 1, &body).to_bytes())
    }

    fn score(out: &Outcome) -> f32 {
        let env = SeerEnvelope::parse(&out.dispatches[0].payload).unwrap();
        match env.kind {
            SeerKind::Answer { body, .. } => {
                let a: fitness::AnswerBody = serde_json::from_value(body).unwrap();
                a.score
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    struct InjectedNan;
    impl Rater for InjectedNan {
        fn score(&self, _q: &fitness::QueryBody) -> f32 {
            f32::NAN
        }
    }

    #[test]
    fn constant_rater_answers_its_score() {
        let mut r = FitnessResponder::constant(0.75);
        assert_eq!(score(&r.handle(query("sha256:aa", "success-rate"))), 0.75);
    }

    #[test]
    fn out_of_range_scores_are_clamped() {
        let mut hi = FitnessResponder::constant(5.0);
        assert_eq!(score(&hi.handle(query("sha256:aa", "x"))), 1.0);
        let mut lo = FitnessResponder::constant(-3.0);
        assert_eq!(score(&lo.handle(query("sha256:aa", "x"))), 0.0);
    }

    #[test]
    fn non_finite_score_folds_to_zero_fail_closed() {
        let mut r = FitnessResponder::new(Box::new(InjectedNan));
        let s = score(&r.handle(query("sha256:aa", "x")));
        assert_eq!(s, 0.0, "NaN must not propagate as 'infinitely fit'");
    }

    #[test]
    fn empty_candidate_hash_is_dropped() {
        let mut r = FitnessResponder::constant(0.5);
        assert!(r.handle(query("", "x")).dispatches.is_empty(), "empty candidate → silent drop");
    }
}
