//! `SuccessRateScorer` — a **reference** injected [`FitnessScorer`] that scores a creature by the
//! fraction of its handled envelopes that were useful (`ok / handled`, in `[0.0, 1.0]`).
//!
//! Mirror of the `cosmos/creatures/prototypes/policies/policy-signed` / `cosmos/creatures/prototypes/reputation/reputation-roundrobin` pattern: a tiny struct
//! implementing a substrate-shipped trait. The simplest honest fitness criterion — "how often does
//! this creature do useful work?" — and the one the M11 integration test uses to prove a real
//! kernel fitness stream drives a promotion.
//!
//! ### What this reference deliberately doesn't do
//!
//! - **No windowing.** It scores the all-time tally; a real selector would weight recent behavior
//!   (an EWMA, a sliding window) so a creature that regressed loses its promotion.
//! - **No minimum-sample floor.** One lucky `ok` handle scores `1.0`. A real criterion would
//!   require N observations before trusting a rate (the selector's `threshold` is a separate gate;
//!   sample-count confidence is the scorer's to add).
//! - **No latency / cost.** It ignores [`Observations::mean_latency_ms`] entirely — see
//!   `cosmos/creatures/prototypes/scorers/scorer-latency` for the timing dimension.
//!
//! Operators write their own (`my-org-fitness`, `latency-weighted-success`, …) and pass it to
//! `SelectorConfig`. The substrate ships only the trait + this minimum reference (T4 / IoC).

use fitness_selector::{FitnessScorer, Observations};

/// Scores by success rate: `ok / handled`, `0.0` when nothing was handled.
pub struct SuccessRateScorer;

impl FitnessScorer for SuccessRateScorer {
    fn score(&self, obs: &Observations) -> f32 {
        obs.success_rate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_the_useful_fraction() {
        let s = SuccessRateScorer;
        assert_eq!(s.score(&Observations::default()), 0.0);
        assert!(
            (s.score(&Observations { handled: 4, ok: 3, ..Default::default() }) - 0.75).abs()
                < 1e-6
        );
        assert!(
            (s.score(&Observations { handled: 2, ok: 2, ..Default::default() }) - 1.0).abs() < 1e-6
        );
    }
}
