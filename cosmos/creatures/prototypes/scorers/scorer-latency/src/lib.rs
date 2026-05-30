//! `LatencyScorer` — a **reference** injected [`FitnessScorer`] that rewards *fast* creatures:
//! lower mean handle-latency scores higher, linearly against a configured ceiling.
//!
//! Score: `(1.0 - mean_ms / ceiling_ms)` clamped to `[0.0, 1.0]`. A creature whose mean latency is
//! `0` scores `1.0`; one at or above the ceiling scores `0.0`; one with **no latency samples**
//! scores `0.0` (no evidence is not "instant"). This is the dimension the kernel's fitness signal
//! *can't* provide — `Fitness { module, ok }` carries no timing — so a latency-scored selector is
//! fed via `fitness-selector`'s `Observe { module, ok, latency_ms }` op (an operator's load test, a
//! replayed trace, or a creature that self-reports its own service time).
//!
//! ### What this reference deliberately doesn't do
//!
//! - **No success weighting.** It ignores `ok`/`handled` entirely — a fast creature that always
//!   *fails* still scores high here. A real criterion composes latency with success (e.g.
//!   `success_rate * latency_score`); kept separate so each dimension is a clean reference.
//! - **No percentile / tail awareness.** It uses the mean; a real latency criterion would care
//!   about p99, not the average (a creature that's usually fast but sometimes catastrophic).
//!
//! Operators write their own and bind it. Substrate ships only the trait + this reference (T4 / IoC).

use fitness_selector::{FitnessScorer, Observations};

/// Scores by mean latency against a ceiling (milliseconds). Construct with [`LatencyScorer::new`].
pub struct LatencyScorer {
    /// Mean latency at or above this scores `0.0`; `0` scores `1.0`; linear in between. Must be
    /// positive — a non-positive ceiling makes every score `0.0` (a degenerate config, never a panic).
    pub ceiling_ms: f64,
}

impl LatencyScorer {
    pub fn new(ceiling_ms: f64) -> Self {
        LatencyScorer { ceiling_ms }
    }
}

impl FitnessScorer for LatencyScorer {
    fn score(&self, obs: &Observations) -> f32 {
        match obs.mean_latency_ms() {
            // No latency evidence → unproven → 0.0 (never treat "no samples" as instantaneous).
            None => 0.0,
            Some(_) if self.ceiling_ms <= 0.0 => 0.0,
            Some(mean) => ((1.0 - mean / self.ceiling_ms).clamp(0.0, 1.0)) as f32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(total_ms: u64, samples: u64) -> Observations {
        Observations {
            handled: samples,
            ok: samples,
            latency_ms_total: total_ms,
            latency_samples: samples,
        }
    }

    #[test]
    fn faster_means_score_higher() {
        let s = LatencyScorer::new(100.0);
        // mean 0 → 1.0
        assert!((s.score(&obs(0, 4)) - 1.0).abs() < 1e-6);
        // mean 25 → 0.75
        assert!((s.score(&obs(100, 4)) - 0.75).abs() < 1e-6);
        // mean 100 (== ceiling) → 0.0
        assert!(s.score(&obs(100, 1)).abs() < 1e-6);
        // mean 200 (over ceiling) → clamped 0.0
        assert!(s.score(&obs(200, 1)).abs() < 1e-6);
    }

    #[test]
    fn no_samples_scores_zero() {
        let s = LatencyScorer::new(100.0);
        assert_eq!(s.score(&Observations { handled: 5, ok: 5, ..Default::default() }), 0.0);
    }

    #[test]
    fn non_positive_ceiling_is_degenerate_not_a_panic() {
        let s = LatencyScorer::new(0.0);
        assert_eq!(s.score(&obs(10, 1)), 0.0);
    }
}
