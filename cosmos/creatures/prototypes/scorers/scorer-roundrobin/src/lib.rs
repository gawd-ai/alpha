//! `RoundRobinScorer` — a **reference** injected [`FitnessScorer`] that scores every creature with
//! at least one handled envelope at `1.0` (alive = fit), everything else `0.0`.
//!
//! The non-discriminating reference, sibling to `cosmos/creatures/prototypes/reputation/reputation-roundrobin`'s `UnitWeigher`
//! and `cosmos/creatures/prototypes/distributors/distributor-roundrobin`: it makes the *plumbing* observable (a `Tick` promotes
//! every live watched creature) without expressing a real preference. It exists so the selection loop can
//! be exercised end-to-end with a criterion that has no opinion — proving the substrate enforces no
//! selection of its own; the *model* does (T7). With this scorer bound, "selection" degenerates to
//! "promote whatever is alive," which is exactly the wrong production policy — and that's the point:
//! the contrast with a real `SuccessRateScorer` shows the criterion is the operator's, never the
//! fabric's.
//!
//! **NEVER appropriate as a production criterion** — it promotes every creature that has done
//! anything, fit or not. Operators write a real one and bind it.

use fitness_selector::{FitnessScorer, Observations};

/// Scores `1.0` if the creature has handled anything, else `0.0`.
pub struct RoundRobinScorer;

impl FitnessScorer for RoundRobinScorer {
    fn score(&self, obs: &Observations) -> f32 {
        if obs.handled > 0 {
            1.0
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alive_is_fit_idle_is_not() {
        let s = RoundRobinScorer;
        assert_eq!(s.score(&Observations::default()), 0.0);
        assert_eq!(s.score(&Observations { handled: 1, ok: 0, ..Default::default() }), 1.0);
        assert_eq!(s.score(&Observations { handled: 9, ok: 9, ..Default::default() }), 1.0);
    }
}
