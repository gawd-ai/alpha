//! Two **reference** injected creatures that subscribe to
//! [`BudgetSignalEvent`] on the proprioception topic and decide what to do about a creature in
//! trouble with a quantitative cap.
//!
//! - [`BudgetApoptosis`] — the **simplest possible** policy: every `Hard` becomes one
//!   [`KernelControl::Unload`]; every `Warn` is observed-and-ignored. The apoptosis integration
//!   test uses this. It reads no field of `BudgetVector`.
//! - [`BudgetGraceful`] — a **richer sibling** that consults `BudgetVector` (consumed/limit
//!   ratio, dispatches_this_envelope, envelopes_since_load) to classify the creature's
//!   trajectory and decide accordingly: still always `Unload` on `Hard` (the engine trap
//!   already happened — there's nothing to recover), but on `Warn`, it grants one-shot grace
//!   via [`KernelControl::ExtendBudget`] to creatures whose trajectory says "this was useful
//!   work, the cap is just too low" and refuses grace to first-call burners. This is the
//!   real consumer of the vector + ExtendBudget behavior.
//!
//! **Neither is substrate.** Both are reference creatures, one of many possible budget responses
//! (kill, demote-tier, escalate to a human, raise-then-kill, exponential-backoff, …). Operators
//! ship their own. The fabric ships the *event* (`BudgetSignalEvent` with level/kind/vector) and
//! the *control ops* (`Unload`, `ExtendBudget`, and a creature's `BudgetRequest`), never the decision.
//!
//! **The full gradient loop is live:**
//! - The wasm engine emits `Warn` (via `budget_warn_at`), so `BudgetGraceful`'s Warn branches fire
//!   from real beast execution, not just injection.
//! - The kernel **honors** `ExtendBudget`: a granted fuel lift takes effect on the creature's next
//!   handle (the wasm tier's live fuel ceiling). So a grace grant here actually rescues a creature.
//! - `BudgetGraceful` also consumes a creature-initiated `BudgetRequest` (schema `budget_request`):
//!   it honors the first fuel ask per module (one-shot) by issuing `ExtendBudget`. The symmetric,
//!   creature-side direction of the same gradient.
//!
//! **Remaining honest limits:**
//! - `mem_bytes`/`wall_ms` `ExtendBudget` lifts are accepted by the wire but not yet honored (the
//!   wasm `StoreLimiter` isn't live-mutable); only the fuel dimension lifts today.
//! - Per-module grace state is held in a `HashMap` that only grows. A production policy would
//!   subscribe to a `module_unloaded` event and prune; we don't, because the proprioception
//!   topic does not carry that lifecycle schema yet. For a reference creature the unbounded map is
//!   acceptable.
//!
//! Wiring is identical to [`BudgetApoptosis`]: open an endpoint, subscribe
//! to `Topic::PROPRIOCEPTION`, drain the inbox into `handle`, send the resulting dispatches back
//! through the bus.

use aether::{Address, Creature, CreatureCtx, Dispatch, Envelope, LimitKind, Outcome};
use sanctum::{BudgetRequest, BudgetSignalEvent, KernelControl};
use std::collections::HashMap;

// =============================================================================================
// BudgetApoptosis — the simplest policy
// =============================================================================================

/// The simplest budget policy: every `Hard`-level `BudgetSignalEvent` becomes one `Unload`; every
/// `Warn` is ignored. Useful as the apoptosis reference; operators ship their own (graceful,
/// demoting, escalating, grace-granting) variants. See [`BudgetGraceful`] for the first such
/// richer sibling.
pub struct BudgetApoptosis;

impl BudgetApoptosis {
    pub fn new() -> Self {
        BudgetApoptosis
    }
}

impl Default for BudgetApoptosis {
    fn default() -> Self {
        BudgetApoptosis::new()
    }
}

impl Creature for BudgetApoptosis {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Fan-out delivers ALL proprioception envelopes; only ones that parse as
        // `BudgetSignalEvent` are ours. Unknown shapes (`Proprioception`, `Fitness`,
        // `BudgetRequest`) are silently ignored — every subscriber on a shared topic learns to
        // look past what isn't for it.
        let Ok(b) = serde_json::from_slice::<BudgetSignalEvent>(&env.payload) else {
            return Outcome::none();
        };
        // Policy: Hard -> unload, Warn -> ignore. A richer creature would inspect
        // `b.vector` and make a trajectory-aware decision — see [`BudgetGraceful`].
        if b.level != "hard" {
            return Outcome::none();
        }
        // Map the parsed event to the kernel's control vocabulary. Fire-and-forget: control ops
        // have no synchronous reply by design (a creature waiting on a confirmation would block
        // the bus; if a requester needs ack, it adds its own `reply_to` / `corr`).
        let op = KernelControl::Unload { module: b.module };
        let payload = match serde_json::to_vec(&op) {
            Ok(b) => b,
            Err(_) => return Outcome::none(), // serialization failure is unreachable in practice
        };
        Outcome::send(Dispatch::to(Address::Kernel, payload).with_schema("kernel_control"))
    }
}

// =============================================================================================
// BudgetGraceful — the richer sibling (Phase 2a — first real BudgetVector consumer)
// =============================================================================================

/// The trajectory classes [`BudgetGraceful`] reads out of a `BudgetVector`. Each class is a
/// rough story about what the creature was doing when it hit the limit; the decision matrix
/// uses the class to pick between unload, one-shot grace, and observe.
///
/// These are intentionally **coarse** — a substrate-shipped policy would be opinionated; an
/// reference creature stays simple enough to read. Real policies would compute smoother curves
/// (sliding-window dispatches/sec, fuel-per-dispatch slope, …) over multiple signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetTrajectory {
    /// `dispatches_this_envelope == 0`, `consumed >= limit/2`, `envelopes_since_load <= 1` —
    /// the creature did no observable work before consuming half (or more) of its cap, on a
    /// first or near-first envelope. Looks like a tight loop with no useful output.
    FirstCallBurner,

    /// `dispatches_this_envelope >= 1` — the creature produced at least one bus dispatch
    /// before/while hitting the threshold. Whatever else it was doing, there's evidence of
    /// useful work; the cap may just be too low for this workload.
    ///
    /// **Threshold rationale**: engine-emitted Warns ride alongside the creature's reply, so
    /// the kernel enriches `dispatches_this_envelope` to 1 (the reply) before publishing. A
    /// real beast-emitted productive Warn therefore arrives with exactly one dispatch — so the
    /// threshold must be `>= 1` for this classifier to fire on real engine signals, not just
    /// on manually-injected ones. Pre-engine-warn (Phase 2a) used `>= 2`, which was unreachable
    /// from real engines and only worked when tests manually crafted vectors.
    ProductiveThenTerminal { dispatches: u32 },

    /// `envelopes_since_load >= 10` and not classified above — the creature has been handling
    /// envelopes for a while; this signal smells like creep (e.g. growing internal state,
    /// memory leak) rather than a burst. Modest grace is plausible.
    SteadyClimb { envelopes: u64 },

    /// The vector's scalars don't add up to a clear story (e.g., engine couldn't measure
    /// `consumed`, vector is mostly zero). Defer to the floor: Hard unloads, Warn is ignored.
    Unclassifiable,
}

/// What [`BudgetGraceful`] decided about a single signal. `Grant` and `Observe` carry the
/// trajectory that drove the choice for post-hoc inspection (and for tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetDecision {
    /// Emit a `KernelControl::Unload { module }`. The fabric will run the unload path.
    Unload { reason: BudgetTrajectory },
    /// Emit a `KernelControl::ExtendBudget { module, .. }` with the given new caps. The
    /// kernel **honors** a fuel lift (it takes effect on the creature's next handle, wasm tier);
    /// mem/wall lifts are accepted-but-not-yet-honored. Tracked per `(module, kind)` so the same
    /// creature gets at most one grant per dimension.
    Grant { reason: BudgetTrajectory, kind: LimitKind, new_cap: u64 },
    /// Emit nothing. The fabric does not act; the creature continues (Warn) or has already
    /// trapped (Hard, but only if `Unload` was suppressed — which never happens in this
    /// policy; `Observe` only fires for `Warn`).
    Observe { reason: BudgetTrajectory },
}

/// Per-creature per-kind grace already granted. Bounded by the `(module, kind)` key set; entries
/// are only added, never removed (a production policy would prune on creature-unload events).
#[derive(Default, Debug)]
struct GraceState {
    fuel_granted: bool,
    memory_granted: bool,
    wall_granted: bool,
}

impl GraceState {
    fn is_granted(&self, kind: LimitKind) -> bool {
        match kind {
            LimitKind::Fuel => self.fuel_granted,
            LimitKind::Memory => self.memory_granted,
            LimitKind::Wall => self.wall_granted,
        }
    }
    fn mark_granted(&mut self, kind: LimitKind) {
        match kind {
            LimitKind::Fuel => self.fuel_granted = true,
            LimitKind::Memory => self.memory_granted = true,
            LimitKind::Wall => self.wall_granted = true,
        }
    }
}

/// Trajectory-aware sibling of [`BudgetApoptosis`]. Reads `BudgetVector`, classifies the
/// creature's path, and picks between `Unload` / `Grant` (`ExtendBudget`) / `Observe`. First
/// real consumer of the `vector` + `ExtendBudget` path.
///
/// **The Hard floor stays.** On `level: "hard"` the engine has already trapped the creature;
/// there is no continuation to grant. Hard → Unload regardless of trajectory; the trajectory
/// is recorded as the *reason* for inspection. Warn is where trajectory branches.
pub struct BudgetGraceful {
    /// One-shot grace tracking per `(module, kind)`. This reference never shrinks it; a production
    /// policy would subscribe to creature-unloaded lifecycle events.
    grace_granted: HashMap<u64, GraceState>,
    /// Most recent decision per module, exposed by [`Self::last_decision`] for tests /
    /// observability. Overwritten on each new signal for that module.
    last_decision: HashMap<u64, BudgetDecision>,
}

impl BudgetGraceful {
    pub fn new() -> Self {
        BudgetGraceful { grace_granted: HashMap::new(), last_decision: HashMap::new() }
    }

    /// Inspect the most recent decision this policy made for `module`. Returns `None` if no
    /// signal for that module has been processed yet. Primary use is tests / operator
    /// observability — production policies would emit a side-topic envelope.
    pub fn last_decision(&self, module: u64) -> Option<&BudgetDecision> {
        self.last_decision.get(&module)
    }

    /// The pure classifier. Reads the vector, returns the trajectory. No state read or
    /// written; testable in isolation.
    pub fn classify(vector: &aether::BudgetVector) -> BudgetTrajectory {
        // FirstCallBurner: did nothing observable, ran out fast, on a fresh handle.
        // The `limit > 0` guard avoids the dev-default (no cap declared → limit==0) from
        // matching every signal as a burner.
        if vector.dispatches_this_envelope == 0
            && vector.limit > 0
            && vector.consumed >= vector.limit / 2
            && vector.envelopes_since_load <= 1
        {
            return BudgetTrajectory::FirstCallBurner;
        }
        // SteadyClimb: long-lived (≥10 envelopes) — checked BEFORE Productive so a 10-envelopes-
        // old creature with a productive reply still classifies as SteadyClimb (the longevity is
        // the more interesting signal; grace is smaller because creep often keeps creeping).
        // Ordering matters: with Productive at `>= 1`, almost any reply would match Productive
        // first if SteadyClimb were checked after — losing the long-lived distinction entirely.
        if vector.envelopes_since_load >= 10 {
            return BudgetTrajectory::SteadyClimb { envelopes: vector.envelopes_since_load };
        }
        // ProductiveThenTerminal: ≥1 dispatch is evidence of useful work. A successful
        // engine-emitted Warn rides alongside the beast's reply (one dispatch after kernel
        // enrichment), so the threshold must be `>= 1` to be reachable from real beast
        // execution — not just manual injection.
        if vector.dispatches_this_envelope >= 1 {
            return BudgetTrajectory::ProductiveThenTerminal {
                dispatches: vector.dispatches_this_envelope,
            };
        }
        BudgetTrajectory::Unclassifiable
    }

    /// Decide what to do given a parsed signal. Mutates internal state (records the decision,
    /// marks grace as granted). Pure-ish: same inputs same output until you call it with a
    /// `Warn` that gets granted, after which the same `(module, kind)` Warn will Observe.
    fn decide(
        &mut self,
        module: u64,
        level: &str,
        kind: LimitKind,
        vector: &aether::BudgetVector,
    ) -> BudgetDecision {
        let reason = Self::classify(vector);

        // The Hard floor: engine already trapped, there's no continuation. Unload regardless
        // of trajectory; the trajectory becomes the *reason* (observable, not actionable).
        if level == "hard" {
            let d = BudgetDecision::Unload { reason };
            self.last_decision.insert(module, d.clone());
            return d;
        }

        // Warn paths — branch on trajectory + one-shot grace.
        let already_granted =
            self.grace_granted.get(&module).map(|g| g.is_granted(kind)).unwrap_or(false);

        let d = match (reason, already_granted) {
            // FirstCallBurner: refuse grace regardless of prior grants. A creature that did
            // nothing useful and ran out instantly is not a candidate for cap-lifting.
            (BudgetTrajectory::FirstCallBurner, _) => BudgetDecision::Observe { reason },

            // Unclassifiable: not enough signal — defer to the floor (Warn does nothing).
            (BudgetTrajectory::Unclassifiable, _) => BudgetDecision::Observe { reason },

            // Already granted (any productive/climb trajectory): one-shot is exhausted.
            (_, true) => BudgetDecision::Observe { reason },

            // ProductiveThenTerminal, fresh: grant 1.5× (rounded up) — the workload deserves
            // headroom and the cap looks miscalibrated.
            (BudgetTrajectory::ProductiveThenTerminal { .. }, false) => {
                let new_cap = vector.limit.saturating_add(vector.limit / 2).max(1);
                self.grace_granted.entry(module).or_default().mark_granted(kind);
                BudgetDecision::Grant { reason, kind, new_cap }
            }

            // SteadyClimb, fresh: grant a more modest 1.25× — creep often keeps creeping;
            // give the creature room to finish a unit of work but don't bless the trend.
            (BudgetTrajectory::SteadyClimb { .. }, false) => {
                let new_cap = vector.limit.saturating_add(vector.limit / 4).max(1);
                self.grace_granted.entry(module).or_default().mark_granted(kind);
                BudgetDecision::Grant { reason, kind, new_cap }
            }
        };
        self.last_decision.insert(module, d.clone());
        d
    }

    /// **Consume a creature-initiated [`BudgetRequest`].** A creature asks for more fuel;
    /// this reference honors the *first* fuel ask per module (one-shot, reusing the same `grace_granted`
    /// guard as the Warn path) so a creature can't loop-request unbounded budget, and observes the
    /// rest. A production policy would weigh `justification` against a quota / trajectory / cost
    /// model — the substrate ships the seam, never the model (IoC). Only the fuel dimension is
    /// honored (the kernel lifts fuel live; mem/wall lifts are future engine work).
    fn on_budget_request(&mut self, env: &Envelope) -> Outcome {
        let Ok(req) = serde_json::from_slice::<BudgetRequest>(&env.payload) else {
            return Outcome::none();
        };
        let Some(fuel) = req.fuel else {
            return Outcome::none(); // no fuel ask → nothing this reference acts on
        };
        let already = self
            .grace_granted
            .get(&req.module)
            .map(|g| g.is_granted(LimitKind::Fuel))
            .unwrap_or(false);
        if already {
            self.last_decision.insert(
                req.module,
                BudgetDecision::Observe { reason: BudgetTrajectory::Unclassifiable },
            );
            return Outcome::none(); // one-shot exhausted — a creature can't keep asking for more
        }
        self.grace_granted.entry(req.module).or_default().mark_granted(LimitKind::Fuel);
        self.last_decision.insert(
            req.module,
            BudgetDecision::Grant {
                reason: BudgetTrajectory::Unclassifiable,
                kind: LimitKind::Fuel,
                new_cap: fuel,
            },
        );
        let op = KernelControl::ExtendBudget {
            module: req.module,
            fuel: Some(fuel),
            mem_bytes: None,
            wall_ms: None,
        };
        let Ok(payload) = serde_json::to_vec(&op) else { return Outcome::none() };
        Outcome::send(Dispatch::to(Address::Kernel, payload).with_schema("kernel_control"))
    }
}

impl Default for BudgetGraceful {
    fn default() -> Self {
        BudgetGraceful::new()
    }
}

impl Creature for BudgetGraceful {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // **The creature-initiated grace ask (`BudgetRequest`).** A creature that knows
        // it will need more than its declared cap publishes a `BudgetRequest` on PROPRIOCEPTION
        // (schema `budget_request`); this policy weighs it and may grant `ExtendBudget`. The
        // *symmetric* direction to the Warn path below (which is *engine*-initiated). Now that the
        // kernel honors `ExtendBudget`, both directions are real.
        if env.header.schema == "budget_request" {
            return self.on_budget_request(&env);
        }
        // Same parse-or-pass-through discipline as BudgetApoptosis — fan-out delivers
        // everything on PROPRIOCEPTION; only BudgetSignalEvent shapes are ours.
        let Ok(b) = serde_json::from_slice::<BudgetSignalEvent>(&env.payload) else {
            return Outcome::none();
        };

        // Parse the kind string back to LimitKind. The fabric ships strings on the wire
        // (looser coupling for cross-language subscribers); we re-tighten to the enum here.
        // An unknown kind (a future engine using a kind we don't recognize) is Observe-only.
        let kind = match b.kind.as_str() {
            "fuel" => LimitKind::Fuel,
            "memory" => LimitKind::Memory,
            "wall" => LimitKind::Wall,
            _ => {
                self.last_decision.insert(
                    b.module,
                    BudgetDecision::Observe { reason: BudgetTrajectory::Unclassifiable },
                );
                return Outcome::none();
            }
        };

        let decision = self.decide(b.module, &b.level, kind, &b.vector);

        match decision {
            BudgetDecision::Unload { .. } => {
                let op = KernelControl::Unload { module: b.module };
                let Ok(payload) = serde_json::to_vec(&op) else { return Outcome::none() };
                Outcome::send(Dispatch::to(Address::Kernel, payload).with_schema("kernel_control"))
            }
            BudgetDecision::Grant { kind, new_cap, .. } => {
                // Fill only the dimension that fired; other fields stay None (leave untouched).
                let op = match kind {
                    LimitKind::Fuel => KernelControl::ExtendBudget {
                        module: b.module,
                        fuel: Some(new_cap),
                        mem_bytes: None,
                        wall_ms: None,
                    },
                    LimitKind::Memory => KernelControl::ExtendBudget {
                        module: b.module,
                        fuel: None,
                        mem_bytes: Some(new_cap),
                        wall_ms: None,
                    },
                    LimitKind::Wall => KernelControl::ExtendBudget {
                        module: b.module,
                        fuel: None,
                        mem_bytes: None,
                        wall_ms: Some(new_cap),
                    },
                };
                let Ok(payload) = serde_json::to_vec(&op) else { return Outcome::none() };
                Outcome::send(Dispatch::to(Address::Kernel, payload).with_schema("kernel_control"))
            }
            BudgetDecision::Observe { .. } => Outcome::none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{BudgetVector, CreatureId, Header};

    fn proprio_env(payload: &[u8]) -> Envelope {
        Envelope {
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
            payload: payload.to_vec(),
        }
    }

    fn event(module: u64, level: &str, kind: &str, vector: BudgetVector) -> Vec<u8> {
        serde_json::to_vec(&BudgetSignalEvent {
            module,
            level: level.into(),
            kind: kind.into(),
            vector,
        })
        .unwrap()
    }

    /// A `budget_request`-schema envelope carrying a creature's grace ask (creature side).
    fn request_env(module: u64, fuel: Option<u64>) -> Envelope {
        let mut e = proprio_env(
            &serde_json::to_vec(&BudgetRequest {
                module,
                fuel,
                mem_bytes: None,
                wall_ms: None,
                justification: "needs headroom for a big payload".into(),
            })
            .unwrap(),
        );
        e.header.schema = "budget_request".into();
        e
    }

    #[test]
    fn graceful_honors_a_creatures_first_fuel_request_then_observes_repeats() {
        // Creature-initiated direction: a BudgetRequest for fuel becomes an ExtendBudget…
        let mut p = BudgetGraceful::new();
        let out = p.handle(request_env(7, Some(2_500)));
        assert_eq!(out.dispatches.len(), 1, "first fuel request is granted");
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Kernel);
        match serde_json::from_slice::<KernelControl>(&d.payload).unwrap() {
            KernelControl::ExtendBudget { module, fuel, .. } => {
                assert_eq!(module, 7);
                assert_eq!(fuel, Some(2_500), "honors the requested fuel");
            }
            other => panic!("expected ExtendBudget, got {other:?}"),
        }
        // …but one-shot: a second ask for the same module is observed, not granted (no loop-begging).
        let out2 = p.handle(request_env(7, Some(9_999)));
        assert!(out2.dispatches.is_empty(), "the one-shot grace is exhausted");
        assert!(matches!(p.last_decision(7), Some(BudgetDecision::Observe { .. })));
    }

    #[test]
    fn graceful_ignores_a_request_with_no_fuel_ask() {
        let mut p = BudgetGraceful::new();
        assert!(p.handle(request_env(7, None)).dispatches.is_empty());
    }

    #[test]
    fn graceful_does_not_panic_on_a_malformed_budget_request() {
        let mut p = BudgetGraceful::new();
        let mut e = proprio_env(b"{not json");
        e.header.schema = "budget_request".into();
        assert!(p.handle(e).dispatches.is_empty());
    }

    // -----------------------------------------------------------------------------------------
    // BudgetApoptosis — unchanged tests
    // -----------------------------------------------------------------------------------------

    fn hard_fuel_event(module: u64) -> Vec<u8> {
        event(module, "hard", "fuel", BudgetVector::default())
    }

    #[test]
    fn apoptosis_hard_signal_becomes_one_unload_addressed_to_the_kernel() {
        let mut p = BudgetApoptosis::new();
        let out = p.handle(proprio_env(&hard_fuel_event(7)));
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Kernel);
        let op: KernelControl = serde_json::from_slice(&d.payload).unwrap();
        match op {
            KernelControl::Unload { module } => assert_eq!(module, 7),
            other => panic!("expected Unload, got {other:?}"),
        }
    }

    /// Warn signals are observed-and-ignored by this reference. A
    /// richer creature would compute its own trajectory model and emit either `ExtendBudget` or
    /// `Unload` based on the vector; the simplest possible policy stays simple.
    #[test]
    fn apoptosis_warn_signal_is_observed_and_ignored() {
        let mut p = BudgetApoptosis::new();
        let warn = event(42, "warn", "fuel", BudgetVector::default());
        assert!(p.handle(proprio_env(&warn)).dispatches.is_empty());
    }

    #[test]
    fn apoptosis_unrelated_proprio_events_pass_through_as_no_op() {
        let mut p = BudgetApoptosis::new();
        // A `Proprioception { module, event }` payload has a different shape than
        // `BudgetSignalEvent`; the parse should fail and we should emit nothing.
        let other =
            serde_json::to_vec(&sanctum::Proprioception { module: 1, event: "loaded".into() })
                .unwrap();
        assert!(p.handle(proprio_env(&other)).dispatches.is_empty());
    }

    // -----------------------------------------------------------------------------------------
    // BudgetGraceful — classifier (pure, state-free)
    // -----------------------------------------------------------------------------------------

    #[test]
    fn classifier_recognizes_first_call_burner() {
        // dispatches_this_envelope == 0, consumed >= limit/2, envelopes_since_load <= 1
        let v = BudgetVector {
            consumed: 600,
            limit: 1000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 5,
            envelopes_since_load: 1,
        };
        assert_eq!(BudgetGraceful::classify(&v), BudgetTrajectory::FirstCallBurner);
    }

    #[test]
    fn classifier_does_not_call_burner_when_limit_is_zero_m0_default() {
        // Dev default: no cap declared → limit == 0. The fabric ships consumed >= 0, but
        // we must not classify this as a burner (zero >= zero/2 = 0 is trivially true).
        let v = BudgetVector {
            consumed: 100,
            limit: 0,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 0,
            envelopes_since_load: 1,
        };
        assert_eq!(BudgetGraceful::classify(&v), BudgetTrajectory::Unclassifiable);
    }

    #[test]
    fn classifier_recognizes_productive_then_terminal() {
        let v = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        };
        assert_eq!(
            BudgetGraceful::classify(&v),
            BudgetTrajectory::ProductiveThenTerminal { dispatches: 5 }
        );
    }

    /// **The threshold that matters for real engine-emitted Warns.** The kernel enriches
    /// `dispatches_this_envelope` from `outcome.dispatches.len()` before publishing, so a
    /// beast that replied + warned arrives with exactly one dispatch. The classifier must
    /// fire on `>= 1` for the productive grace path to be reachable from real execution.
    #[test]
    fn classifier_productive_fires_on_one_dispatch_the_real_engine_warn_case() {
        let v = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 1, // the realistic engine-emitted-Warn case
            wall_ms_elapsed: 50,
            envelopes_since_load: 1,
        };
        assert_eq!(
            BudgetGraceful::classify(&v),
            BudgetTrajectory::ProductiveThenTerminal { dispatches: 1 }
        );
    }

    #[test]
    fn classifier_recognizes_steady_climb_on_long_lived_creature() {
        let v = BudgetVector {
            consumed: 800,
            limit: 1000,
            dispatches_this_envelope: 1,
            wall_ms_elapsed: 10,
            envelopes_since_load: 42,
        };
        assert_eq!(BudgetGraceful::classify(&v), BudgetTrajectory::SteadyClimb { envelopes: 42 });
    }

    #[test]
    fn classifier_falls_through_to_unclassifiable_when_nothing_fires() {
        // Young (<10 envelopes), silent (no dispatch), low consumption (not a burner). A quiet
        // new creature with weak signal — the floor classification.
        let v = BudgetVector {
            consumed: 100,
            limit: 1000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 0,
            envelopes_since_load: 2,
        };
        assert_eq!(BudgetGraceful::classify(&v), BudgetTrajectory::Unclassifiable);
    }

    // -----------------------------------------------------------------------------------------
    // BudgetGraceful — Hard floor (engine trap already happened)
    // -----------------------------------------------------------------------------------------

    #[test]
    fn graceful_hard_always_unloads_regardless_of_trajectory() {
        // A productive trajectory does NOT save a Hard signal — the engine already trapped.
        let mut p = BudgetGraceful::new();
        let productive = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        };
        let out = p.handle(proprio_env(&event(7, "hard", "fuel", productive)));
        assert_eq!(out.dispatches.len(), 1, "Hard always emits one Unload");
        let op: KernelControl = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        assert!(matches!(op, KernelControl::Unload { module: 7 }));
        // The decision is recorded with the productive reason for observability.
        assert!(matches!(
            p.last_decision(7),
            Some(BudgetDecision::Unload {
                reason: BudgetTrajectory::ProductiveThenTerminal { .. }
            })
        ));
    }

    #[test]
    fn graceful_hard_with_burner_trajectory_unloads_with_burner_reason() {
        let mut p = BudgetGraceful::new();
        let burner = BudgetVector {
            consumed: 600,
            limit: 1000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 5,
            envelopes_since_load: 1,
        };
        p.handle(proprio_env(&event(9, "hard", "fuel", burner)));
        assert!(matches!(
            p.last_decision(9),
            Some(BudgetDecision::Unload { reason: BudgetTrajectory::FirstCallBurner })
        ));
    }

    // -----------------------------------------------------------------------------------------
    // BudgetGraceful — Warn branches (trajectory-aware)
    // -----------------------------------------------------------------------------------------

    #[test]
    fn graceful_warn_burner_refuses_grace_and_observes() {
        let mut p = BudgetGraceful::new();
        let burner = BudgetVector {
            consumed: 600,
            limit: 1000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 5,
            envelopes_since_load: 1,
        };
        let out = p.handle(proprio_env(&event(3, "warn", "fuel", burner)));
        assert!(out.dispatches.is_empty(), "burner gets no grace");
        assert!(matches!(
            p.last_decision(3),
            Some(BudgetDecision::Observe { reason: BudgetTrajectory::FirstCallBurner })
        ));
    }

    #[test]
    fn graceful_warn_productive_grants_one_shot_extend_budget_at_1_5x_fuel() {
        let mut p = BudgetGraceful::new();
        let productive = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        };
        let out = p.handle(proprio_env(&event(11, "warn", "fuel", productive)));
        assert_eq!(out.dispatches.len(), 1, "productive Warn grants grace");
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Kernel);
        let op: KernelControl = serde_json::from_slice(&d.payload).unwrap();
        match op {
            KernelControl::ExtendBudget { module, fuel, mem_bytes, wall_ms } => {
                assert_eq!(module, 11);
                assert_eq!(fuel, Some(15_000), "1.5× the 10_000 limit on the kind that fired");
                assert!(mem_bytes.is_none(), "only the kind that fired is filled");
                assert!(wall_ms.is_none());
            }
            other => panic!("expected ExtendBudget, got {other:?}"),
        }
        assert!(matches!(
            p.last_decision(11),
            Some(BudgetDecision::Grant {
                kind: LimitKind::Fuel,
                new_cap: 15_000,
                reason: BudgetTrajectory::ProductiveThenTerminal { .. }
            })
        ));
    }

    #[test]
    fn graceful_warn_productive_second_time_observes_grace_already_used() {
        let mut p = BudgetGraceful::new();
        let productive = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        };
        // First Warn: grants grace.
        let first = p.handle(proprio_env(&event(11, "warn", "fuel", productive)));
        assert_eq!(first.dispatches.len(), 1);
        // Second Warn on same (module, kind): grace already used → Observe, no dispatches.
        let second = p.handle(proprio_env(&event(11, "warn", "fuel", productive)));
        assert!(second.dispatches.is_empty(), "one-shot grace per (module, kind)");
        assert!(matches!(
            p.last_decision(11),
            Some(BudgetDecision::Observe {
                reason: BudgetTrajectory::ProductiveThenTerminal { .. }
            })
        ));
    }

    #[test]
    fn graceful_warn_grace_is_per_kind_not_per_module() {
        let mut p = BudgetGraceful::new();
        let productive = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        };
        // Grant fuel grace.
        let fuel_grant = p.handle(proprio_env(&event(11, "warn", "fuel", productive)));
        assert_eq!(fuel_grant.dispatches.len(), 1);
        // A Warn on memory for the same module is a fresh grant.
        let mem_grant = p.handle(proprio_env(&event(11, "warn", "memory", productive)));
        assert_eq!(mem_grant.dispatches.len(), 1, "memory grace is independent of fuel grace");
        let op: KernelControl = serde_json::from_slice(&mem_grant.dispatches[0].payload).unwrap();
        match op {
            KernelControl::ExtendBudget { mem_bytes, fuel, .. } => {
                assert_eq!(mem_bytes, Some(15_000));
                assert!(fuel.is_none(), "only the kind that fired is filled");
            }
            other => panic!("expected ExtendBudget, got {other:?}"),
        }
    }

    #[test]
    fn graceful_warn_steady_climb_grants_smaller_1_25x() {
        let mut p = BudgetGraceful::new();
        let climb = BudgetVector {
            consumed: 800,
            limit: 1000,
            dispatches_this_envelope: 1,
            wall_ms_elapsed: 10,
            envelopes_since_load: 42,
        };
        let out = p.handle(proprio_env(&event(99, "warn", "memory", climb)));
        assert_eq!(out.dispatches.len(), 1);
        let op: KernelControl = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match op {
            KernelControl::ExtendBudget { mem_bytes, .. } => {
                assert_eq!(mem_bytes, Some(1250), "1.25× of 1000 on the kind that fired");
            }
            other => panic!("expected ExtendBudget, got {other:?}"),
        }
    }

    #[test]
    fn graceful_warn_unclassifiable_observes() {
        let mut p = BudgetGraceful::new();
        // Young, silent, low consumption — Unclassifiable (no dispatches, not a burner, not
        // long-lived). Warn under this trajectory observes; the policy has too little signal
        // to commit to grace.
        let weak = BudgetVector {
            consumed: 100,
            limit: 1000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 0,
            envelopes_since_load: 2,
        };
        let out = p.handle(proprio_env(&event(5, "warn", "fuel", weak)));
        assert!(out.dispatches.is_empty());
        assert!(matches!(
            p.last_decision(5),
            Some(BudgetDecision::Observe { reason: BudgetTrajectory::Unclassifiable })
        ));
    }

    // -----------------------------------------------------------------------------------------
    // BudgetGraceful — edge cases
    // -----------------------------------------------------------------------------------------

    #[test]
    fn graceful_ignores_unknown_kind_strings() {
        // A future engine might publish a kind we don't recognize. We must not crash; we must
        // not emit anything actionable — record as Observe/Unclassifiable.
        let mut p = BudgetGraceful::new();
        let out = p.handle(proprio_env(&event(1, "warn", "future-kind", BudgetVector::default())));
        assert!(out.dispatches.is_empty());
        assert!(matches!(
            p.last_decision(1),
            Some(BudgetDecision::Observe { reason: BudgetTrajectory::Unclassifiable })
        ));
    }

    #[test]
    fn graceful_unrelated_proprio_events_pass_through_as_no_op() {
        let mut p = BudgetGraceful::new();
        let other =
            serde_json::to_vec(&sanctum::Proprioception { module: 1, event: "loaded".into() })
                .unwrap();
        assert!(p.handle(proprio_env(&other)).dispatches.is_empty());
        // No decision recorded because no BudgetSignalEvent parsed.
        assert!(p.last_decision(1).is_none());
    }

    #[test]
    fn graceful_extend_budget_payload_passes_kernel_control_serde() {
        // A round-trip discipline check: the payload we emit must serde-parse as the same
        // KernelControl variant on the kernel side. Caught here in unit form so a serde-tag
        // mismatch never bypasses the wiring tests.
        let mut p = BudgetGraceful::new();
        let productive = BudgetVector {
            consumed: 9000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        };
        let out = p.handle(proprio_env(&event(7, "warn", "fuel", productive)));
        let raw = &out.dispatches[0].payload;
        // Verifies serde_json::Value round-trip works too (tag-discipline check).
        let v: serde_json::Value = serde_json::from_slice(raw).unwrap();
        assert_eq!(v.get("op").and_then(|s| s.as_str()), Some("ExtendBudget"));
        assert_eq!(v.get("module").and_then(|n| n.as_u64()), Some(7));
        assert_eq!(v.get("fuel").and_then(|n| n.as_u64()), Some(15_000));
    }
}
