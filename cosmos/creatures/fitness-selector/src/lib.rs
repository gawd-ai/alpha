//! `fitness-selector` — the keystone creature for the operating model's **Loop 2 (author → select
//! → promote)**.
//!
//! The substrate carries the *shape* of selection: the kernel emits a per-handle fitness signal on
//! [`Topic::FITNESS`](aether::Topic::FITNESS), and the registry has a signed, content-addressed
//! reputation slot ([`registry_mem::ReputationScore`]). This creature closes the loop: it
//! aggregates the fitness signal per watched creature, scores each by an **injected** criterion,
//! and writes a **signed, self-verifying promotion** onto the registry. Selection pressure becomes
//! real, while the *criterion* stays the operator's (T4 / IoC).
//!
//! ## What it does
//!
//! Bound to [`Role::FITNESS_SELECTOR`](aether::Role::FITNESS_SELECTOR), one selector per Sanctum
//! holds a **watch map** ([`CreatureId`] → `(realm, artifact_hash)`) and a per-module
//! [`Observations`] tally, and exposes four operator ops + consumes the kernel's fitness signal:
//!
//! - `Watch { module, realm, artifact_hash }` — register the registry key a creature's fitness
//!   should be promoted *to*. **Required**: a fitness event names only the numeric [`CreatureId`],
//!   never the content address (the kernel can't — see the watch-map rationale below).
//! - kernel `Fitness { module, ok }` events (schema `"fitness"`) — each increments
//!   `handled` (and `ok` if the handle was useful) for that module.
//! - `Observe { module, ok, latency_ms? }` *(operator op)* — inject an observation directly. The
//!   only path that can feed **latency** (the kernel's fitness event carries `ok` but no timing),
//!   and the path an operator uses for a fully synthetic feed (a load test, a replayed trace).
//! - `Tick` — evaluate every *watched* creature that has observations: compute
//!   `scorer.score(&obs)`; if it's finite and `>= threshold`, **sign the promotion claim**
//!   (`artifact_hash + realm + score + attesting_realm`) with this selector's Abode key and write
//!   [`RegistryOp::AttestFitness`] onto the local registry. Reply `Ticked { evaluated, promoted }`.
//! - `StatusQuery` — read-only dump of the watch count, per-module observation summary, threshold.
//!
//! **No automatic eviction.** A score *below* threshold simply isn't promoted — the selector never
//! unloads, quarantines, or retires anything. Retiring the unfit is a *defense* signal (a different
//! observation — budget breach, fault, leak), and that is the immune-response creature, bound to
//! a different role. Keeping promotion and defense separate is deliberate: selection rewards; the
//! immune system punishes; conflating them would let a slow creature look like a hostile one.
//!
//! ## Why the promotion is signed (the Baldwin effect, made heritable)
//!
//! A bare score on the registry is an *assertion*: anyone who can write the registry could claim
//! any creature is fit. The selector makes a promotion a **checkable fact** instead. It signs the
//! promotion claim with its Abode key; the stored [`registry_mem::ReputationScore`] carries
//! `signed_by` + `signature`; an admission policy (`cosmos/creatures/prototypes/policies/policy-prefer-promoted`) re-derives
//! the claim from the entry key + score and verifies the signature before crediting it. A learned
//! score thus travels as a signed, verifiable fact — heredity. The shared payload shape
//! lives in `registry-mem` (the *mechanism*); *which key to trust* stays the policy's (the
//! *model*) — IoC to the end.
//!
//! ## Why a watch map (and not a kernel field)
//!
//! The kernel's `Fitness` event carries only the numeric [`CreatureId`] — never the
//! content address — because the kernel is model-free: it senses "module N handled an envelope
//! (usefully or not)" and ships that fact, nothing about *which artifact* N was loaded from or
//! *which Realm* it belongs to. Resolving `CreatureId → (realm, artifact_hash)` is an operator
//! concern (the operator loaded N from a known artifact), so it's an operator-populated watch map,
//! not a new kernel field. Kernel scope creep is forbidden; this honors it.
//!
//! ## The anti-feedback truth (why the selector must NOT subscribe to FITNESS)
//!
//! The kernel publishes a `Fitness { module, ok }` event after **every** creature handles an
//! envelope — *including the selector itself*. So a drain-thread creature that subscribed directly
//! to [`Topic::FITNESS`](aether::Topic::FITNESS) would feed on its own fitness events: handling one
//! fitness envelope makes the kernel publish a new fitness event *for the selector*, which the
//! selector then receives and handles, publishing another — a perpetual 1-in-1-out livelock (not
//! exponential, but never idle). **The selector therefore is fed by direct addressing, never by a
//! topic subscription.** An operator who wants automatic feeding wires a *passive* relay — a bare
//! `Kernel::open_endpoint` consumer with **no drain thread** (so it generates no
//! fitness events of its own) — that subscribes to FITNESS and re-addresses each *watched* module's
//! event to the selector as a `"fitness"`-schema [`Address::Creature`] envelope. The selector's
//! integration test demonstrates exactly this relay. As defense-in-depth the selector also drops
//! any fitness event for its own [`CreatureId`] (`FitnessSelector::on_fitness`), so a mis-wiring
//! degrades to a dropped event rather than a spin.
//!
//! ## Fabric-not-model preserved (T4 / T7)
//!
//! The selector is a *creature* the operator binds to `Role::FITNESS_SELECTOR` — never substrate.
//! It ships **no** [`FitnessScorer`]; the three references (`cosmos/creatures/prototypes/scorers/scorer-success-rate`,
//! `scorer-latency`, `scorer-roundrobin`) are creatures like any other. What counts as "fit," and
//! the promotion threshold, are the operator's model. The substrate ships the fitness *signal*, the
//! registry *slot*, the signing *payload shape*, and this *socket* — and judges none of them.

use std::collections::HashMap;

use aether::{Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome, RealmId};
use registry_mem::{RegistryOp, ReputationScore};
use serde::{Deserialize, Serialize};
use sigil::Ed25519KeyMaterial;

/// Wire schema for the selector's own control ops + replies. Single schema + a `kind`-tagged enum,
/// same convention as `abode-migrator` / `omega-federator` / `distributor-requirements`.
pub const SCHEMA: &str = "fitness.selector";

/// The schema the kernel publishes its per-handle fitness event under (see `sanctum`'s
/// `publish_fitness`). The selector matches inbound envelopes on this so a relay can forward a raw
/// kernel fitness event to it verbatim. Mirrors the wire shape of `sanctum::Fitness`
/// (`{"module":u64,"ok":bool}`) without depending on the kernel crate (modules never depend on the
/// kernel — the crate-layout rule); the integration test pins the shape by driving
/// real kernel fitness events through the selector, so a drift in the kernel's event breaks the
/// test rather than silently mis-parsing.
pub const FITNESS_EVENT_SCHEMA: &str = "fitness";

/// The registry op schema — what the selector writes its promotions under (matches the literal
/// `registry-mem` reads on every op).
const REGISTRY_OP_SCHEMA: &str = "registry.op";

// ===================================================================================================
// Observations — the per-creature tally the injected scorer reads
// ===================================================================================================

/// A running tally of one creature's observed fitness. The selector accumulates these from the
/// kernel's fitness signal (`handled` / `ok`) and from operator `Observe` ops (which can also carry
/// `latency_ms`). All fields are integer counters — no float state, so the tally is exact and
/// `Eq`. The injected [`FitnessScorer`] turns this into a score; the substrate never interprets it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observations {
    /// Total envelopes this creature was observed handling.
    pub handled: u64,
    /// Of those, how many were "useful" (the kernel's `Fitness.ok`, or an `Observe { ok: true }`).
    pub ok: u64,
    /// Sum of observed handle latencies, milliseconds. Only `Observe { latency_ms: Some(_) }` feeds
    /// this — the kernel's fitness event carries no timing.
    pub latency_ms_total: u64,
    /// How many observations carried a latency sample (the denominator for [`Self::mean_latency_ms`]).
    pub latency_samples: u64,
}

impl Observations {
    /// `ok / handled` in `[0.0, 1.0]`; `0.0` when nothing has been handled (a creature with no
    /// observations is not "100% successful" — it's unproven, which scores as zero).
    pub fn success_rate(&self) -> f32 {
        if self.handled == 0 {
            0.0
        } else {
            self.ok as f32 / self.handled as f32
        }
    }

    /// Mean observed latency in ms, or `None` when no observation carried a latency sample. A
    /// latency-based scorer reads `None` as "no evidence" (scores zero), never as "instantaneous."
    pub fn mean_latency_ms(&self) -> Option<f64> {
        if self.latency_samples == 0 {
            None
        } else {
            Some(self.latency_ms_total as f64 / self.latency_samples as f64)
        }
    }
}

// ===================================================================================================
// Injected fitness criterion (IoC / T4)
// ===================================================================================================

/// What counts as "fit" — the **injected** selection criterion. The substrate ships none;
/// `cosmos/creatures/prototypes/scorers/scorer-success-rate`, `scorer-latency`, and `scorer-roundrobin` are references.
/// Operators write their own (windowed averages, latency-vs-throughput tradeoffs, cost-weighted
/// fitness, peer-comparative percentiles) and bind it.
///
/// Returns a score; the reference scorers use `[0.0, 1.0]`, but the selector stores whatever it's
/// told (the threshold is in the same units). The selector guards a **non-finite** score before it
/// reaches the registry (the scorer is operator code — untrusted output, R9), so a buggy scorer
/// can't poison a reputation slot the way a buggy weigher could.
pub trait FitnessScorer: Send + Sync {
    fn score(&self, obs: &Observations) -> f32;
}

// ===================================================================================================
// The kernel fitness event (deserialize-only mirror — no kernel dependency)
// ===================================================================================================

/// Deserialize mirror of the kernel's `Fitness` event (`sanctum::Fitness`). Modules don't depend on
/// the kernel crate, so the selector mirrors the wire shape rather than importing the type.
#[derive(Clone, Debug, Deserialize)]
struct FitnessEvent {
    module: u64,
    ok: bool,
}

// ===================================================================================================
// Control / reply messages (schema = SCHEMA)
// ===================================================================================================

/// One per-module observation summary for a [`SelectorMsg::StatusReply`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatureObservation {
    pub module: u64,
    pub handled: u64,
    pub ok: u64,
    pub latency_samples: u64,
}

/// Every selector message on [`SCHEMA`]: operator control ops + the selector's replies.
///
/// Forward-compat: new variants at the END are additive; reordering/renaming is a wire break (same
/// discipline as the other creatures' tagged enums).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SelectorMsg {
    // ----- operator → selector (control plane) -----
    /// Register the registry key a creature's fitness promotes to. `module` is the numeric
    /// [`CreatureId`] the kernel's fitness event names; `(realm, artifact_hash)` is the registry key
    /// the operator knows it was loaded from.
    Watch { module: u64, realm: RealmId, artifact_hash: String },
    /// Inject an observation directly. The only path that feeds latency; also the synthetic-feed
    /// path (load test / replayed trace). `latency_ms` elides from the wire when `None`.
    Observe {
        module: u64,
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        latency_ms: Option<u64>,
    },
    /// Evaluate every watched creature with observations; promote those at/over threshold.
    Tick,
    /// Read-only dump of the selector's view.
    StatusQuery,

    // ----- selector → operator (replies) -----
    /// Acknowledges a [`Watch`](Self::Watch).
    Watching { module: u64 },
    /// The result of a [`Tick`](Self::Tick): how many watched creatures were evaluated (had
    /// observations) and which were promoted (sorted [`CreatureId`] values for a deterministic reply).
    Ticked { evaluated: usize, promoted: Vec<u64> },
    /// The result of a [`StatusQuery`](Self::StatusQuery).
    StatusReply { watched: usize, observations: Vec<CreatureObservation>, threshold: f32 },
    /// A control op was rejected before any work.
    Rejected { reason: String },
}

impl SelectorMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ===================================================================================================
// The selector
// ===================================================================================================

/// Construction config — the operator wires this before `Kernel::load_instance`.
pub struct SelectorConfig {
    /// The Realm this selector promotes into (tagged as `attesting_realm` on every promotion, and
    /// bound into the signed claim so a signature can't be replayed across Realms).
    pub self_realm: RealmId,
    /// The local `registry-mem` creature id — where promotions land.
    pub local_registry: CreatureId,
    /// This selector's Abode authorship key — signs every promotion (the heredity signature).
    pub abode_key: Ed25519KeyMaterial,
    /// Promote a watched creature only when its score is `>= threshold`. In the injected scorer's
    /// units (the reference scorers use `[0.0, 1.0]`).
    pub threshold: f32,
    /// The injected fitness criterion. Substrate ships none (T4).
    pub scorer: Box<dyn FitnessScorer>,
}

/// The fitness-selector creature.
pub struct FitnessSelector {
    cfg: SelectorConfig,
    /// Cache of `cfg.abode_key.public_hex()` — the `signed_by` stamped on every promotion.
    pubkey: String,
    me: Option<CreatureId>,
    /// `CreatureId → (realm, artifact_hash)` — the operator-populated resolution of a fitness event's
    /// numeric creature id to a registry key.
    watch: HashMap<CreatureId, (RealmId, String)>,
    /// `CreatureId → running tally`. Accumulates for every non-self module observed; `Tick` only
    /// promotes *watched* ones, so an observation can arrive before its `Watch`.
    obs: HashMap<CreatureId, Observations>,
    /// Maximum number of distinct observed creatures tallied at once. A spray of fitness events for
    /// ever-new creature ids would otherwise grow `obs` without bound. At capacity an observation for
    /// a *new* creature is dropped (tallies for already-tracked creatures always update). **`0` means
    /// unbounded** (the default; preserves prior behavior). Set via [`FitnessSelector::with_max_obs`].
    max_obs: usize,
}

impl FitnessSelector {
    pub fn new(cfg: SelectorConfig) -> Self {
        let pubkey = cfg.abode_key.public_hex().to_string();
        FitnessSelector {
            cfg,
            pubkey,
            me: None,
            watch: HashMap::new(),
            obs: HashMap::new(),
            max_obs: 0,
        }
    }

    /// Cap the number of distinct observed modules tracked (resilience guardrail; default `0` =
    /// unbounded). At capacity an observation for a *new* module is dropped rather than growing the
    /// tally map without bound; already-tracked modules keep accumulating.
    pub fn with_max_obs(mut self, max_obs: usize) -> Self {
        self.max_obs = max_obs;
        self
    }

    /// Return a mutable tally for `mid`, creating it only if under the `max_obs` cap. Returns `None`
    /// when the cap is reached and `mid` is not already tracked (the caller drops the observation).
    fn obs_entry_capped(&mut self, mid: CreatureId) -> Option<&mut Observations> {
        if self.max_obs != 0 && self.obs.len() >= self.max_obs && !self.obs.contains_key(&mid) {
            eprintln!(
                "fitness-selector: observation map at capacity ({}); dropping observation for new module {}",
                self.max_obs, mid.0
            );
            return None;
        }
        Some(self.obs.entry(mid).or_default())
    }

    /// Seed a watch entry at construction (tests / an operator who knows the map up front).
    pub fn watching(
        mut self,
        module: CreatureId,
        realm: RealmId,
        artifact_hash: impl Into<String>,
    ) -> Self {
        self.watch.insert(module, (realm, artifact_hash.into()));
        self
    }

    /// How many creatures are watched.
    pub fn watched_count(&self) -> usize {
        self.watch.len()
    }

    /// Read-only accessor for tests + introspection.
    pub fn observations(&self, module: CreatureId) -> Option<&Observations> {
        self.obs.get(&module)
    }

    fn me_id(&self) -> Option<CreatureId> {
        self.me
    }
}

impl Creature for FitnessSelector {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        match env.header.schema.as_str() {
            // A kernel fitness event (relayed to us — never via a topic subscription; see module docs).
            FITNESS_EVENT_SCHEMA => self.on_fitness(&env),
            // Our own control plane.
            SCHEMA => self.on_control(&env),
            // Misbind / stray — never crash (R9).
            _ => Outcome::none(),
        }
    }
}

impl FitnessSelector {
    // ----- fitness signal ingest ---------------------------------------------------------------

    fn on_fitness(&mut self, env: &Envelope) -> Outcome {
        let Ok(ev) = serde_json::from_slice::<FitnessEvent>(&env.payload) else {
            return Outcome::none(); // R9: malformed event → drop, never panic.
        };
        let mid = CreatureId(ev.module);
        // Anti-feedback (see module docs): never aggregate our own fitness. Defense-in-depth — the
        // correct wiring is a passive relay that never forwards our id, but a mis-wiring degrades to
        // a dropped event here rather than a livelock.
        if Some(mid) == self.me {
            return Outcome::none();
        }
        let Some(o) = self.obs_entry_capped(mid) else {
            return Outcome::none(); // map at capacity, new module — drop (never panic, R9).
        };
        o.handled = o.handled.saturating_add(1);
        if ev.ok {
            o.ok = o.ok.saturating_add(1);
        }
        Outcome::none()
    }

    // ----- control plane (operator → selector) -------------------------------------------------

    fn on_control(&mut self, env: &Envelope) -> Outcome {
        let Ok(msg) = SelectorMsg::parse(&env.payload) else {
            return Outcome::none(); // R9: never panic on malformed input.
        };
        match msg {
            SelectorMsg::Watch { module, realm, artifact_hash } => {
                self.on_watch(env, module, realm, artifact_hash)
            }
            SelectorMsg::Observe { module, ok, latency_ms } => {
                self.on_observe(module, ok, latency_ms)
            }
            SelectorMsg::Tick => self.on_tick(env),
            SelectorMsg::StatusQuery => self.on_status(env),
            // Replies arriving inbound (echo / misdirected) — the selector issues these, never
            // consumes them.
            SelectorMsg::Watching { .. }
            | SelectorMsg::Ticked { .. }
            | SelectorMsg::StatusReply { .. }
            | SelectorMsg::Rejected { .. } => Outcome::none(),
        }
    }

    fn on_watch(
        &mut self,
        env: &Envelope,
        module: u64,
        realm: RealmId,
        artifact_hash: String,
    ) -> Outcome {
        self.watch.insert(CreatureId(module), (realm, artifact_hash));
        reply(env, SelectorMsg::Watching { module })
    }

    fn on_observe(&mut self, module: u64, ok: bool, latency_ms: Option<u64>) -> Outcome {
        let mid = CreatureId(module);
        if Some(mid) == self.me {
            return Outcome::none(); // defensive: never self-observe.
        }
        let Some(o) = self.obs_entry_capped(mid) else {
            return Outcome::none(); // map at capacity, new module — drop (never panic, R9).
        };
        o.handled = o.handled.saturating_add(1);
        if ok {
            o.ok = o.ok.saturating_add(1);
        }
        if let Some(l) = latency_ms {
            o.latency_ms_total = o.latency_ms_total.saturating_add(l);
            o.latency_samples = o.latency_samples.saturating_add(1);
        }
        // No reply — Observe is the high-volume path; the operator confirms via StatusQuery / Tick.
        Outcome::none()
    }

    fn on_tick(&mut self, env: &Envelope) -> Outcome {
        let Some(me) = self.me_id() else {
            return reply(
                env,
                SelectorMsg::Rejected { reason: "fitness-selector not bound yet".into() },
            );
        };
        let mut out = Outcome::none();
        let mut promoted: Vec<u64> = Vec::new();
        let mut evaluated = 0usize;

        for (mid, (realm, hash)) in &self.watch {
            let Some(o) = self.obs.get(mid) else {
                continue; // watched but never observed — nothing to score yet.
            };
            evaluated += 1;
            let score = self.cfg.scorer.score(o);
            // R9 / adversarial-numeric guard (mirrors the federator weigher guard). TWO untrusted
            // floats meet here and BOTH must fail *closed* (promote nothing), never open:
            //  - `score` — the injected scorer's output (operator code). A non-finite score must
            //    never reach the registry; it would poison every downstream admission and
            //    defense read of this entry.
            //  - `self.cfg.threshold` — an operator-supplied public config field, equally untrusted.
            //    The fail-OPEN trap: a bare `score < threshold` with
            //    `threshold = NaN` is `false` for EVERY finite score (`finite < NaN` is false per
            //    IEEE-754), so the `continue` never fires and the gate silently promotes everything.
            // Guarding `threshold.is_finite()` first makes a non-finite threshold skip the
            // promotion (fail-closed), and only then is `score < threshold` a well-defined compare.
            if !score.is_finite() || !self.cfg.threshold.is_finite() || score < self.cfg.threshold {
                continue;
            }
            // Sign the promotion claim with our Abode key (heredity). The payload binds
            // artifact_hash + realm + score + attesting_realm, so the signature can't be replayed
            // onto a different entry (registry-mem's promotion_payload is the shared contract with
            // the verifying policy).
            let payload =
                ReputationScore::promotion_payload(hash, realm, score, Some(&self.cfg.self_realm));
            let signature = self.cfg.abode_key.sign(&payload);
            let op = RegistryOp::AttestFitness {
                artifact_hash: hash.clone(),
                realm: realm.clone(),
                score,
                attesting_realm: Some(self.cfg.self_realm.clone()),
                signed_by: Some(self.pubkey.clone()),
                signature: Some(signature),
            };
            out.dispatches.push(
                Dispatch::to(Address::Creature(self.cfg.local_registry), op.to_bytes())
                    .with_schema(REGISTRY_OP_SCHEMA)
                    .with_reply_to(Address::Creature(me)),
            );
            promoted.push(mid.0);
        }
        // HashMap iteration order is nondeterministic — sort so the reply (and tests) are stable.
        promoted.sort_unstable();
        let ticked = reply(env, SelectorMsg::Ticked { evaluated, promoted });
        out.dispatches.extend(ticked.dispatches);
        out
    }

    fn on_status(&self, env: &Envelope) -> Outcome {
        let mut observations: Vec<CreatureObservation> = self
            .obs
            .iter()
            .map(|(mid, o)| CreatureObservation {
                module: mid.0,
                handled: o.handled,
                ok: o.ok,
                latency_samples: o.latency_samples,
            })
            .collect();
        observations.sort_by_key(|m| m.module);
        reply(
            env,
            SelectorMsg::StatusReply {
                watched: self.watch.len(),
                observations,
                threshold: self.cfg.threshold,
            },
        )
    }
}

#[doc(hidden)]
impl FitnessSelector {
    /// For tests that drive `handle` directly without a kernel `bind`.
    #[cfg(test)]
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ----- helpers --------------------------------------------------------------------------------

/// Reply to the envelope's `reply_to` (or `from`) with a selector message + SCHEMA + corr.
fn reply(env: &Envelope, msg: SelectorMsg) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, msg.to_bytes()).with_schema(SCHEMA))
}

// ===================================================================================================
// Tests
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, Header};
    use sigil::Ed25519Verifier;

    const REGISTRY: CreatureId = CreatureId(50);
    const ME: CreatureId = CreatureId(9);
    const SELF_REALM: &str = "crew";

    fn key(seed: u8) -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([seed; 32]).unwrap()
    }

    /// A trivial in-crate scorer: returns the success rate. (The reference is
    /// `cosmos/creatures/prototypes/scorers/scorer-success-rate`; this keeps the unit tests free of a
    /// prototype-crate dependency.)
    struct SuccessRate;
    impl FitnessScorer for SuccessRate {
        fn score(&self, obs: &Observations) -> f32 {
            obs.success_rate()
        }
    }

    fn selector(seed: u8, threshold: f32) -> FitnessSelector {
        selector_with(seed, threshold, Box::new(SuccessRate))
    }

    fn selector_with(seed: u8, threshold: f32, scorer: Box<dyn FitnessScorer>) -> FitnessSelector {
        let cfg = SelectorConfig {
            self_realm: RealmId::new(SELF_REALM),
            local_registry: REGISTRY,
            abode_key: key(seed),
            threshold,
            scorer,
        };
        let mut s = FitnessSelector::new(cfg);
        s.set_me_for_tests(ME);
        s
    }

    fn header(to: Address, schema: &str, corr: Option<u64>) -> Header {
        Header {
            from: Address::Creature(CreatureId(100)),
            to,
            reply_to: Some(Address::Creature(CreatureId(100))),
            seq: 0,
            causal: vec![],
            stamp: 0,
            sig: String::new(),
            corr,
            commitment: None,
            schema: schema.into(),
        }
    }

    fn control_env(msg: SelectorMsg, corr: u64) -> Envelope {
        Envelope {
            header: header(Address::Creature(ME), SCHEMA, Some(corr)),
            payload: msg.to_bytes(),
        }
    }

    fn fitness_env(module: u64, ok: bool) -> Envelope {
        let payload =
            serde_json::to_vec(&serde_json::json!({ "module": module, "ok": ok })).unwrap();
        Envelope { header: header(Address::Creature(ME), FITNESS_EVENT_SCHEMA, None), payload }
    }

    fn parse_reply(d: &Dispatch) -> SelectorMsg {
        SelectorMsg::parse(&d.payload).unwrap()
    }

    fn parse_op(d: &Dispatch) -> RegistryOp {
        serde_json::from_slice(&d.payload).unwrap()
    }

    // ----- Observations math ----

    #[test]
    fn success_rate_is_zero_when_nothing_handled() {
        assert_eq!(Observations::default().success_rate(), 0.0);
    }

    #[test]
    fn success_rate_and_mean_latency_compute() {
        let o = Observations { handled: 4, ok: 3, latency_ms_total: 40, latency_samples: 2 };
        assert!((o.success_rate() - 0.75).abs() < 1e-6);
        assert_eq!(o.mean_latency_ms(), Some(20.0));
        assert_eq!(
            Observations { handled: 1, ok: 1, ..Default::default() }.mean_latency_ms(),
            None
        );
    }

    // ----- fitness-signal aggregation ----

    #[test]
    fn aggregates_fitness_events_per_module() {
        let mut s = selector(0xA1, 0.5);
        s.handle(fitness_env(7, true));
        s.handle(fitness_env(7, true));
        s.handle(fitness_env(7, false));
        let o = s.observations(CreatureId(7)).unwrap();
        assert_eq!(o.handled, 3);
        assert_eq!(o.ok, 2);
    }

    #[test]
    fn drops_its_own_fitness_event_to_avoid_self_feedback() {
        // The selector must never aggregate a fitness event for its own id (the anti-feedback
        // guard). ME == CreatureId(9).
        let mut s = selector(0xA2, 0.5);
        let out = s.handle(fitness_env(ME.0, true));
        assert!(out.dispatches.is_empty());
        assert!(s.observations(ME).is_none(), "must not record an observation for itself");
    }

    #[test]
    fn malformed_fitness_event_does_not_panic() {
        let mut s = selector(0xA3, 0.5);
        let env = Envelope {
            header: header(Address::Creature(ME), FITNESS_EVENT_SCHEMA, None),
            payload: b"{not json".to_vec(),
        };
        assert!(s.handle(env).dispatches.is_empty());
    }

    // ----- Observe (latency + synthetic) ----

    #[test]
    fn observe_op_feeds_handled_ok_and_latency() {
        let mut s = selector(0xA4, 0.5);
        s.handle(control_env(
            SelectorMsg::Observe { module: 5, ok: true, latency_ms: Some(12) },
            1,
        ));
        s.handle(control_env(
            SelectorMsg::Observe { module: 5, ok: false, latency_ms: Some(8) },
            2,
        ));
        let o = s.observations(CreatureId(5)).unwrap();
        assert_eq!(o.handled, 2);
        assert_eq!(o.ok, 1);
        assert_eq!(o.latency_ms_total, 20);
        assert_eq!(o.latency_samples, 2);
        assert_eq!(o.mean_latency_ms(), Some(10.0));
    }

    // ----- Watch + StatusQuery ----

    #[test]
    fn watch_registers_a_key_and_acks() {
        let mut s = selector(0xA5, 0.5);
        let out = s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            3,
        ));
        assert_eq!(s.watched_count(), 1);
        match parse_reply(&out.dispatches[0]) {
            SelectorMsg::Watching { module } => assert_eq!(module, 7),
            other => panic!("expected Watching, got {other:?}"),
        }
        assert_eq!(out.dispatches[0].corr, Some(3));
    }

    #[test]
    fn status_query_reports_watch_count_observations_and_threshold() {
        let mut s = selector(0xA6, 0.7);
        s.handle(fitness_env(7, true));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::StatusQuery, 2));
        match parse_reply(&out.dispatches[0]) {
            SelectorMsg::StatusReply { watched, observations, threshold } => {
                assert_eq!(watched, 1);
                assert_eq!(observations.len(), 1);
                assert_eq!(observations[0].module, 7);
                assert_eq!(observations[0].handled, 1);
                assert!((threshold - 0.7).abs() < 1e-6);
            }
            other => panic!("expected StatusReply, got {other:?}"),
        }
    }

    // ----- Tick → signed promotion ----

    #[test]
    fn tick_promotes_a_watched_creature_at_threshold_with_a_verifying_signature() {
        let k = key(0xB1);
        let pubkey = k.public_hex().to_string();
        let mut s = selector(0xB1, 0.5);
        // Three useful handles → success_rate 1.0 ≥ 0.5.
        s.handle(fitness_env(7, true));
        s.handle(fitness_env(7, true));
        s.handle(fitness_env(7, true));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 2));

        // One AttestFitness to the registry + the Ticked reply.
        let attest = out
            .dispatches
            .iter()
            .find(|d| d.schema == REGISTRY_OP_SCHEMA)
            .expect("an AttestFitness was emitted");
        assert_eq!(attest.to, Address::Creature(REGISTRY));
        match parse_op(attest) {
            RegistryOp::AttestFitness {
                artifact_hash,
                realm,
                score,
                attesting_realm,
                signed_by,
                signature,
            } => {
                assert_eq!(artifact_hash, "h7");
                assert_eq!(realm, RealmId::new("crew"));
                assert!((score - 1.0).abs() < 1e-6);
                assert_eq!(attesting_realm, Some(RealmId::new("crew")));
                assert_eq!(
                    signed_by.as_deref(),
                    Some(pubkey.as_str()),
                    "stamped with our Abode pubkey"
                );
                // The signature verifies for THIS entry under our key — and a stored score that
                // carries it `promotion_verifies` (the contract policy-prefer-promoted checks).
                let rep = ReputationScore { score, attesting_realm, signed_by, signature };
                let v = Ed25519Verifier;
                assert!(rep.promotion_verifies("h7", &RealmId::new("crew"), &v));
                assert!(
                    !rep.promotion_verifies("other", &RealmId::new("crew"), &v),
                    "claim binds the artifact_hash"
                );
                assert!(
                    !rep.promotion_verifies("h7", &RealmId::new("other"), &v),
                    "claim binds the realm too"
                );
            }
            other => panic!("expected AttestFitness, got {other:?}"),
        }
        // The Ticked reply names the promoted module.
        let ticked = out.dispatches.iter().find(|d| d.schema == SCHEMA).expect("Ticked reply");
        match parse_reply(ticked) {
            SelectorMsg::Ticked { evaluated, promoted } => {
                assert_eq!(evaluated, 1);
                assert_eq!(promoted, vec![7]);
            }
            other => panic!("expected Ticked, got {other:?}"),
        }
    }

    #[test]
    fn tick_does_not_promote_below_threshold() {
        let mut s = selector(0xB2, 0.8);
        // 1 ok of 4 → 0.25 < 0.8.
        s.handle(fitness_env(7, true));
        s.handle(fitness_env(7, false));
        s.handle(fitness_env(7, false));
        s.handle(fitness_env(7, false));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 2));
        assert!(
            out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA),
            "no AttestFitness below threshold"
        );
        match parse_reply(out.dispatches.iter().find(|d| d.schema == SCHEMA).unwrap()) {
            SelectorMsg::Ticked { evaluated, promoted } => {
                assert_eq!(evaluated, 1, "it was evaluated");
                assert!(promoted.is_empty(), "but not promoted");
            }
            other => panic!("expected Ticked, got {other:?}"),
        }
    }

    #[test]
    fn tick_skips_watched_creatures_with_no_observations() {
        let mut s = selector(0xB3, 0.0); // threshold 0.0 would promote anything observed
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 2));
        match parse_reply(out.dispatches.iter().find(|d| d.schema == SCHEMA).unwrap()) {
            SelectorMsg::Ticked { evaluated, promoted } => {
                assert_eq!(evaluated, 0, "watched but unobserved → not evaluated");
                assert!(promoted.is_empty());
            }
            other => panic!("expected Ticked, got {other:?}"),
        }
    }

    #[test]
    fn tick_does_not_promote_unwatched_creatures_even_when_observed() {
        let mut s = selector(0xB4, 0.0);
        // Observed but never watched → no key to promote to.
        s.handle(fitness_env(7, true));
        let out = s.handle(control_env(SelectorMsg::Tick, 1));
        assert!(out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA));
    }

    #[test]
    fn non_finite_scorer_output_never_reaches_the_registry() {
        // R9: a buggy/hostile injected scorer returning NaN must not write NaN to the registry.
        // `score < threshold` alone would let NaN through (NaN < x is false); the is_finite() guard
        // catches it. Mirror of the federator NaN-weight guard.
        struct NanScorer;
        impl FitnessScorer for NanScorer {
            fn score(&self, _obs: &Observations) -> f32 {
                f32::NAN
            }
        }
        let mut s = selector_with(0xB5, 0.5, Box::new(NanScorer));
        s.handle(fitness_env(7, true));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 2));
        assert!(
            out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA),
            "NaN score must discard the promotion, never write NaN"
        );
    }

    #[test]
    fn infinite_scorer_output_never_reaches_the_registry() {
        // The `is_finite()` guard rejects ±∞ as well as NaN; the NaN case is covered above, this
        // pins the infinity arm (the federator's mirror guard has the same coverage).
        struct InfScorer;
        impl FitnessScorer for InfScorer {
            fn score(&self, _obs: &Observations) -> f32 {
                f32::INFINITY
            }
        }
        let mut s = selector_with(0xB7, 0.5, Box::new(InfScorer));
        s.handle(fitness_env(7, true));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 2));
        assert!(
            out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA),
            "an infinite score must discard the promotion, never write ∞"
        );
    }

    #[test]
    fn nan_threshold_promotes_nothing_fail_closed() {
        // A non-finite *operator-supplied* threshold must fail
        // CLOSED. A bare `score < threshold` with `threshold = NaN` is false for every finite score
        // (`finite < NaN` is false), so without the `threshold.is_finite()` guard the gate would
        // promote EVERYTHING. With it, a NaN threshold promotes nothing.
        let mut s = selector(0xB8, f32::NAN);
        s.handle(fitness_env(7, true)); // a perfect success rate — would promote under any finite threshold
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 2));
        assert!(
            out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA),
            "NaN threshold must promote nothing (fail-closed), never everything (fail-open)"
        );
        match parse_reply(out.dispatches.iter().find(|d| d.schema == SCHEMA).unwrap()) {
            SelectorMsg::Ticked { evaluated, promoted } => {
                assert_eq!(evaluated, 1, "it was evaluated");
                assert!(promoted.is_empty(), "but a NaN threshold promotes nothing");
            }
            other => panic!("expected Ticked, got {other:?}"),
        }
    }

    #[test]
    fn two_watched_creatures_promote_independently() {
        let mut s = selector(0xB6, 0.5);
        s.handle(fitness_env(7, true)); // 7: 1.0
        s.handle(fitness_env(8, true)); // 8: 0.5
        s.handle(fitness_env(8, false));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 7,
                realm: RealmId::new("crew"),
                artifact_hash: "h7".into(),
            },
            1,
        ));
        s.handle(control_env(
            SelectorMsg::Watch {
                module: 8,
                realm: RealmId::new("crew"),
                artifact_hash: "h8".into(),
            },
            2,
        ));
        let out = s.handle(control_env(SelectorMsg::Tick, 3));
        match parse_reply(out.dispatches.iter().find(|d| d.schema == SCHEMA).unwrap()) {
            SelectorMsg::Ticked { evaluated, promoted } => {
                assert_eq!(evaluated, 2);
                assert_eq!(promoted, vec![7, 8], "both at/over 0.5; sorted");
            }
            other => panic!("expected Ticked, got {other:?}"),
        }
        let attests = out.dispatches.iter().filter(|d| d.schema == REGISTRY_OP_SCHEMA).count();
        assert_eq!(attests, 2);
    }

    // ----- misbind / hostile ----

    #[test]
    fn malformed_control_payload_does_not_panic() {
        let mut s = selector(0x01, 0.5);
        let env = Envelope {
            header: header(Address::Creature(ME), SCHEMA, None),
            payload: b"{not json".to_vec(),
        };
        assert!(s.handle(env).dispatches.is_empty());
    }

    #[test]
    fn tick_before_bind_replies_rejected_and_does_not_panic() {
        let mut s = selector(0x03, 0.5);
        s.me = None;

        let out = s.handle(control_env(SelectorMsg::Tick, 77));

        assert_eq!(out.dispatches.len(), 1);
        match parse_reply(&out.dispatches[0]) {
            SelectorMsg::Rejected { reason } => assert!(reason.contains("not bound"), "{reason}"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn unknown_schema_is_a_no_op() {
        let mut s = selector(0x02, 0.5);
        let env = Envelope {
            header: header(Address::Creature(ME), "some.other.schema", None),
            payload: b"x".to_vec(),
        };
        assert!(s.handle(env).dispatches.is_empty());
    }

    #[test]
    fn selector_msg_wire_roundtrips_and_elides_optional_latency() {
        let observe_full = SelectorMsg::Observe { module: 1, ok: true, latency_ms: Some(5) };
        let back = SelectorMsg::parse(&observe_full.to_bytes()).unwrap();
        assert_eq!(back, observe_full);
        let observe_min = SelectorMsg::Observe { module: 1, ok: true, latency_ms: None };
        let json = String::from_utf8(observe_min.to_bytes()).unwrap();
        assert!(!json.contains("latency_ms"), "absent latency elides: {json}");
    }

    #[test]
    fn max_obs_drops_observations_for_new_modules_at_capacity() {
        // Cap the tally map at 1 distinct module. The first observed module is tracked; a fitness
        // event for a *second* module is dropped (never panics — R9), but the already-tracked
        // module keeps accumulating. `0` would be unbounded (the default).
        let mut s = selector(0x09, 0.5).with_max_obs(1);
        let _ = s.handle(fitness_env(10, true));
        assert!(s.observations(CreatureId(10)).is_some(), "first module tracked");

        // Second distinct module at capacity → dropped, no panic, no new entry.
        let out = s.handle(fitness_env(11, true));
        assert!(out.dispatches.is_empty(), "fitness ingest never replies");
        assert!(s.observations(CreatureId(11)).is_none(), "new module dropped at capacity");

        // The tracked module still accumulates — refuse-new never blocks existing tallies.
        let _ = s.handle(fitness_env(10, false));
        let o = s.observations(CreatureId(10)).expect("module 10 still tracked");
        assert_eq!(o.handled, 2, "tracked module keeps accumulating at capacity");
    }
}
