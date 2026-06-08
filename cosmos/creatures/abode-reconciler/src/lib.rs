//! `abode-reconciler` — the **fork + merge** half of the distributed self (the
//! `abode-migrator` does *single-active-fork* hand-off only).
//!
//! The `abode-migrator` moves an Abode between Sanctums with an explicit hand-off: the source marks
//! itself `Migrated { to }` the moment the destination acks, so at most one body is ever
//! authoritative. That deliberately sidesteps the hard case: **two bodies of the same self that both
//! kept running and diverged** (a partition healed, an offline fork came back, a deliberate
//! parallel exploration rejoined). Reconciling them needs a **conflict-free merge** — a CRDT — and
//! the merge *semantics* depend on what the Abode's state actually is, which is opaque to the
//! substrate (T1). So the substrate ships the **reconciler socket + the snapshot
//! verify/sign primitives**; the merge model is **injected** (IoC).
//!
//! ## What it does
//!
//! On a [`ReconcilerMsg::Reconcile { fork_a, fork_b }`] for the *same* Abode (same `abode_key`), the
//! reconciler:
//! 1. **Bounds the reconcile message before JSON decode**, then verifies both forks through the
//!    substrate's snapshot gates — size ceiling (R9), signature
//!    (each fork must be validly signed by the Abode key, unless the operator opts out for a sealed
//!    lab), and integrity (`state_hash == sha256(payload)`). A fork that fails any gate → `Rejected`,
//!    never a panic.
//! 2. **Confirms they are the same self** — `fork_a.abode_key == fork_b.abode_key`, and (when the
//!    reconciler holds that self's key) equal to its own pubkey. Merging two *different* selves is
//!    refused; that's not a fork.
//! 3. **Unwraps the migrator's framing** (`abode_migrator::unwrap_payload_v0_3`) so the [`MergeModel`] sees
//!    pure state, runs the injected merge, and **re-wraps** the merged state with the same framing.
//! 4. **Re-signs** the merged snapshot with the Abode key and replies [`ReconcilerMsg::Reconciled`].
//!    The result is a fresh authoritative snapshot the migrator can hand off / a Sanctum can restore.
//!
//! ## The merge is injected, and must be a CRDT
//!
//! [`MergeModel::merge`] takes the two divergent state byte-strings and returns the merged state. For
//! the merge to be *correct under any interleaving of forks* it must be a **CRDT**: commutative
//! (`merge(a,b) == merge(b,a)`), associative, and idempotent (`merge(a,a) == a`) — so reconciling in
//! any order, any number of times, converges. The substrate ships **none**; `cosmos/creatures/prototypes/merge/merge-lww-map`
//! is the reference (an LWW-Element-Map over JSON). Operators write their own (OR-Set, RGA for text,
//! a domain-specific lattice) and bind it. The reconciler enforces the *envelope* (verify, same-self,
//! re-sign); it trusts the injected model for the *lattice* — exactly the fabric-not-model split.

use abode::AbodeSnapshot;
use aether::{Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome};
use serde::{Deserialize, Serialize};
use sigil::{Ed25519KeyMaterial, Ed25519Verifier, Verifier};
use std::sync::Arc;

/// Wire schema for the reconciler's control plane + replies. Single `kind`-tagged enum, same
/// convention as `abode-migrator` and the other creatures.
pub const SCHEMA: &str = "abode.reconciler";

/// Default ceiling on each fork's `payload_bytes`. Deliberately **tighter** than the migrator's
/// single-snapshot default (`abode::DEFAULT_MAX_PAYLOAD_BYTES`, 8 MiB): a reconcile admits
/// *several* forks at once, so it bounds each fork at half that. A peer can't have the reconciler
/// admit an enormous fork just because it knows the address (R9).
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Fixed allowance for non-payload JSON fields in one reconcile message.
const RECONCILER_MESSAGE_OVERHEAD_BYTES: usize = 256 * 1024;

/// The pre-parse ceiling for a serialized [`ReconcilerMsg`], derived from the instance's
/// `max_payload_bytes`. A reconcile carries two snapshots. `AbodeSnapshot.payload_bytes` currently
/// serializes as a JSON `Vec<u8>` array; a single byte can occupy up to four wire bytes (`255,`).
/// The cap therefore allows two max-sized fork payloads at worst-case JSON expansion plus fixed
/// metadata overhead.
fn max_reconciler_message_bytes(max_payload_bytes: usize) -> usize {
    max_payload_bytes
        .saturating_mul(2)
        .saturating_mul(4)
        .saturating_add(RECONCILER_MESSAGE_OVERHEAD_BYTES)
}

// ===================================================================================================
// Injected CRDT merge model (IoC)
// ===================================================================================================

/// The **injected** conflict-free merge over two divergent Abode states. The substrate ships none;
/// `cosmos/creatures/prototypes/merge/merge-lww-map` is the reference. For correctness under any fork interleaving the
/// implementation MUST be a CRDT — commutative, associative, idempotent — so reconciliation
/// converges regardless of order or repetition.
///
/// Inputs are the two forks' **unwrapped** state bytes (the migrator's framing already stripped); the
/// return is the merged state bytes (the reconciler re-wraps + re-signs). An `Err` aborts the
/// reconcile into a [`ReconcilerMsg::Rejected`] — the model couldn't merge (e.g. unparseable state).
pub trait MergeModel: Send + Sync {
    fn merge(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, String>;
}

// ===================================================================================================
// Wire messages
// ===================================================================================================

/// Every reconciler message on [`SCHEMA`]. New variants append (additive wire); reorder/rename is a
/// wire break — same discipline as the other creatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
// Short-lived wire message (serialized to JSON, sent on the bus); the variant-size difference is
// immaterial. Boxing would only obscure the uniform kind-tagged-enum wire convention.
#[allow(clippy::large_enum_variant)]
pub enum ReconcilerMsg {
    // ----- operator → reconciler -----
    /// Merge two divergent snapshots of the same Abode into one authoritative snapshot.
    Reconcile { fork_a: AbodeSnapshot, fork_b: AbodeSnapshot },

    // ----- reconciler → operator -----
    /// The merged, re-signed snapshot (a fresh authoritative state).
    Reconciled { merged: AbodeSnapshot },
    /// The reconcile was refused before producing a result (a fork failed a gate, the forks were of
    /// different selves, or the injected merge errored). Structured for an orchestrator to dispatch.
    Rejected { reason: String },
}

impl ReconcilerMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ===================================================================================================
// The reconciler
// ===================================================================================================

/// Construction config — the operator wires this before `Kernel::load_instance`.
pub struct ReconcilerConfig {
    /// The Abode's authorship key — signs the merged snapshot (the merged state is the self's,
    /// re-attested). The reconciler refuses to merge forks of a *different* self.
    pub abode_key: Ed25519KeyMaterial,
    /// The injected CRDT merge model. Substrate ships none (IoC).
    pub merge_model: Box<dyn MergeModel>,
    /// Per-fork `payload_bytes` ceiling. Defaults to [`DEFAULT_MAX_PAYLOAD_BYTES`].
    pub max_payload_bytes: usize,
    /// Require each inbound fork to be validly signed by the Abode key. Default `true`; an operator
    /// flips it for a sealed test harness.
    pub require_signed: bool,
}

impl ReconcilerConfig {
    /// Sensible defaults: substrate size ceiling + signatures required.
    pub fn new(abode_key: Ed25519KeyMaterial, merge_model: Box<dyn MergeModel>) -> Self {
        ReconcilerConfig {
            abode_key,
            merge_model,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            require_signed: true,
        }
    }
    pub fn with_max_payload_bytes(mut self, max: usize) -> Self {
        self.max_payload_bytes = max;
        self
    }
    pub fn with_unsigned_forks_allowed(mut self) -> Self {
        self.require_signed = false;
        self
    }
}

/// The abode-reconciler creature.
pub struct AbodeReconciler {
    cfg: ReconcilerConfig,
    pubkey: String,
    verifier: Arc<dyn Verifier>,
    me: Option<CreatureId>,
}

impl AbodeReconciler {
    pub fn new(cfg: ReconcilerConfig) -> Self {
        let pubkey = cfg.abode_key.public_hex().to_string();
        AbodeReconciler { cfg, pubkey, verifier: Arc::new(Ed25519Verifier), me: None }
    }

    /// Swap the verifier (tests with a deterministic stub).
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = verifier;
        self
    }
}

impl Creature for AbodeReconciler {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA {
            return Outcome::none(); // misbind / stray — never crash (R9).
        }
        let max_message_bytes = max_reconciler_message_bytes(self.cfg.max_payload_bytes);
        if env.payload.len() > max_message_bytes {
            return reply(
                &env,
                ReconcilerMsg::Rejected {
                    reason: format!(
                        "reconciler message {} bytes exceeds max {} bytes",
                        env.payload.len(),
                        max_message_bytes
                    ),
                },
            );
        }
        let Ok(msg) = ReconcilerMsg::parse(&env.payload) else {
            return Outcome::none(); // R9: malformed input → drop, never panic.
        };
        match msg {
            ReconcilerMsg::Reconcile { fork_a, fork_b } => self.on_reconcile(&env, fork_a, fork_b),
            // Replies arriving inbound (echo / misdirected) — we issue these, never consume them.
            ReconcilerMsg::Reconciled { .. } | ReconcilerMsg::Rejected { .. } => Outcome::none(),
        }
    }
}

impl AbodeReconciler {
    fn on_reconcile(
        &mut self,
        env: &Envelope,
        fork_a: AbodeSnapshot,
        fork_b: AbodeSnapshot,
    ) -> Outcome {
        match self.reconcile(fork_a, fork_b) {
            Ok(merged) => reply(env, ReconcilerMsg::Reconciled { merged }),
            Err(reason) => reply(env, ReconcilerMsg::Rejected { reason }),
        }
    }

    /// The pure reconcile (no bus): verify both forks, confirm same-self, merge via the injected
    /// model, re-wrap + re-sign. Returns the merged snapshot or a structured reason. Exposed for
    /// direct testing.
    pub fn reconcile(
        &self,
        fork_a: AbodeSnapshot,
        fork_b: AbodeSnapshot,
    ) -> Result<AbodeSnapshot, String> {
        // ---- substrate gates, both forks (R9 size, signature, integrity) ----
        self.gate(&fork_a, "fork_a")?;
        self.gate(&fork_b, "fork_b")?;

        // ---- same-self: a fork is two bodies of ONE Abode; merging two selves is not a fork ----
        if fork_a.abode_key != fork_b.abode_key {
            return Err(format!(
                "forks are of different selves (abode_key {} != {}) — not a fork to reconcile",
                fork_a.abode_key, fork_b.abode_key
            ));
        }
        if fork_a.abode_key != self.pubkey {
            return Err(format!(
                "this reconciler holds the key for `{}`; refusing to merge forks of `{}`",
                self.pubkey, fork_a.abode_key
            ));
        }

        // ---- unwrap the migrator's framing so the merge model sees pure state ----
        let state_a = abode_migrator::unwrap_payload_v0_3(&fork_a.payload_bytes)
            .map_err(|e| format!("fork_a framing: {e}"))?;
        let state_b = abode_migrator::unwrap_payload_v0_3(&fork_b.payload_bytes)
            .map_err(|e| format!("fork_b framing: {e}"))?;

        // ---- the injected CRDT merge (the operator's lattice) ----
        let merged_state = self.cfg.merge_model.merge(state_a, state_b)?;

        // ---- re-wrap + re-sign as a fresh authoritative snapshot ----
        let wrapped = abode_migrator::wrap_payload_v0_3(&merged_state);
        let mut merged = AbodeSnapshot::new(self.pubkey.clone(), wrapped);
        // Carry the self's requirements + Realm forward (take fork_a's; identical for a true fork).
        merged.requires = fork_a.requires.clone();
        merged.realm = fork_a.realm.clone();
        // Bound the MERGE OUTPUT, not just each input fork: a concatenating lattice merge of two
        // near-ceiling forks can yield an oversized snapshot, and signing it would mint a valid,
        // admissible-but-oversized self. Gate it with the same primitive `gate()` uses on inputs,
        // BEFORE signing. (T10)
        merged
            .assert_payload_size(self.cfg.max_payload_bytes)
            .map_err(|e| format!("merged output size: {e}"))?;
        merged.sign(&self.cfg.abode_key);
        Ok(merged)
    }

    /// The substrate snapshot gates for one fork: size → signature (opt) → integrity. Never panics.
    fn gate(&self, fork: &AbodeSnapshot, which: &str) -> Result<(), String> {
        fork.assert_payload_size(self.cfg.max_payload_bytes)
            .map_err(|e| format!("{which} size: {e}"))?;
        if self.cfg.require_signed {
            fork.verify_signature(self.verifier.as_ref())
                .map_err(|e| format!("{which} signature: {e}"))?;
        }
        fork.assert_integrity().map_err(|e| format!("{which} integrity: {e}"))?;
        Ok(())
    }
}

#[doc(hidden)]
impl AbodeReconciler {
    #[cfg(test)]
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ----- helpers --------------------------------------------------------------------------------

fn reply(env: &Envelope, msg: ReconcilerMsg) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, msg.to_bytes()).with_schema(SCHEMA))
}

// ===================================================================================================
// Tests
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, Header};

    const ME: CreatureId = CreatureId(9);

    fn key(seed: u8) -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([seed; 32]).unwrap()
    }

    /// A trivial commutative merge for the creature-level tests: concatenate the two states sorted,
    /// so merge(a,b) == merge(b,a). (The real CRDT reference is `cosmos/creatures/prototypes/merge/merge-lww-map`; this keeps
    /// the unit tests free of a prototype-crate dependency.)
    struct SortedConcatMerge;
    impl MergeModel for SortedConcatMerge {
        fn merge(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let mut out = lo.to_vec();
            out.extend_from_slice(hi);
            Ok(out)
        }
    }

    fn reconciler(seed: u8) -> AbodeReconciler {
        let mut r =
            AbodeReconciler::new(ReconcilerConfig::new(key(seed), Box::new(SortedConcatMerge)));
        r.set_me_for_tests(ME);
        r
    }

    /// A signed fork: wrap `state` in the migrator's framing, sign with the Abode key.
    fn fork(abode: &Ed25519KeyMaterial, state: &[u8]) -> AbodeSnapshot {
        let wrapped = abode_migrator::wrap_payload_v0_3(state);
        let mut s = AbodeSnapshot::new(abode.public_hex().to_string(), wrapped);
        s.sign(abode);
        s
    }

    fn reconcile_env(fork_a: AbodeSnapshot, fork_b: AbodeSnapshot, corr: u64) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(ME),
                reply_to: Some(Address::Creature(CreatureId(100))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: ReconcilerMsg::Reconcile { fork_a, fork_b }.to_bytes(),
        }
    }

    #[test]
    fn reconciles_two_forks_into_a_signed_integrity_valid_merged_snapshot() {
        let abode = key(0xA1);
        let r = reconciler(0xA1); // same key → this reconciler owns the self
        let merged =
            r.reconcile(fork(&abode, b"alpha"), fork(&abode, b"beta")).expect("reconciles");
        // The merged snapshot is signed by the Abode key + integrity-valid + carries the merged state.
        assert_eq!(merged.abode_key, abode.public_hex());
        assert!(merged.verify_signature(&Ed25519Verifier).is_ok(), "merged is re-signed");
        assert!(merged.assert_integrity().is_ok(), "merged state_hash matches its payload");
        let merged_state = abode_migrator::unwrap_payload_v0_3(&merged.payload_bytes).unwrap();
        assert_eq!(merged_state, b"alphabeta", "SortedConcatMerge of the two unwrapped states");
    }

    #[test]
    fn merge_is_order_independent_at_the_creature_level() {
        // The reconciler must not impose an order; with a commutative model the result is identical.
        let abode = key(0xA2);
        let r = reconciler(0xA2);
        let ab = r.reconcile(fork(&abode, b"x"), fork(&abode, b"y")).unwrap();
        let ba = r.reconcile(fork(&abode, b"y"), fork(&abode, b"x")).unwrap();
        assert_eq!(
            abode_migrator::unwrap_payload_v0_3(&ab.payload_bytes).unwrap(),
            abode_migrator::unwrap_payload_v0_3(&ba.payload_bytes).unwrap(),
            "a commutative merge yields the same state regardless of fork order"
        );
    }

    #[test]
    fn reconcile_over_the_bus_replies_reconciled() {
        let abode = key(0xA3);
        let mut r = reconciler(0xA3);
        let out = r.handle(reconcile_env(fork(&abode, b"a"), fork(&abode, b"b"), 5));
        assert_eq!(out.dispatches[0].corr, Some(5));
        match ReconcilerMsg::parse(&out.dispatches[0].payload).unwrap() {
            ReconcilerMsg::Reconciled { merged } => {
                assert!(merged.verify_signature(&Ed25519Verifier).is_ok())
            }
            other => panic!("expected Reconciled, got {other:?}"),
        }
    }

    #[test]
    fn refuses_forks_of_different_selves() {
        let abode = key(0xB1);
        let other = key(0xB2);
        let r = reconciler(0xB1);
        let err = r.reconcile(fork(&abode, b"a"), fork(&other, b"b")).unwrap_err();
        assert!(err.contains("different selves"), "got: {err}");
    }

    #[test]
    fn refuses_a_fork_for_a_self_this_reconciler_does_not_hold() {
        let other = key(0xC2);
        let r = reconciler(0xC1); // holds 0xC1, but the forks are 0xC2's self
        let err = r.reconcile(fork(&other, b"a"), fork(&other, b"b")).unwrap_err();
        assert!(err.contains("refusing to merge forks"), "got: {err}");
    }

    #[test]
    fn refuses_an_unsigned_fork_when_signatures_required() {
        let abode = key(0xD1);
        let r = reconciler(0xD1);
        let wrapped = abode_migrator::wrap_payload_v0_3(b"a");
        let unsigned = AbodeSnapshot::new(abode.public_hex().to_string(), wrapped); // no sign()
        let err = r.reconcile(unsigned, fork(&abode, b"b")).unwrap_err();
        assert!(err.contains("signature"), "got: {err}");
    }

    #[test]
    fn refuses_a_tampered_fork_on_integrity() {
        let abode = key(0xD2);
        let r = reconciler(0xD2);
        let mut f = fork(&abode, b"a");
        f.payload_bytes = abode_migrator::wrap_payload_v0_3(b"tampered"); // mutate AFTER signing+hashing
                                                                          // (signature now fails first; flip require_signed off to reach the integrity gate cleanly)
        let r2 = {
            let mut rr = AbodeReconciler::new(
                ReconcilerConfig::new(key(0xD2), Box::new(SortedConcatMerge))
                    .with_unsigned_forks_allowed(),
            );
            rr.set_me_for_tests(ME);
            rr
        };
        let err = r2.reconcile(f, fork(&abode, b"b")).unwrap_err();
        assert!(err.contains("integrity"), "got: {err}");
        let _ = r; // silence unused in the signed-path branch
    }

    #[test]
    fn merge_model_error_becomes_a_structured_reject() {
        struct FailMerge;
        impl MergeModel for FailMerge {
            fn merge(&self, _a: &[u8], _b: &[u8]) -> Result<Vec<u8>, String> {
                Err("unparseable state".into())
            }
        }
        let abode = key(0xE1);
        let mut r = AbodeReconciler::new(ReconcilerConfig::new(key(0xE1), Box::new(FailMerge)));
        r.set_me_for_tests(ME);
        match ReconcilerMsg::parse(
            &r.handle(reconcile_env(fork(&abode, b"a"), fork(&abode, b"b"), 1)).dispatches[0]
                .payload,
        )
        .unwrap()
        {
            ReconcilerMsg::Rejected { reason } => {
                assert!(reason.contains("unparseable"), "got: {reason}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn malformed_payload_does_not_panic() {
        let mut r = reconciler(0x01);
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(ME),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: b"{not json".to_vec(),
        };
        assert!(r.handle(env).dispatches.is_empty());
    }

    #[test]
    fn oversized_reconcile_message_is_rejected_before_json_decode() {
        let mut r = AbodeReconciler::new(
            ReconcilerConfig::new(key(0x02), Box::new(SortedConcatMerge)).with_max_payload_bytes(8),
        );
        r.set_me_for_tests(ME);
        let max_message_bytes = max_reconciler_message_bytes(8);
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(ME),
                reply_to: Some(Address::Creature(CreatureId(100))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(99),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: vec![b'{'; max_message_bytes + 1],
        };

        let out = r.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].corr, Some(99));
        match ReconcilerMsg::parse(&out.dispatches[0].payload).unwrap() {
            ReconcilerMsg::Rejected { reason } => {
                assert!(reason.contains("exceeds max"), "got: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
