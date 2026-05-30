//! `verifiable-die` — the consumer of the envelope **`commitment`** slot, the
//! verifiable-randomness dimension of *proof of trust* (time, order, weight, consensus, permission,
//! history — **and verifiable randomness**). The slot
//! ([`aether::Header::commitment`] / [`Dispatch::with_commitment`](aether::Dispatch::with_commitment))
//! carries a commitment "for verifiable randomness / a concealed decision — scheme injected"; this
//! creature is the commit-and-reveal consumer of it.
//!
//! ## What it is — a commit-reveal fair die
//!
//! A *verifiable die* makes a fair pick among `n` options that **any peer who demands it can audit**
//! — the load-bearing promise that the substrate "supplies primitives to verify a model …
//! commit-reveal lets any peer who demands it check whether a 'random' pick was truly random or
//! secretly chosen"). It is **two-phase** so that *neither* party alone controls the outcome:
//!
//! 1. **Commit.** A requester asks the die to roll among `n` options for a `round`. The die draws a
//!    secret `seed` from its **injected** [`EntropySource`], computes
//!    `commitment = sha256(round ‖ n ‖ seed)`, and replies [`DieMsg::Committed`] with the commitment
//!    **also carried in the envelope's `commitment` slot** ([`Dispatch::with_commitment`]). The seed
//!    stays hidden; the commitment binds it.
//! 2. **Reveal.** The requester supplies its own `nonce` — chosen *without knowing the seed*. The die
//!    reveals the seed; the result is `pick = sha256(seed ‖ nonce) mod n`. Because the **seed was
//!    fixed at commit** (before the die saw the nonce) and the **nonce was fixed before the reveal**
//!    (before the requester saw the seed), neither party can steer `pick` toward a *specific favoured
//!    value*.
//!
//! Anyone — the requester, a skeptical peer, an auditor reading the journal — calls
//! [`verify_roll`] with the commitment, the revealed seed, and the nonce to **recompute and confirm**
//! both halves: that `sha256(round ‖ n ‖ seed)` equals the commitment (so the die didn't swap the
//! seed after seeing the nonce) and that `pick = sha256(seed ‖ nonce) mod n` (so the pick is the
//! honest function of the agreed inputs). A mismatch is provable cheating.
//!
//! **The one residual influence (inherent to plain commit-reveal).** The die reveals *last*: it sees
//! the pick before disclosing the seed, so it can *withhold* the reveal (reply nothing / a bogus
//! `Rejected`) to abort an unfavourable round — a ~1-bit selective-abort bias, and a withheld reveal
//! is cost-free here (the commitment leaks nothing; `verify_roll` never runs). This is **not** closed
//! by two-party commit-reveal; a real ECVRF / threshold-VRF on the same socket closes it. An operator
//! who cares treats a non-reveal within a deadline as a forfeit (or a reputation penalty) so abort
//! isn't free. The die binds the *value*; it does not bind *liveness*.
//!
//! ## Fabric ships the slot; the model is injected (IoC)
//!
//! The substrate ships the `commitment` field + this *socket*; it ships **no** randomness model. The
//! **scheme** here is sha256-based commit-reveal — a real [VRF](https://en.wikipedia.org/wiki/Verifiable_random_function)
//! (ECVRF) is the same *shape* (commit a proof, reveal, anyone verifies) and slots in as a different
//! `verify_roll`/[`EntropySource`] pair without touching the substrate. The **entropy source** is
//! injected too: [`OsEntropy`] (OS CSPRNG via `ring`, the production default) vs [`FixedEntropy`] (a
//! deterministic reference for tests — *never* production: a predictable seed lets a requester who
//! learns it pre-compute a favourable nonce). The fabric judges none of this; it only carries the
//! commitment and lets any peer verify.

use std::collections::HashMap;

use aether::{Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire schema for the die's commit/reveal control plane + replies. Single `kind`-tagged enum, same
/// convention as the other creatures.
pub const SCHEMA: &str = "verifiable.die";

// ===================================================================================================
// Injected entropy (IoC) — substrate ships no randomness source
// ===================================================================================================

/// Where the die's secret seed comes from — the **injected** entropy source. The substrate ships
/// none as a default; [`OsEntropy`] is the production reference, [`FixedEntropy`] the test reference.
pub trait EntropySource: Send + Sync {
    /// A fresh 32-byte seed for one roll. A production source MUST be unpredictable to the requester
    /// at commit time (else the commit-reveal binding is worthless — see the module docs).
    fn fresh_seed(&self) -> Result<[u8; 32], String>;
}

/// Production entropy: the OS CSPRNG (`ring::rand::SystemRandom`, via
/// `sigil::crypto::fresh_seed`).
pub struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fresh_seed(&self) -> Result<[u8; 32], String> {
        sigil::crypto::fresh_seed()
    }
}

/// A deterministic seed — **reference / tests only, never production**. A fixed (predictable) seed
/// defeats the commit-reveal guarantee: a requester who can guess the seed picks a nonce that forces
/// a chosen `pick`. Shipped so unit/integration tests are deterministic, exactly as
/// `cosmos/creatures/prototypes/scorers/scorer-roundrobin` / `policy-quarantine-trust-all` are deliberately-not-production
/// references.
pub struct FixedEntropy(pub [u8; 32]);
impl EntropySource for FixedEntropy {
    fn fresh_seed(&self) -> Result<[u8; 32], String> {
        Ok(self.0)
    }
}

// ===================================================================================================
// The verifiable scheme — free functions any party (die OR auditor) computes identically
// ===================================================================================================

/// The commitment a die publishes at commit time: `hex(sha256(round_le ‖ n_le ‖ seed))`. Binds the
/// seed to the `(round, n)` it was drawn for, so a die can't later reveal a different seed (the
/// commitment wouldn't match) or reuse a seed for a different option count. Byte-stable: fixed-width
/// little-endian integers + the raw seed.
pub fn commitment_of(round: u64, n: u32, seed: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(round.to_le_bytes());
    h.update(n.to_le_bytes());
    h.update(seed);
    hex(&h.finalize())
}

/// The pick: `sha256(seed ‖ nonce) interpreted as a u64 (big-endian, first 8 bytes) mod n`. Mixes
/// the die's seed with the requester's nonce so neither alone controls the result. `n == 0` yields
/// `0` (a degenerate roll with no options — callers guard `n > 0` before committing).
pub fn pick_of(seed: &[u8; 32], nonce: &str, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut h = Sha256::new();
    h.update(seed);
    h.update(nonce.as_bytes());
    let digest = h.finalize();
    let mut head = [0u8; 8];
    head.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(head) % (n as u64)) as u32
}

/// Audit a revealed roll. Recomputes the commitment from `(round, n, seed)` and, **iff** it matches
/// the published `commitment`, returns `Some(pick)` for the agreed `nonce`. A mismatch (a swapped
/// seed, a tampered commitment, a wrong `(round, n)`) returns `None` — provable cheating. `n == 0`
/// also returns `None` (a degenerate roll is never a valid verified outcome). This is the function a
/// skeptical peer runs; the die has no privileged path.
pub fn verify_roll(
    commitment: &str,
    round: u64,
    n: u32,
    seed_hex: &str,
    nonce: &str,
) -> Option<u32> {
    if n == 0 {
        return None;
    }
    let seed = decode_seed(seed_hex)?;
    if commitment_of(round, n, &seed) != commitment {
        return None;
    }
    Some(pick_of(&seed, nonce, n))
}

// ===================================================================================================
// Wire messages
// ===================================================================================================

/// Every die message on [`SCHEMA`]: requester ops + the die's replies. New variants append (additive
/// wire); reorder/rename is a wire break — same discipline as the other creatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DieMsg {
    // ----- requester → die -----
    /// Commit to a roll among `n` options for `round`. Reply: [`Committed`](Self::Committed) (with
    /// the commitment also in the envelope's `commitment` slot) or [`Rejected`](Self::Rejected).
    Commit { round: u64, n: u32 },
    /// Reveal the roll for `round` using the requester's `nonce`. Reply: [`Revealed`](Self::Revealed)
    /// or [`Rejected`](Self::Rejected) (no such pending round).
    Reveal { round: u64, nonce: String },

    // ----- die → requester -----
    /// The commitment for `round`. The same value rides the reply envelope's `commitment` slot.
    Committed { round: u64, commitment: String },
    /// The revealed roll: the `seed` (hex) the die committed to, the `nonce` used, and the resulting
    /// `pick` in `0..n`. Anyone can confirm with [`verify_roll`]`(commitment, round, n, seed, nonce)`.
    Revealed { round: u64, n: u32, seed: String, nonce: String, pick: u32 },
    /// The op was refused (e.g. `n == 0`, a round already committed, or a reveal with no commit).
    Rejected { reason: String },
}

impl DieMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ===================================================================================================
// The die
// ===================================================================================================

/// The verifiable-die creature. Holds the injected [`EntropySource`] and the per-round committed
/// seeds awaiting reveal.
pub struct VerifiableDie {
    entropy: Box<dyn EntropySource>,
    me: Option<CreatureId>,
    /// `round → (committed seed, option count)`. Held between commit and reveal.
    pending: HashMap<u64, ([u8; 32], u32)>,
}

impl VerifiableDie {
    pub fn new(entropy: Box<dyn EntropySource>) -> Self {
        VerifiableDie { entropy, me: None, pending: HashMap::new() }
    }

    /// How many rounds are committed but not yet revealed.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

impl Creature for VerifiableDie {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA {
            return Outcome::none(); // misbind / stray — never crash (R9).
        }
        let Ok(msg) = DieMsg::parse(&env.payload) else {
            return Outcome::none(); // R9: malformed input → drop, never panic.
        };
        match msg {
            DieMsg::Commit { round, n } => self.on_commit(&env, round, n),
            DieMsg::Reveal { round, nonce } => self.on_reveal(&env, round, nonce),
            // Replies arriving inbound (echo / misdirected) — the die issues these, never consumes.
            DieMsg::Committed { .. } | DieMsg::Revealed { .. } | DieMsg::Rejected { .. } => {
                Outcome::none()
            }
        }
    }
}

impl VerifiableDie {
    fn on_commit(&mut self, env: &Envelope, round: u64, n: u32) -> Outcome {
        if n == 0 {
            return reply(
                env,
                DieMsg::Rejected { reason: "cannot roll among zero options".into() },
                None,
            );
        }
        if self.pending.contains_key(&round) {
            // Never overwrite a committed seed — that would break the binding for the prior commit.
            return reply(
                env,
                DieMsg::Rejected {
                    reason: format!("round {round} already committed (reveal it first)"),
                },
                None,
            );
        }
        let seed = match self.entropy.fresh_seed() {
            Ok(seed) => seed,
            Err(e) => {
                return reply(
                    env,
                    DieMsg::Rejected { reason: format!("entropy source failed: {e}") },
                    None,
                )
            }
        };
        let commitment = commitment_of(round, n, &seed);
        self.pending.insert(round, (seed, n));
        // The commitment rides BOTH the reply body and the envelope's `commitment` slot — the latter
        // is the substrate's verifiable-randomness primitive, so a relay/journal carries
        // it without parsing the body.
        reply(env, DieMsg::Committed { round, commitment: commitment.clone() }, Some(commitment))
    }

    fn on_reveal(&mut self, env: &Envelope, round: u64, nonce: String) -> Outcome {
        let Some((seed, n)) = self.pending.remove(&round) else {
            return reply(
                env,
                DieMsg::Rejected { reason: format!("no committed roll for round {round}") },
                None,
            );
        };
        let pick = pick_of(&seed, &nonce, n);
        reply(env, DieMsg::Revealed { round, n, seed: hex(&seed), nonce, pick }, None)
    }
}

#[doc(hidden)]
impl VerifiableDie {
    #[cfg(test)]
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ----- helpers --------------------------------------------------------------------------------

fn reply(env: &Envelope, msg: DieMsg, commitment: Option<String>) -> Outcome {
    let mut d = Dispatch::reply_to_env(env, msg.to_bytes()).with_schema(SCHEMA);
    if let Some(commit) = commitment {
        d = d.with_commitment(commit);
    }
    Outcome::send(d)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn decode_seed(seed_hex: &str) -> Option<[u8; 32]> {
    if seed_hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(seed_hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ===================================================================================================
// Tests
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, Header};

    const ME: CreatureId = CreatureId(9);

    fn die_with(seed: [u8; 32]) -> VerifiableDie {
        let mut d = VerifiableDie::new(Box::new(FixedEntropy(seed)));
        d.set_me_for_tests(ME);
        d
    }

    struct FailingEntropy;
    impl EntropySource for FailingEntropy {
        fn fresh_seed(&self) -> Result<[u8; 32], String> {
            Err("rng offline".into())
        }
    }

    fn header(schema: &str, corr: Option<u64>) -> Header {
        Header {
            from: Address::Creature(CreatureId(100)),
            to: Address::Creature(ME),
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

    fn env(msg: DieMsg, corr: u64) -> Envelope {
        Envelope { header: header(SCHEMA, Some(corr)), payload: msg.to_bytes() }
    }

    fn parse(d: &Dispatch) -> DieMsg {
        DieMsg::parse(&d.payload).unwrap()
    }

    #[test]
    fn commit_hides_seed_then_reveal_yields_a_verifiable_pick() {
        let mut d = die_with([0x11; 32]);
        // Commit.
        let out = d.handle(env(DieMsg::Commit { round: 1, n: 6 }, 10));
        let dispatch = &out.dispatches[0];
        let commitment = match parse(dispatch) {
            DieMsg::Committed { round, commitment } => {
                assert_eq!(round, 1);
                // The commitment body reveals nothing about the seed (it's a hash).
                assert_eq!(commitment.len(), 64);
                commitment
            }
            other => panic!("expected Committed, got {other:?}"),
        };
        // …and it rides the envelope commitment slot (the substrate's verifiable-randomness primitive).
        assert_eq!(
            dispatch.commitment.as_deref(),
            Some(commitment.as_str()),
            "commitment in the slot"
        );
        assert_eq!(d.pending_count(), 1);

        // Reveal with the requester's nonce.
        let out =
            d.handle(env(DieMsg::Reveal { round: 1, nonce: "requester-chose-this".into() }, 11));
        let (seed, pick) = match parse(&out.dispatches[0]) {
            DieMsg::Revealed { round, n, seed, nonce, pick } => {
                assert_eq!(round, 1);
                assert_eq!(n, 6);
                assert_eq!(nonce, "requester-chose-this");
                assert!(pick < 6, "pick is in range");
                (seed, pick)
            }
            other => panic!("expected Revealed, got {other:?}"),
        };
        assert_eq!(d.pending_count(), 0, "reveal consumes the pending round");

        // Anyone can verify: the commitment binds the seed, and the pick is the honest function.
        assert_eq!(
            verify_roll(&commitment, 1, 6, &seed, "requester-chose-this"),
            Some(pick),
            "an auditor recomputes the same pick from the public commitment + revealed seed + nonce"
        );
    }

    #[test]
    fn a_swapped_seed_at_reveal_is_caught_by_verification() {
        // The security property: a die that commits to seed A but reveals seed B is provably cheating
        // — verify_roll against the ORIGINAL commitment with the swapped seed returns None.
        let commitment = commitment_of(7, 4, &[0xAA; 32]);
        assert_eq!(
            verify_roll(&commitment, 7, 4, &hex(&[0xAA; 32]), "nonce"),
            Some(pick_of(&[0xAA; 32], "nonce", 4))
        );
        assert_eq!(
            verify_roll(&commitment, 7, 4, &hex(&[0xBB; 32]), "nonce"),
            None,
            "swapped seed fails"
        );
        // A tampered (round, n) also fails — the commitment binds them.
        assert_eq!(
            verify_roll(&commitment, 8, 4, &hex(&[0xAA; 32]), "nonce"),
            None,
            "wrong round fails"
        );
        assert_eq!(
            verify_roll(&commitment, 7, 5, &hex(&[0xAA; 32]), "nonce"),
            None,
            "wrong n fails"
        );
    }

    #[test]
    fn the_nonce_actually_mixes_into_the_pick() {
        // The requester's contribution matters: find two nonces that yield different picks for the
        // same committed seed (n large enough that a difference is near-certain among a few tries).
        let seed = [0x33; 32];
        let p0 = pick_of(&seed, "nonce-0", 1000);
        let differs = (1..20).any(|i| pick_of(&seed, &format!("nonce-{i}"), 1000) != p0);
        assert!(
            differs,
            "different requester nonces produce different picks (the requester co-determines)"
        );
    }

    #[test]
    fn pick_is_deterministic_for_the_same_inputs() {
        let seed = [0x44; 32];
        assert_eq!(pick_of(&seed, "x", 10), pick_of(&seed, "x", 10), "same inputs → same pick");
    }

    #[test]
    fn committing_zero_options_is_rejected() {
        let mut d = die_with([0x55; 32]);
        match parse(&d.handle(env(DieMsg::Commit { round: 1, n: 0 }, 1)).dispatches[0]) {
            DieMsg::Rejected { reason } => {
                assert!(reason.contains("zero options"), "reason: {reason}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(d.pending_count(), 0);
    }

    #[test]
    fn entropy_failure_rejects_commit_without_parking_a_round() {
        let mut d = VerifiableDie::new(Box::new(FailingEntropy));
        d.set_me_for_tests(ME);
        match parse(&d.handle(env(DieMsg::Commit { round: 7, n: 6 }, 1)).dispatches[0]) {
            DieMsg::Rejected { reason } => {
                assert!(reason.contains("entropy source failed"), "reason: {reason}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(d.pending_count(), 0, "failed entropy must not leave an unrevealable commit");
    }

    #[test]
    fn re_committing_a_pending_round_is_rejected_not_overwritten() {
        let mut d = die_with([0x66; 32]);
        d.handle(env(DieMsg::Commit { round: 1, n: 6 }, 1));
        match parse(&d.handle(env(DieMsg::Commit { round: 1, n: 6 }, 2)).dispatches[0]) {
            DieMsg::Rejected { reason } => {
                assert!(reason.contains("already committed"), "reason: {reason}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert_eq!(d.pending_count(), 1, "the original commit is untouched");
    }

    #[test]
    fn revealing_an_uncommitted_round_is_rejected() {
        let mut d = die_with([0x77; 32]);
        match parse(
            &d.handle(env(DieMsg::Reveal { round: 99, nonce: "x".into() }, 1)).dispatches[0],
        ) {
            DieMsg::Rejected { reason } => {
                assert!(reason.contains("no committed roll"), "reason: {reason}")
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_roll_rejects_zero_n_and_malformed_seed() {
        assert_eq!(verify_roll(&commitment_of(1, 0, &[0; 32]), 1, 0, &hex(&[0; 32]), "x"), None);
        assert_eq!(verify_roll("deadbeef", 1, 4, "not-hex-and-wrong-length", "x"), None);
    }

    #[test]
    fn malformed_payload_does_not_panic() {
        let mut d = die_with([0x88; 32]);
        let e = Envelope { header: header(SCHEMA, None), payload: b"{not json".to_vec() };
        assert!(d.handle(e).dispatches.is_empty());
    }

    #[test]
    fn unknown_schema_is_a_no_op() {
        let mut d = die_with([0x99; 32]);
        let e = Envelope { header: header("some.other.schema", None), payload: b"x".to_vec() };
        assert!(d.handle(e).dispatches.is_empty());
    }
}
