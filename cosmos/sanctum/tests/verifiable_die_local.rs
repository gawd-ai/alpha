//! **The envelope `commitment` slot carries a verifiable-randomness commitment across the
//! real bus** (consumed in-process).
//!
//! Proves three things through a loaded `verifiable-die` creature, on the real kernel bus:
//! 1. **Commit** — the die replies `Committed { commitment }` and the commitment **also rides the
//!    reply envelope's `commitment` header slot** (so a relay or live observer carries it without
//!    parsing the body — the substrate's primitive is real on the wire, not just in a payload; the
//!    metadata-only router journal deliberately does not retain it).
//! 2. **Reveal** — the die reveals the seed + the pick for the requester's nonce.
//! 3. **Verify** — `verify_roll(commitment, round, n, seed, nonce)` (the function any skeptical peer
//!    runs) recomputes the same pick from the public commitment + revealed seed + agreed nonce.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{Address, Deadline, Dispatch, Ed25519Verifier, Envelope, InboxReceiver, StubSigner};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use verifiable_die::{verify_roll, DieMsg, FixedEntropy, VerifiableDie};

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}
fn scaled(d: Duration) -> Duration {
    d * (slow_factor() as u32)
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

/// Receive the first envelope matching `corr` that parses as a `DieMsg`, returning the envelope (so
/// the test can inspect the `commitment` header slot too).
fn recv_die(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<(Envelope, DieMsg)> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env)
                if env.header.corr == Some(corr) && env.header.schema == verifiable_die::SCHEMA =>
            {
                if let Ok(msg) = DieMsg::parse(&env.payload) {
                    return Some((env, msg));
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

#[test]
fn verifiable_die_commitment_rides_the_slot_and_the_pick_verifies() {
    let node_key = Ed25519KeyMaterial::from_seed([0xD4u8; 32]).unwrap();
    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("v04-die")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        64,
    );

    // A FixedEntropy die so the test is deterministic (reference-only seed — never production).
    let die = VerifiableDie::new(Box::new(FixedEntropy([0x5Au8; 32])));
    let die_id = k
        .load_instance(signed_boot_manifest("verifiable-die", &node_key), Box::new(die))
        .expect("verifiable-die admits");

    let (probe_id, probe, rx) = k.open_endpoint(Capabilities::default());

    const ROUND: u64 = 1;
    const N: u32 = 6;
    const NONCE: &str = "requester-picked-this-without-seeing-the-seed";

    // ----- Commit: the commitment must arrive in BOTH the body and the envelope slot --------------
    probe
        .send(
            Dispatch::to(
                Address::Creature(die_id),
                DieMsg::Commit { round: ROUND, n: N }.to_bytes(),
            )
            .with_schema(verifiable_die::SCHEMA)
            .with_corr(1)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Commit sends");
    let (commit_env, commit_msg) =
        recv_die(&rx, 1, scaled(Duration::from_secs(3))).expect("Committed reply");
    let commitment = match commit_msg {
        DieMsg::Committed { round, commitment } => {
            assert_eq!(round, ROUND);
            commitment
        }
        other => panic!("expected Committed, got {other:?}"),
    };
    // THE POINT: the commitment rode the envelope's `commitment` header slot across the real bus.
    assert_eq!(
        commit_env.header.commitment.as_deref(),
        Some(commitment.as_str()),
        "the verifiable-randomness commitment must ride the envelope `commitment` slot, not just the body"
    );

    // ----- Reveal: the die discloses the seed + pick for the requester's nonce --------------------
    probe
        .send(
            Dispatch::to(
                Address::Creature(die_id),
                DieMsg::Reveal { round: ROUND, nonce: NONCE.into() }.to_bytes(),
            )
            .with_schema(verifiable_die::SCHEMA)
            .with_corr(2)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Reveal sends");
    let (_e, reveal_msg) =
        recv_die(&rx, 2, scaled(Duration::from_secs(3))).expect("Revealed reply");
    let (seed, pick) = match reveal_msg {
        DieMsg::Revealed { round, n, seed, nonce, pick } => {
            assert_eq!(round, ROUND);
            assert_eq!(n, N);
            assert_eq!(nonce, NONCE);
            assert!(pick < N);
            (seed, pick)
        }
        other => panic!("expected Revealed, got {other:?}"),
    };

    // ----- Verify: any skeptical peer recomputes the same pick from the public inputs -------------
    assert_eq!(
        verify_roll(&commitment, ROUND, N, &seed, NONCE),
        Some(pick),
        "the commitment binds the seed; the revealed roll verifies — a 'random' pick anyone can audit"
    );
    // And a swapped seed against the same commitment is provable cheating.
    let other_seed = "00".repeat(32);
    assert_eq!(
        verify_roll(&commitment, ROUND, N, &other_seed, NONCE),
        None,
        "a swapped seed fails to verify"
    );

    k.shutdown_all(Deadline::from_millis(800));
}
