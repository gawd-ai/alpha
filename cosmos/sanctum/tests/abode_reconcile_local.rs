//! **The fork+merge half of the distributed self, in-process.** Where
//! `abode_migrate_local` proves single-active-fork hand-off, this proves the merge case:
//! two divergent snapshots of the *same* Abode are merged, through the real kernel, by a loaded
//! `abode-reconciler` running the reference LWW-Element-Map CRDT.
//!
//! Flow: build two signed forks of one self (overlapping + distinct keys, different logical times)
//! → load the reconciler on `Role::ABODE_RECONCILER` with the injected `LwwMapMerge` → send
//! `Reconcile { fork_a, fork_b }` → assert `Reconciled { merged }` where the merged state is the
//! LWW union (higher `ts` wins) and the merged snapshot is re-signed + integrity-valid.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use abode::AbodeSnapshot;
use abode_reconciler::{AbodeReconciler, ReconcilerConfig, ReconcilerMsg};
use aether::{Address, Deadline, Dispatch, Ed25519Verifier, InboxReceiver, Role, StubSigner};
use merge_lww_map::{Lww, LwwMapMerge};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

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

/// A signed fork of `abode`: an LWW-map state signed with the Abode key.
fn signed_fork(
    abode: &Ed25519KeyMaterial,
    entries: &[(&str, serde_json::Value, u64)],
) -> AbodeSnapshot {
    let map: BTreeMap<String, Lww> =
        entries.iter().map(|(k, v, ts)| (k.to_string(), Lww { v: v.clone(), ts: *ts })).collect();
    let state = serde_json::to_vec(&map).unwrap();
    let wrapped = abode_migrator::wrap_payload_v0_3(&state);
    let mut s = AbodeSnapshot::new(abode.public_hex().to_string(), wrapped);
    s.sign(abode);
    s
}

fn recv_reconciler(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<ReconcilerMsg> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env)
                if env.header.corr == Some(corr)
                    && env.header.schema == abode_reconciler::SCHEMA =>
            {
                if let Ok(msg) = ReconcilerMsg::parse(&env.payload) {
                    return Some(msg);
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

#[test]
fn abode_reconcile_local_merges_two_divergent_forks_of_one_self() {
    let abode = Ed25519KeyMaterial::from_seed([0x44u8; 32]).unwrap();
    let node_key = Ed25519KeyMaterial::from_seed([0xC4u8; 32]).unwrap();

    let k = Kernel::new(
        vec![
            Arc::new(anima::NativeEngine),
            Arc::new(anima::WasmEngine::new()),
            Arc::new(anima::ScriptEngine),
        ],
        Arc::new(StubSigner::new("v04-reconcile")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        64,
    );

    // The reconciler holds the SELF's Abode key + the injected LWW-Map CRDT.
    let reconciler =
        AbodeReconciler::new(ReconcilerConfig::new(abode.clone(), Box::new(LwwMapMerge)));
    let reconciler_id = k
        .load_instance(signed_boot_manifest("abode-reconciler", &node_key), Box::new(reconciler))
        .expect("reconciler admits");
    k.bind_role(Role::new(Role::ABODE_RECONCILER), reconciler_id);

    let (probe_id, probe, rx) = k.open_endpoint(Capabilities::default());

    // Two divergent forks of the SAME self:
    //  - "name": a wrote it at ts 1, b overwrote at ts 3 → b ("bob") wins.
    //  - "color": only a → kept.  "city": only b → kept.
    let fork_a = signed_fork(
        &abode,
        &[("name", serde_json::json!("alice"), 1), ("color", serde_json::json!("red"), 5)],
    );
    let fork_b = signed_fork(
        &abode,
        &[("name", serde_json::json!("bob"), 3), ("city", serde_json::json!("paris"), 2)],
    );

    probe
        .send(
            Dispatch::to(
                Address::Role(Role::new(Role::ABODE_RECONCILER)),
                ReconcilerMsg::Reconcile { fork_a, fork_b }.to_bytes(),
            )
            .with_schema(abode_reconciler::SCHEMA)
            .with_corr(1)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Reconcile routes to the bound reconciler");

    let merged = match recv_reconciler(&rx, 1, scaled(Duration::from_secs(3))).expect("a reply") {
        ReconcilerMsg::Reconciled { merged } => merged,
        other => panic!("expected Reconciled, got {other:?}"),
    };

    // The merged snapshot is a fresh authoritative state: re-signed by the self + integrity-valid.
    assert_eq!(merged.abode_key, abode.public_hex(), "merged is the same self");
    assert!(merged.verify_signature(&Ed25519Verifier).is_ok(), "re-signed by the Abode key");
    assert!(merged.assert_integrity().is_ok(), "merged state_hash matches its payload");

    // The merged STATE is the LWW union of the two forks.
    let state = abode_migrator::unwrap_payload_v0_3(&merged.payload_bytes).expect("v0.3 framing");
    let map: BTreeMap<String, Lww> = serde_json::from_slice(state).expect("an LWW map");
    assert_eq!(map["name"].v, serde_json::json!("bob"), "higher ts (3 > 1) wins");
    assert_eq!(map["color"].v, serde_json::json!("red"), "only in fork_a → kept");
    assert_eq!(map["city"].v, serde_json::json!("paris"), "only in fork_b → kept");
    assert_eq!(map.len(), 3, "union of all keys across the forks");

    k.shutdown_all(Deadline::from_millis(800));
}
