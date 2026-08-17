//! Single-Sanctum migrator-to-migrator hand-off (the "loopback" case).
//!
//! Exercises [`AbodeMigrator`]'s state machine over the bus with no transport involved: two
//! migrators on the same kernel, RestoreRequest delivered via `Address::Creature` (the migrator's
//! `self_node`-collapse). The state-machine + gate logic lives in `abode-migrator`'s unit tests
//! (23 tests there); this file proves the kernel + router wiring works against the same code
//! paths.
//!
//! ## What this test proves
//!
//! - #1: `creatures/abode-migrator` exists and loads via `kernel.load_instance` on
//!   [`Role::ABODE_MIGRATOR`].
//! - #2: `abode_migrate_local` — counter-state Abode migrates loopback (one Sanctum, two
//!   migrator creatures); source becomes `Migrated { to }`, destination becomes `Authoritative`
//!   with the same payload bytes.
//! - #8: The migrator's admission gate is an injected `RestorePolicy` creature
//!   (`AbodeAllowlistPolicy`); substrate ships none.
//!
//! ## What this test deliberately is NOT
//!
//! - Not a transport-stress test (no transport-tcp here).
//! - Not a state-machine coverage test (the migrator's unit suite covers SetState / SnapshotRequest /
//!   StatusQuery / pending-migration rejection / already-authoritative RestoreRequest / etc.).

use std::sync::Arc;
use std::time::Duration;

use abode_migrator::{AbodeMigrator, MigratorMsg, SCHEMA};
use aether::{Address, Deadline, Dispatch, InboxReceiver, NodeId, Role, StubSigner};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_abode_allowlist::AbodeAllowlistPolicy;
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

// ----- shared scaffolding (mirrors realm_local_route + distributor_local) ---------------------

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

const SELF_NODE: &str = "m9-local-node";

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m9-local")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

fn recv_match<F: Fn(&MigratorMsg) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<MigratorMsg> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == SCHEMA => {
                if let Ok(msg) = MigratorMsg::parse(&env.payload) {
                    if pred(&msg) {
                        return Some(msg);
                    }
                }
            }
            _ => continue,
        }
    }
    None
}

// =================================================================================================
// abode_migrate_local — one Sanctum, two migrators, acknowledged in-memory hand-off
// =================================================================================================

/// A counter-state Abode migrates loopback (one Sanctum, two migrator
/// creatures); source becomes `Migrated`, destination becomes `Authoritative` with the same
/// payload bytes; operator receives `MigrateAck { migrated_to: SELF_NODE }`.
#[test]
fn abode_migrate_local_two_migrators_on_one_sanctum_hand_off_state() {
    // One Abode key used both as the *signing identity* for both migrators (they're the same
    // Abode — the destination is a new body for the same self) and as
    // the *one entry* in the destination's allowlist. The ABODE is the self; the SANCTUM is the
    // body; the same Abode legitimately migrates between bodies it owns.
    let abode = Ed25519KeyMaterial::from_seed([0xA9u8; 32]).unwrap();
    let abode_pub = abode.public_hex().to_string();

    // The Sanctum's own boot/signing key (used to author boot manifests). Distinct from Abode
    // identity.
    let node_key = Ed25519KeyMaterial::from_seed([0xB9u8; 32]).unwrap();
    let allowlist = vec![abode_pub.clone(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

    // Two migrators on the same kernel. Both clone the same Abode key so they're the same self
    // in two bodies. This successful request/reply endpoint seals the source after the destination
    // activates; it does not claim a crash-safe no-overlap fence.
    //
    // The destination's allowlist trusts the Abode's pubkey, so the substrate-shipped gates +
    // the policy will both admit when the source ships its RestoreRequest.
    let dest_policy = Box::new(AbodeAllowlistPolicy::allowing(abode_pub.clone()));
    let dest_migrator = AbodeMigrator::new(NodeId(SELF_NODE.into()), abode.clone(), dest_policy);
    let dest_id = k
        .load_instance(
            signed_boot_manifest("abode-migrator-dest", &node_key),
            Box::new(dest_migrator),
        )
        .expect("dest migrator admits");

    // Source migrator. Its restore policy is irrelevant here (source never receives a restore);
    // use a permissive one with the same allowlist for symmetry.
    let src_policy = Box::new(AbodeAllowlistPolicy::allowing(abode_pub.clone()));
    let src_migrator = AbodeMigrator::new(NodeId(SELF_NODE.into()), abode.clone(), src_policy);
    let src_id = k
        .load_instance(
            signed_boot_manifest("abode-migrator-src", &node_key),
            Box::new(src_migrator),
        )
        .expect("src migrator admits");
    // The "role binding" of the canonical migrator: source is the operator-facing one.
    k.bind_role(Role::new(Role::ABODE_MIGRATOR), src_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    // ----- Phase 1: seed source's state ---------------------------------------------------------

    let set_state_corr = 1u64;
    probe_bus
        .send(
            Dispatch::to(
                Address::Creature(src_id),
                MigratorMsg::SetState { payload: b"the-self-counter=42".to_vec() }.to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(set_state_corr)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("SetState admits");
    let reply = recv_match(
        &probe_rx,
        set_state_corr,
        |m| matches!(m, MigratorMsg::StateSet),
        scaled(Duration::from_secs(3)),
    )
    .expect("StateSet reply received");
    assert!(matches!(reply, MigratorMsg::StateSet));

    // ----- Phase 2: hand off source → dest ------------------------------------------------------

    let migrate_corr = 2u64;
    probe_bus
        .send(
            Dispatch::to(
                Address::Creature(src_id),
                MigratorMsg::Migrate {
                    destination_node: NodeId(SELF_NODE.into()),
                    destination_migrator: dest_id,
                    // Local hand-off — the dest migrator signs a witness the source verifies; no
                    // pinned anchor (the responder's pubkey isn't known ahead of time here).
                    expected_responder_pubkey: None,
                }
                .to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(migrate_corr)
            .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("Migrate admits");
    // The migrator emits a RestoreRequest to dest_id (Address::Creature collapse since
    // destination_node == self_node), dest admits, RestoreResponse comes back to source, source
    // transitions Migrated, source replies MigrateAck to probe.
    let ack = recv_match(
        &probe_rx,
        migrate_corr,
        |m| matches!(m, MigratorMsg::MigrateAck { .. }),
        scaled(Duration::from_secs(5)),
    )
    .expect("MigrateAck received");
    match ack {
        MigratorMsg::MigrateAck { migrated_to } => {
            assert_eq!(migrated_to, NodeId(SELF_NODE.into()), "ack carries the destination node");
        }
        other => panic!("expected MigrateAck, got {other:?}"),
    }

    // ----- Phase 3: assert state on both migrators via StatusQuery ------------------------------

    // Source: should be Migrated { to: SELF_NODE }, payload_len: 0.
    let src_status_corr = 3u64;
    probe_bus
        .send(
            Dispatch::to(Address::Creature(src_id), MigratorMsg::StatusQuery.to_bytes())
                .with_schema(SCHEMA)
                .with_corr(src_status_corr)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("source StatusQuery admits");
    let src_status = recv_match(
        &probe_rx,
        src_status_corr,
        |m| matches!(m, MigratorMsg::StatusReply { .. }),
        scaled(Duration::from_secs(3)),
    )
    .expect("source status reply");
    match src_status {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            assert_eq!(state, "migrated");
            assert_eq!(migrated_to, Some(NodeId(SELF_NODE.into())));
            assert_eq!(payload_len, 0, "source's payload is gone after hand-off");
        }
        other => panic!("expected StatusReply, got {other:?}"),
    }

    // Destination: should be Authoritative with the original payload.
    let dest_status_corr = 4u64;
    probe_bus
        .send(
            Dispatch::to(Address::Creature(dest_id), MigratorMsg::StatusQuery.to_bytes())
                .with_schema(SCHEMA)
                .with_corr(dest_status_corr)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("dest StatusQuery admits");
    let dest_status = recv_match(
        &probe_rx,
        dest_status_corr,
        |m| matches!(m, MigratorMsg::StatusReply { .. }),
        scaled(Duration::from_secs(3)),
    )
    .expect("dest status reply");
    match dest_status {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            assert_eq!(state, "authoritative");
            assert!(migrated_to.is_none());
            // payload_len matches the original raw bytes (the migrator strips the v3.0 prefix
            // before storing, so what we get out matches what we put in).
            assert_eq!(payload_len, b"the-self-counter=42".len());
        }
        other => panic!("expected StatusReply, got {other:?}"),
    }

    // ----- Phase 4: snapshot dest, verify payload round-trips ----------------------------------

    let snap_corr = 5u64;
    probe_bus
        .send(
            Dispatch::to(Address::Creature(dest_id), MigratorMsg::SnapshotRequest.to_bytes())
                .with_schema(SCHEMA)
                .with_corr(snap_corr)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("dest SnapshotRequest admits");
    let snap = recv_match(
        &probe_rx,
        snap_corr,
        |m| matches!(m, MigratorMsg::SnapshotReply { .. }),
        scaled(Duration::from_secs(3)),
    )
    .expect("snapshot reply");
    let snapshot = match snap {
        MigratorMsg::SnapshotReply { snapshot } => snapshot,
        other => panic!("expected SnapshotReply, got {other:?}"),
    };
    // Substrate-shipped gates: snapshot is integrity-valid and signed under the Abode key.
    snapshot.assert_integrity().expect("dest snapshot integrity");
    snapshot.verify_signature(&Ed25519Verifier).expect("dest snapshot signature");
    // Payload starts with the v3.0 magic + carries the round-tripped state.
    let inner = abode_migrator::unwrap_payload_v0_3(&snapshot.payload_bytes)
        .expect("payload unwraps as v3.0");
    assert_eq!(inner, b"the-self-counter=42");
    assert_eq!(snapshot.abode_key, abode_pub);

    // The source migrator is sealed after hand-off — further `Migrate` rejects with
    // "migrator is sealed (already migrated…)". The migrator's unit suite covers that path
    // directly (`migrate_from_empty_returns_migrate_failed_no_authoritative_state` family);
    // we don't re-prove it here.

    k.shutdown_all(Deadline::from_millis(1500));
}
