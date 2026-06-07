//! The additive `bestiary.op` schema — the durable-Bestiary operations that have no `RegistryOp`
//! equivalent: a portable [`EntryProof`] request, an operator-triggered compaction,
//! and PUSH replication. The `bestiary-daemon` serves these alongside `registry.op` (which it answers
//! byte-identically). `registry-mem` does not understand this schema and ignores it.
//!
//! Zero-retrofit: a brand-new schema string + brand-new enums; no existing `RegistryOp`/`RegistryReply`
//! wire shape changes.

use serde::{Deserialize, Serialize};
use sigil::RealmId;

use crate::store::{EntryProof, SignedSyncEntry};

/// The `bestiary.op` request set.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BestiaryOp {
    /// Ask for a standalone signed [`EntryProof`] over `(realm, artifact_hash)`.
    ProveEntry { artifact_hash: String, realm: RealmId },
    /// Trigger a compaction pass (GC + genesis rewrite + orphan-blob collection).
    Compact,
    /// PUSH replication: merge a batch of self-verifying peer entries.
    PushEntries { entries: Vec<SignedSyncEntry> },
}

/// The `bestiary.reply` response set.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum BestiaryReply {
    /// A verified-able attestation (reply to [`BestiaryOp::ProveEntry`]).
    EntryProof { proof: EntryProof },
    /// No live entry for the requested `(realm, artifact_hash)`.
    NotFound,
    /// Compaction stats (reply to [`BestiaryOp::Compact`]).
    Compacted { scanned: usize, gc: usize, quarantined: usize, blobs_removed: usize },
    /// How many pushed entries merged vs. were rejected (reply to [`BestiaryOp::PushEntries`]).
    PushAck { accepted: usize, rejected: usize },
    /// A structured failure (malformed op, store error) — never a panic (R9).
    Error { message: String },
}

impl BestiaryOp {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

impl BestiaryReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_tags_are_snake_case_and_round_trip() {
        let prove =
            BestiaryOp::ProveEntry { artifact_hash: "h".into(), realm: RealmId::new("crew") };
        let json = serde_json::to_string(&prove).unwrap();
        assert!(json.contains("\"op\":\"prove_entry\""));
        let compact = BestiaryOp::Compact;
        assert!(serde_json::to_string(&compact).unwrap().contains("\"op\":\"compact\""));
        let push = BestiaryOp::PushEntries { entries: vec![] };
        let bytes = push.to_bytes();
        let back: BestiaryOp = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(back, BestiaryOp::PushEntries { .. }));
    }

    #[test]
    fn reply_tags_are_snake_case() {
        let r = BestiaryReply::Compacted { scanned: 3, gc: 1, quarantined: 0, blobs_removed: 1 };
        assert!(serde_json::to_string(&r).unwrap().contains("\"reply\":\"compacted\""));
        let r = BestiaryReply::PushAck { accepted: 2, rejected: 1 };
        assert!(serde_json::to_string(&r).unwrap().contains("\"reply\":\"push_ack\""));
        assert!(serde_json::to_string(&BestiaryReply::NotFound).unwrap().contains("not_found"));
    }
}
