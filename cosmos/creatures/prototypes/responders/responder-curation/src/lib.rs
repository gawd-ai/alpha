//! `responder-curation` — the reference standing consumer for the SEER `curation` topic.
//!
//! The `curation` topic ([`seer::topics::curation`]) is the durable Bestiary's **external-curator
//! seam**: a daemon's compaction/anti-entropy thread asks "what should I do with this entry?" off
//! the synchronous decide path, so a model call never blocks the catalog. The body is
//! `{ realm, artifact_hash, manifest_hash } → { decision, reason }`, where `decision` mirrors
//! `bestiary::CurationDecision`'s verbs: `keep` / `gc` / `quarantine`.
//!
//! This reference responder decides from two configured sets keyed by `artifact_hash` — a
//! quarantine set and a gc set — and **keeps everything else**. The in-process `bestiary::AICurator`
//! curates directly over an injected `mind::Model` today; this creature is the off-box alternative
//! an operator forks to host curation in a dedicated Sanctum. Keep-by-default is the safe posture:
//! an unrecognized entry is never silently dropped.

use std::collections::HashSet;

use aether::{Creature, CreatureCtx, Envelope, Outcome};
use seer::{responder::respond_query, topics::curation, SeerTopic};

/// The verb a curation answer carries — kept as `&'static str`s so they can't drift from the
/// `bestiary::CurationDecision` vocabulary by a typo.
pub mod decision {
    /// Retain the entry as-is.
    pub const KEEP: &str = "keep";
    /// Garbage-collect the entry (compaction reclaims it).
    pub const GC: &str = "gc";
    /// Quarantine the entry (retained but withheld from serving).
    pub const QUARANTINE: &str = "quarantine";
}

/// Maximum accepted `realm` length (bytes).
pub const MAX_REALM_BYTES: usize = 256;
/// Maximum accepted hash length (bytes) — applies to both `artifact_hash` and `manifest_hash`.
pub const MAX_HASH_BYTES: usize = 256;

/// The reference curation responder. Quarantine takes precedence over gc when a hash is on both
/// lists — withholding is the more conservative action.
pub struct CurationResponder {
    quarantine: HashSet<String>,
    gc: HashSet<String>,
}

impl CurationResponder {
    /// Keep everything — the trivial baseline (every entry stays).
    pub fn keep_all() -> Self {
        CurationResponder { quarantine: HashSet::new(), gc: HashSet::new() }
    }

    /// Configure the quarantine and gc sets (by `artifact_hash`). Everything else is kept.
    pub fn new<I, J, S, T>(quarantine: I, gc: J) -> Self
    where
        I: IntoIterator<Item = S>,
        J: IntoIterator<Item = T>,
        S: Into<String>,
        T: Into<String>,
    {
        CurationResponder {
            quarantine: quarantine.into_iter().map(Into::into).collect(),
            gc: gc.into_iter().map(Into::into).collect(),
        }
    }

    fn decide(&self, q: curation::QueryBody) -> curation::AnswerBody {
        let (decision, reason) = if self.quarantine.contains(&q.artifact_hash) {
            (decision::QUARANTINE, "artifact hash on quarantine list")
        } else if self.gc.contains(&q.artifact_hash) {
            (decision::GC, "artifact hash on gc list")
        } else {
            (decision::KEEP, "default: retain unrecognized entry")
        };
        curation::AnswerBody { decision: decision.to_string(), reason: reason.to_string() }
    }
}

impl Creature for CurationResponder {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        respond_query::<curation::QueryBody, curation::AnswerBody>(
            &env,
            SeerTopic::Curation,
            |q| {
                q.realm.len() <= MAX_REALM_BYTES
                    && !q.artifact_hash.is_empty()
                    && q.artifact_hash.len() <= MAX_HASH_BYTES
                    && q.manifest_hash.len() <= MAX_HASH_BYTES
            },
            |q| self.decide(q),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Header};
    use seer::{SeerEnvelope, SeerKind};

    fn seer_env(payload: Vec<u8>) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(99)),
                reply_to: Some(Address::Creature(CreatureId(11))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: seer::SCHEMA.to_string(),
                origin: None,
            },
            payload,
        }
    }

    fn query(artifact: &str) -> Envelope {
        let body = curation::QueryBody {
            realm: "global".into(),
            artifact_hash: artifact.to_string(),
            manifest_hash: "sha256:mm".into(),
        };
        seer_env(SeerEnvelope::query(SeerTopic::Curation, 7, 1, &body).to_bytes())
    }

    fn verdict(out: &Outcome) -> curation::AnswerBody {
        let env = SeerEnvelope::parse(&out.dispatches[0].payload).unwrap();
        match env.kind {
            SeerKind::Answer { body, .. } => serde_json::from_value(body).unwrap(),
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn keeps_by_default() {
        let mut r = CurationResponder::keep_all();
        assert_eq!(verdict(&r.handle(query("sha256:aa"))).decision, decision::KEEP);
    }

    #[test]
    fn routes_to_configured_lists() {
        let mut r = CurationResponder::new(["sha256:bad"], ["sha256:old"]);
        assert_eq!(verdict(&r.handle(query("sha256:bad"))).decision, decision::QUARANTINE);
        assert_eq!(verdict(&r.handle(query("sha256:old"))).decision, decision::GC);
        assert_eq!(verdict(&r.handle(query("sha256:fresh"))).decision, decision::KEEP);
    }

    #[test]
    fn quarantine_precedes_gc_when_listed_on_both() {
        let mut r = CurationResponder::new(["sha256:x"], ["sha256:x"]);
        assert_eq!(
            verdict(&r.handle(query("sha256:x"))).decision,
            decision::QUARANTINE,
            "withholding beats reclaiming when ambiguous"
        );
    }

    #[test]
    fn empty_artifact_hash_is_dropped() {
        let mut r = CurationResponder::keep_all();
        assert!(r.handle(query("")).dispatches.is_empty(), "empty artifact hash → silent drop");
    }
}
