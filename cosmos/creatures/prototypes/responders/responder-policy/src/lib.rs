//! `responder-policy` — the reference standing consumer for the SEER `policy` topic.
//!
//! The `policy` topic ([`seer::topics::policy`]) ships a typed admission-consult body
//! (`{ manifest_hash } → { admit, reason }`) but, until now, no creature that *stood* on it. This
//! creature is that reference: bind it to a SEER inbox and it answers every admission Query by a
//! simple, auditable rule — admit a manifest whose hash is on a configured **allowlist**, or admit
//! everything in the explicit dev posture.
//!
//! It is a *prototype*, not substrate: a real deployment forks the decision (check a signature, a
//! reputation slot, a quorum, a jurisdiction) while keeping the standing-responder skeleton from
//! [`seer::responder`]. The decision is the only part this creature writes; the wire, the topic
//! isolation, and the hostile-input drops are the shared skeleton's.
//!
//! ## What it deliberately doesn't do
//!
//! - **It doesn't fetch the manifest.** The Query carries only the hash; this reference decides on
//!   identity alone. A richer policy that needs the bytes asks for them out-of-band first.
//! - **It doesn't time out.** SEER carries no deadline the substrate enforces; this responder
//!   answers when it answers.
//! - **It never replies "deny" to a malformed Query.** A body it can't decode (or that fails the
//!   shape check) is dropped silently — the same posture as every consult creature.

use std::collections::HashSet;

use aether::{Creature, CreatureCtx, Envelope, Outcome};
use seer::{responder::respond_query, topics::policy, SeerTopic};

/// Maximum accepted `manifest_hash` length (bytes). A `sha256:<hex>` content address is 71 bytes;
/// this leaves generous headroom while bounding a hostile Query's retained scan cost.
pub const MAX_MANIFEST_HASH_BYTES: usize = 256;

/// The reference admission responder.
///
/// Stateless across calls: every Query is judged against the same allowlist, so retries and
/// reordering don't change the verdict.
pub struct PolicyResponder {
    allow: HashSet<String>,
    admit_unknown: bool,
}

impl PolicyResponder {
    /// An allowlist responder: admit a manifest whose hash is in `allow`, deny everything else.
    pub fn allowlist<I, S>(allow: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PolicyResponder { allow: allow.into_iter().map(Into::into).collect(), admit_unknown: false }
    }

    /// The explicit dev posture: admit every well-formed Query. Mirrors the dev policy disclosed at
    /// a non-clustered node's boot — convenient for a lab, never a production default.
    pub fn admit_all() -> Self {
        PolicyResponder { allow: HashSet::new(), admit_unknown: true }
    }

    /// Full control: an allowlist plus whether an *unknown* hash is admitted (`true` = allow-by
    /// -default with the allowlist as an audit record; `false` = the deny-by-default allowlist).
    pub fn new<I, S>(allow: I, admit_unknown: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PolicyResponder { allow: allow.into_iter().map(Into::into).collect(), admit_unknown }
    }

    fn decide(&self, q: policy::QueryBody) -> policy::AnswerBody {
        let listed = self.allow.contains(&q.manifest_hash);
        let admit = listed || self.admit_unknown;
        let reason = match (admit, listed) {
            (true, true) => "admit: manifest hash on allowlist",
            (true, false) => "admit: dev posture admits unknown manifests",
            (false, _) => "deny: manifest hash not on allowlist",
        };
        policy::AnswerBody { admit, reason: reason.to_string() }
    }
}

impl Creature for PolicyResponder {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        respond_query::<policy::QueryBody, policy::AnswerBody>(
            &env,
            SeerTopic::Policy,
            |q| !q.manifest_hash.is_empty() && q.manifest_hash.len() <= MAX_MANIFEST_HASH_BYTES,
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

    fn query(hash: &str) -> Envelope {
        let body = policy::QueryBody { manifest_hash: hash.to_string() };
        seer_env(SeerEnvelope::query(SeerTopic::Policy, 7, 1, &body).to_bytes())
    }

    fn verdict(out: &Outcome) -> policy::AnswerBody {
        let env = SeerEnvelope::parse(&out.dispatches[0].payload).unwrap();
        match env.kind {
            SeerKind::Answer { body, .. } => serde_json::from_value(body).unwrap(),
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_admits_listed_denies_unlisted() {
        let mut r = PolicyResponder::allowlist(["sha256:aa"]);
        assert!(verdict(&r.handle(query("sha256:aa"))).admit);
        assert!(!verdict(&r.handle(query("sha256:bb"))).admit);
    }

    #[test]
    fn admit_all_admits_any_wellformed() {
        let mut r = PolicyResponder::admit_all();
        assert!(verdict(&r.handle(query("sha256:anything"))).admit);
    }

    #[test]
    fn empty_or_oversized_hash_is_dropped_not_denied() {
        let mut r = PolicyResponder::admit_all();
        assert!(r.handle(query("")).dispatches.is_empty(), "empty hash → silent drop");
        let big = "x".repeat(MAX_MANIFEST_HASH_BYTES + 1);
        assert!(r.handle(query(&big)).dispatches.is_empty(), "oversized hash → silent drop");
    }

    #[test]
    fn wrong_topic_is_dropped() {
        let mut r = PolicyResponder::admit_all();
        let q = SeerEnvelope::query(SeerTopic::Budget, 7, 1, &serde_json::json!({"x": 1}));
        assert!(r.handle(seer_env(q.to_bytes())).dispatches.is_empty());
    }
}
