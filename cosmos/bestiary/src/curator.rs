//! The injected **curator** seam — what decides an entry's fate at compaction.
//!
//! The substrate ships the [`Curator`] trait and two reference fillings; the *policy* (what to keep,
//! promote, demote, quarantine, or collect) is injected, never substrate. This is the same IoC
//! discipline as every other model in the fabric — "ASI is the fabric, not the model."
//!
//! Two fillings ship:
//!
//! - [`DeterministicCurator`] — a pure, synchronous reference: GC an entry that is both old (a large
//!   `first_seen` age-gap behind the catalog's youngest) and weakly-scored. No model, no network.
//! - [`AICurator`] — consumes the injected [`Model`](mind::Model) seam to decide things a
//!   deterministic rule cannot: near-duplicate detection and anomaly scoring over an entry's
//!   `manifest` + `artifact` bytes. **Safe-by-default:** [`decide`](Curator::decide) returns
//!   [`CurationDecision::Keep`] for any entry it has not actually ruled on, so a compaction never
//!   destroys durable state on a cache miss. The (blocking) model call runs in
//!   [`observe`](Curator::observe), off the synchronous decide path — the daemon's compaction worker
//!   calls `observe` before `compact`, never under the store lock.
//!
//! The AI curator's prompt and completion parser bound untrusted text crossing the model seam:
//! catalog metadata is previewed before it enters the prompt, and the returned completion/reason is
//! capped before parsing so an injected or remote-backed model cannot force unbounded parser
//! allocation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sigil::RealmId;

use crate::wire::Entry;

/// Maximum bytes of one catalog metadata field included in an AI-curator prompt.
pub const MAX_AI_CURATOR_FIELD_BYTES: usize = 4 * 1024;
/// Maximum completion bytes the AI-curator parser inspects.
pub const MAX_AI_CURATOR_COMPLETION_BYTES: usize = 16 * 1024;
/// Maximum audit-reason bytes retained from a model curation verdict.
pub const MAX_AI_CURATOR_REASON_BYTES: usize = 1024;

/// What a [`Curator`] decides about one catalog entry.
#[derive(Clone, Debug, PartialEq)]
pub enum CurationDecision {
    /// Leave the entry exactly as it is (the safe default).
    Keep,
    /// Raise the entry's reputation to `score` (an unsigned, curator-authored score).
    Promote { score: f32 },
    /// Lower the entry's reputation to `score`.
    Demote { score: f32 },
    /// Mark the entry quarantined with `reason` (reversible; sticky across federation).
    Quarantine { reason: String },
    /// Permanently evict the entry (a tombstone — federates, never silently resurrected).
    Gc { reason: String },
}

/// What a [`Curator`] sees about one entry when it decides. Borrows the live entry (manifest +
/// artifact bytes + the two optional signals) plus the two age coordinates.
///
/// `first_seen` is the entry's compaction-stable birth order; `head_first_seen` is the catalog's
/// current high-water birth order (the youngest entry's). `head_first_seen - first_seen` is the
/// **age gap** — how many entries were born after this one — which a curator uses to reason about age
/// without a wall clock (the substrate ships none).
pub struct CurationContext<'a> {
    /// The Realm the entry lives in.
    pub realm: &'a RealmId,
    /// The entry's `sha256(artifact_bytes)` hex key.
    pub artifact_hash: &'a str,
    /// The live entry — `manifest`, `artifact` bytes, and the optional reputation/quarantine signals.
    pub entry: &'a Entry,
    /// The entry's birth order (compaction-stable; never reassigned).
    pub first_seen: u64,
    /// The catalog's current high-water birth order. `head_first_seen - first_seen` is the age gap.
    pub head_first_seen: u64,
}

impl CurationContext<'_> {
    /// How many entries were born after this one — the clock-free age measure.
    pub fn age_gap(&self) -> u64 {
        self.head_first_seen.saturating_sub(self.first_seen)
    }

    /// The entry's current reputation score, if any.
    pub fn score(&self) -> Option<f32> {
        self.entry.reputation.as_ref().map(|r| r.score)
    }
}

/// The injected curator. The substrate ships the trait; the operator binds a filling.
pub trait Curator: Send + Sync {
    /// Optionally pre-compute a decision for `ctx` off the synchronous [`decide`](Self::decide) path
    /// (an AI curator's blocking model call lands here; the daemon's compaction worker calls it
    /// *before* `compact`, never under the store lock). The default is a no-op — a deterministic
    /// curator decides synchronously in [`decide`](Self::decide).
    fn observe(&self, _ctx: &CurationContext) {}

    /// Decide this entry's fate. Must be **fast and lock-safe** — it runs under the store lock during
    /// compaction. An AI curator returns the decision it pre-computed in [`observe`](Self::observe),
    /// or [`CurationDecision::Keep`] on a cache miss (safe-by-default).
    fn decide(&self, ctx: &CurationContext) -> CurationDecision;
}

/// A pure, synchronous reference curator. Collects an entry that is **both** old (its age gap exceeds
/// `gc_after_age_gap`) **and** weakly-scored (below `min_keep_score`, treating an unscored entry as
/// score `0.0`). Everything else is kept. No model, no network — the deterministic baseline the
/// AI curator is measured against.
#[derive(Clone, Debug)]
pub struct DeterministicCurator {
    /// Age gap (entries-born-after) past which a weak entry becomes eligible for GC. `0` disables GC.
    pub gc_after_age_gap: u64,
    /// Reputation floor below which an old entry is GC'd. An entry at or above this is always kept.
    pub min_keep_score: f32,
}

impl Default for DeterministicCurator {
    fn default() -> Self {
        // Conservative: never GC (gap 0 disables), keep everything.
        DeterministicCurator { gc_after_age_gap: 0, min_keep_score: 0.0 }
    }
}

impl Curator for DeterministicCurator {
    fn decide(&self, ctx: &CurationContext) -> CurationDecision {
        if self.gc_after_age_gap == 0 {
            return CurationDecision::Keep;
        }
        let old = ctx.age_gap() > self.gc_after_age_gap;
        let weak = ctx.score().unwrap_or(0.0) < self.min_keep_score;
        if old && weak {
            CurationDecision::Gc { reason: "deterministic: old and weakly-scored".to_string() }
        } else {
            CurationDecision::Keep
        }
    }
}

/// An AI-driven curator. Consumes the injected [`Model`](mind::Model) to decide what a deterministic
/// rule cannot — near-duplicate detection / anomaly scoring over an entry's manifest + artifact bytes.
///
/// **Safe-by-default.** [`decide`](Curator::decide) returns [`CurationDecision::Keep`] for any entry
/// it has not actually ruled on, so a compaction never destroys durable state on a cache miss. The
/// (blocking) model call happens in [`observe`](Curator::observe) — the daemon's compaction worker
/// calls `observe` for each entry first (off the store lock), then `compact` reads the cache via
/// `decide`.
///
/// Constructed only via [`AICurator::new`] with an injected `Arc<dyn Model>`; there is no `Default`
/// and it is never shipped as a `.so` (a default fake model would silently curate against nothing).
pub struct AICurator {
    model: Arc<dyn mind::Model>,
    cache: Mutex<HashMap<(RealmId, String), CurationDecision>>,
}

impl AICurator {
    /// Build an AI curator over an injected model.
    pub fn new(model: Arc<dyn mind::Model>) -> Self {
        AICurator { model, cache: Mutex::new(HashMap::new()) }
    }

    /// The model id the curator consults (telemetry).
    pub fn model_label(&self) -> String {
        self.model.describe()
    }

    /// Build the curation prompt for one entry. The model is asked for a single decision token over
    /// the manifest + a bounded prefix of the artifact bytes (so a huge artifact can't blow the
    /// prompt). The contract is intentionally narrow: one of `KEEP` / `GC` / `QUARANTINE` with a short
    /// reason — the substrate parses the verb, the reason is audit material.
    fn prompt_for(ctx: &CurationContext) -> mind::Prompt {
        const ARTIFACT_PREVIEW: usize = 2048;
        let preview_len = ctx.entry.artifact.len().min(ARTIFACT_PREVIEW);
        let artifact_preview = String::from_utf8_lossy(&ctx.entry.artifact[..preview_len]);
        let realm = bounded_text(&ctx.realm.0, MAX_AI_CURATOR_FIELD_BYTES);
        let artifact_hash = bounded_text(ctx.artifact_hash, MAX_AI_CURATOR_FIELD_BYTES);
        let manifest_name = bounded_text(&ctx.entry.manifest.name, MAX_AI_CURATOR_FIELD_BYTES);
        let manifest_version =
            bounded_text(&ctx.entry.manifest.version, MAX_AI_CURATOR_FIELD_BYTES);
        let system_prompt = "You are a Bestiary curator. Given a creature's manifest and a prefix of \
             its artifact bytes, decide whether to KEEP it, GC it (a near-duplicate or dead weight), \
             or QUARANTINE it (anomalous or suspicious). Answer with exactly one line: the verb \
             (KEEP, GC, or QUARANTINE) followed by a short reason."
            .to_string();
        let user_prompt = format!(
            "Realm: {}\nArtifact hash: {}\nManifest name: {} v{}\nArtifact bytes (first {} of {}):\n{}",
            realm,
            artifact_hash,
            manifest_name,
            manifest_version,
            preview_len,
            ctx.entry.artifact.len(),
            artifact_preview,
        );
        mind::Prompt { system_prompt, user_prompt, max_tokens: 64, temperature: 0.0 }
    }

    /// Parse the model's completion into a decision. Fail-closed: anything the parser does not
    /// recognize as an explicit `GC`/`QUARANTINE` verb maps to [`CurationDecision::Keep`], so a
    /// garbled or hostile completion never destroys durable state.
    fn parse_decision(content: &str) -> CurationDecision {
        let content = prefix_on_char_boundary(content, MAX_AI_CURATOR_COMPLETION_BYTES);
        let line = content.trim().lines().next().unwrap_or("").trim();
        let raw_verb = line.split_whitespace().next().unwrap_or("");
        let verb = raw_verb.trim_end_matches(':');
        let reason = bounded_reason(line.strip_prefix(raw_verb).unwrap_or("").trim_start());
        let reason = if reason.is_empty() { "curator".to_string() } else { reason };
        if verb.eq_ignore_ascii_case("GC") {
            CurationDecision::Gc { reason }
        } else if verb.eq_ignore_ascii_case("QUARANTINE") {
            CurationDecision::Quarantine { reason }
        } else {
            // KEEP, an unknown verb, an error, or empty — all keep (safe-by-default).
            CurationDecision::Keep
        }
    }
}

fn prefix_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

fn bounded_text(s: &str, max: usize) -> String {
    let prefix = prefix_on_char_boundary(s, max);
    if prefix.len() == s.len() {
        prefix.to_string()
    } else {
        format!("{prefix}\n... (truncated; {} bytes total)", s.len())
    }
}

fn bounded_reason(s: &str) -> String {
    prefix_on_char_boundary(s, MAX_AI_CURATOR_REASON_BYTES).trim().to_string()
}

impl Curator for AICurator {
    fn observe(&self, ctx: &CurationContext) {
        let decision = match self.model.complete(Self::prompt_for(ctx)) {
            Ok(completion) => Self::parse_decision(&completion.content),
            Err(e) => {
                // A model error must never destroy durable state — keep, and surface the failure.
                eprintln!(
                    "bestiary curator: model call failed for {} in realm {} ({e}); keeping",
                    ctx.artifact_hash, ctx.realm.0
                );
                CurationDecision::Keep
            }
        };
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((ctx.realm.clone(), ctx.artifact_hash.to_string()), decision);
    }

    fn decide(&self, ctx: &CurationContext) -> CurationDecision {
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(ctx.realm.clone(), ctx.artifact_hash.to_string()))
            .cloned()
            // Safe-by-default: an entry the model never ruled on is kept.
            .unwrap_or(CurationDecision::Keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mind::{FakeModel, Model, Prompt};
    use sigil::{Backend, Manifest};

    fn entry(score: Option<f32>) -> Entry {
        Entry {
            manifest: Manifest::new("c", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            artifact: b"some-artifact-bytes".to_vec(),
            reputation: score.map(|s| crate::wire::ReputationScore::unsigned(s, None)),
            quarantine: None,
        }
    }

    fn ctx<'a>(
        realm: &'a RealmId,
        e: &'a Entry,
        first_seen: u64,
        head: u64,
    ) -> CurationContext<'a> {
        CurationContext { realm, artifact_hash: "h", entry: e, first_seen, head_first_seen: head }
    }

    #[test]
    fn deterministic_keeps_young_or_strong_and_gcs_old_weak() {
        let c = DeterministicCurator { gc_after_age_gap: 5, min_keep_score: 0.5 };
        let realm = RealmId::local();
        // Young (gap 2) → keep regardless of score.
        let e = entry(Some(0.0));
        assert_eq!(c.decide(&ctx(&realm, &e, 8, 10)), CurationDecision::Keep);
        // Old (gap 9) but strong (0.9 >= 0.5) → keep.
        let e = entry(Some(0.9));
        assert_eq!(c.decide(&ctx(&realm, &e, 1, 10)), CurationDecision::Keep);
        // Old (gap 9) and weak (0.1 < 0.5) → GC.
        let e = entry(Some(0.1));
        assert!(matches!(c.decide(&ctx(&realm, &e, 1, 10)), CurationDecision::Gc { .. }));
        // Old and unscored (treated as 0.0) → GC.
        let e = entry(None);
        assert!(matches!(c.decide(&ctx(&realm, &e, 1, 10)), CurationDecision::Gc { .. }));
    }

    #[test]
    fn deterministic_gap_zero_never_gcs() {
        let c = DeterministicCurator::default();
        let realm = RealmId::local();
        let e = entry(None);
        assert_eq!(c.decide(&ctx(&realm, &e, 0, u64::MAX)), CurationDecision::Keep);
    }

    #[test]
    fn ai_curator_keeps_on_cache_miss() {
        // decide() with nothing observed must Keep — never destroy durable state for an unruled entry.
        let c = AICurator::new(Arc::new(FakeModel::always_good()));
        let realm = RealmId::local();
        let e = entry(None);
        assert_eq!(c.decide(&ctx(&realm, &e, 0, 0)), CurationDecision::Keep);
    }

    #[test]
    fn ai_curator_observe_then_decide_uses_cache() {
        // The fake model returns a code block, not a verb → parse_decision falls through to Keep.
        let c = AICurator::new(Arc::new(FakeModel::always_good()));
        let realm = RealmId::local();
        let e = entry(None);
        c.observe(&ctx(&realm, &e, 0, 0));
        assert_eq!(c.decide(&ctx(&realm, &e, 0, 0)), CurationDecision::Keep);
    }

    #[test]
    fn parse_decision_is_fail_closed() {
        assert!(matches!(
            AICurator::parse_decision("GC near-duplicate of x"),
            CurationDecision::Gc { .. }
        ));
        assert!(matches!(
            AICurator::parse_decision("GC: near-duplicate of x"),
            CurationDecision::Gc { .. }
        ));
        assert!(matches!(
            AICurator::parse_decision("QUARANTINE looks like a fork bomb"),
            CurationDecision::Quarantine { .. }
        ));
        assert!(matches!(
            AICurator::parse_decision("QUARANTINE: looks like a fork bomb"),
            CurationDecision::Quarantine { .. }
        ));
        assert_eq!(AICurator::parse_decision("KEEP it's fine"), CurationDecision::Keep);
        assert_eq!(AICurator::parse_decision(""), CurationDecision::Keep);
        assert_eq!(AICurator::parse_decision("```rust\nfn main(){}\n```"), CurationDecision::Keep);
        // A GC verb with no reason still parses, with a placeholder reason.
        match AICurator::parse_decision("GC") {
            CurationDecision::Gc { reason } => assert_eq!(reason, "curator"),
            other => panic!("expected Gc, got {other:?}"),
        }
    }

    #[test]
    fn ai_curator_prompt_bounds_untrusted_metadata_fields() {
        let mut e = entry(None);
        e.manifest.name = "n".repeat(MAX_AI_CURATOR_FIELD_BYTES + 256);
        e.manifest.version = "v".repeat(MAX_AI_CURATOR_FIELD_BYTES + 256);
        let realm = RealmId("r".repeat(MAX_AI_CURATOR_FIELD_BYTES + 256));
        let artifact_hash = "h".repeat(MAX_AI_CURATOR_FIELD_BYTES + 256);

        let prompt = AICurator::prompt_for(&CurationContext {
            realm: &realm,
            artifact_hash: &artifact_hash,
            entry: &e,
            first_seen: 0,
            head_first_seen: 0,
        });

        assert!(prompt.user_prompt.contains("truncated"), "prompt should mark bounded previews");
        assert!(
            prompt.user_prompt.len() < (MAX_AI_CURATOR_FIELD_BYTES * 4) + 4096,
            "prompt metadata previews should stay bounded; len={}",
            prompt.user_prompt.len()
        );
    }

    #[test]
    fn ai_curator_completion_and_reason_are_bounded_before_parsing() {
        let oversized_reason = "x".repeat(MAX_AI_CURATOR_REASON_BYTES + 4096);
        match AICurator::parse_decision(&format!("QUARANTINE: {oversized_reason}")) {
            CurationDecision::Quarantine { reason } => {
                assert_eq!(reason.len(), MAX_AI_CURATOR_REASON_BYTES);
                assert!(reason.bytes().all(|b| b == b'x'));
            }
            other => panic!("expected Quarantine, got {other:?}"),
        }

        let late_verdict =
            format!("{}GC duplicate", " ".repeat(MAX_AI_CURATOR_COMPLETION_BYTES + 1));
        assert_eq!(
            AICurator::parse_decision(&late_verdict),
            CurationDecision::Keep,
            "a verdict beyond the completion cap fails closed"
        );
    }

    // A model that returns a chosen verb, to exercise observe→decide caching end to end.
    struct VerbModel(&'static str);
    impl Model for VerbModel {
        fn complete(&self, _req: Prompt) -> Result<mind::Completion, mind::ModelError> {
            Ok(mind::Completion { content: self.0.to_string(), model: "verb".into(), usage: None })
        }
        fn describe(&self) -> String {
            "verb-model".into()
        }
    }

    #[test]
    fn ai_curator_caches_a_gc_verdict() {
        let c = AICurator::new(Arc::new(VerbModel("GC duplicate")));
        let realm = RealmId::local();
        let e = entry(None);
        c.observe(&ctx(&realm, &e, 0, 0));
        assert!(matches!(c.decide(&ctx(&realm, &e, 0, 0)), CurationDecision::Gc { .. }));
    }
}
