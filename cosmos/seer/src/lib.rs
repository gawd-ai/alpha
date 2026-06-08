//! SEER — substrate-wide Query/Answer/Steer/Progress/Thought at the bus level.
//!
//! An AUTHORING-specific conversation would define
//! `AuthoringQuery / AuthoringAnswer / AuthoringSteer / AuthoringProgress / AuthoringThought`
//! schemas living in `creatures/agent-templated` — wire-correct, but narrow. Every
//! other "ask N somethings and reconcile" socket the operating model needs (placement, policy,
//! budget, fitness, consensus) would replay the same five shapes per role; consensus / VRF / weight
//! models would land as N more divergent schemas, not as SEER consumers.
//!
//! SEER lifts the pattern into one primitive. Every consult-and-reconcile conversation
//! rides one [`SeerEnvelope`] carrying a *topic* (which kind of
//! conversation), a *corr* (the thread id), and a *kind* (Query | Answer | Steer | Progress |
//! Thought). Per-topic typed schemas live under [`topics`] — the **wire
//! format is identical** across topics; only the
//! `body` payload's typed interpretation differs.
//!
//! ## Why "seer" (not "oracle")
//!
//! "Seer" — one who sees and tells, consulted for insight — fits GAWD's cosmology (Aether, Sanctum,
//! Realm, Omega, Abode) and ties to the *sense-stream* root of Loop 1 (sense → decide → act).
//! "Oracle" carries trademark baggage from Oracle Corporation; we'd rather not litigate that.
//! Generic "test oracle" / "ASan oracle" usage elsewhere in the codebase keeps the English term
//! intact — only this primitive is named *seer*.
//!
//! ## Properties this module commits to
//!
//! - **One schema string** ([`SCHEMA`] = `"seer"`). The router sees no new wire format; the
//!   SeerEnvelope is just a payload schema riding [`aether::Envelope`] (S1 mitigation: zero new
//!   bus contracts).
//! - **Topic registry is a const enum** ([`SeerTopic`]). Adding a topic is
//!   a one-line addition here + a typed-body reservation under [`topics`]; the
//!   substrate stays small. Reserved topics
//!   compile from the moment they exist — consumers slot in without widening the contract.
//! - **Reduction theorem per topic.** A creature that answers a topic *immediately* (one terminal
//!   reply, no intermediate Query→Answer thread) is wire-equivalent to a single-shot
//!   responder. The SeerEnvelope shape admits richer conversations; it never *requires* them.
//! - **Topic isolation by creature discrimination.** An envelope on topic A is delivered like any
//!   other envelope (by address); the creature checks `seer.topic` before consuming. A creature
//!   bound to topic A that sees topic B drops the envelope (no model in the substrate decides
//!   what cross-topic means; that's the consumer's call).
//! - **Steer is generic.** `Steer{kind, payload}` works for arbitrary topic — "abort" / "amend"
//!   / "info" are conventions, never substrate primitives. Whether a creature acts on a steer is
//!   the creature's model — a substrate-wide guarantee.
//!
//! ## What this module deliberately does NOT do
//!
//! - **No router-level corr table.** SEER envelopes route the same way as any envelope: by address.
//!   A future router-side corr index (for orphan detection, conversation-done events,
//!   journal-by-conversation queries) remains an additive enhancement; the discipline is "no
//!   kernel responsibilities added."
//! - **No timeout enforcement.** `deadline_ms` (where it appears in a topic's typed body) is
//!   advisory; time is injected policy, never fabric. A consumer that
//!   needs a deadline rides it on top, never inside.
//! - **No payload schema for Steer.** Steer's `payload` is `serde_json::Value` opaque; two
//!   creatures sharing a `kind`+`payload` meaning is their contract, not the substrate's.

use serde::{Deserialize, Serialize};

/// Schema string carried in [`aether::Envelope::header.schema`](aether::Header) for every SEER
/// envelope. Single value across every topic — the topic discrimination lives in the payload's
/// [`SeerEnvelope::topic`], not in the wire schema (S1: one bus contract, never N per role).
pub const SCHEMA: &str = "seer";

/// Default maximum serialized [`SeerEnvelope`] payload accepted by live SEER consumers.
///
/// SEER is a high-volume consult/sense stream; this cap prevents direct bus traffic from forcing a
/// consumer to allocate and parse arbitrarily large opaque JSON bodies. Consumers may opt into a
/// narrower limit with [`SeerEnvelope::parse_with_limit`].
pub const MAX_SEER_ENVELOPE_BYTES: usize = 1024 * 1024;

/// Error returned by bounded SEER parsing.
#[derive(Debug, thiserror::Error)]
pub enum SeerParseError {
    #[error("seer envelope payload too large: {len} bytes exceeds {limit} byte limit")]
    TooLarge { len: usize, limit: usize },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// The reserved set of SEER topics. Adding a topic is a one-line addition here plus a typed-body
/// reservation under [`topics`]. The set is closed at the substrate level — a creature using a
/// topic the substrate doesn't know cannot lift consensus / weight / VRF up to a model later
/// without changing the wire.
///
/// The topics and their consumers:
/// - `Authoring` — consumed by `agent-curious`.
/// - `Placement` — consumed by `distributor-requirements` + `embodiment-advertiser`.
/// - `Consensus` — consumed by `creatures/omega-federator` (signed reputation deltas).
/// - `Policy`, `Budget`, `Fitness`, `Curation` — reserved/draft typed bodies; consumers may use the
///   generic SEER envelope without changing the wire. `Curation` is the durable Bestiary's
///   external-curator consult seam (the in-process `bestiary::AICurator` curates directly today).
///
/// `snake_case` serde rename matches the on-wire convention used by every other enum in `aether`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeerTopic {
    /// The authoring conversation — Query/Answer/Steer/Progress/Thought between an
    /// orchestrator and an authoring creature. Carries `AuthoringQuery`/`Answer`/
    /// `Steer`/`Progress`/`Thought` on this topic; the reduction theorem stays preserved.
    Authoring,
    /// The distributor consult — a Distributor (bound to `Intent`) asks N embodiments via
    /// `placement` and reconciles by its own model (round-robin / verifiable-die / first-fit /
    /// consult-N-somethings).
    Placement,
    /// Admission-policy consultation. Reserved/draft topic for richer admission than the current
    /// mechanically-applied policy examples.
    Policy,
    /// `BudgetRequest` / `ExtendBudget` consultation topic. Reserved/draft typed body; the
    /// live budget path currently uses proprioception events plus `KernelControl::ExtendBudget`.
    Budget,
    /// Loop 2's selection signal — fitness-score consultation across N raters. Reserved/draft typed
    /// body; the current local selector uses an injected scorer trait and registry promotion.
    Fitness,
    /// Weighted-vote / VRF / quorum reconciliation. Live topic: the Omega federator uses it
    /// for signed reputation deltas; additional consensus mechanisms can land as consumers without
    /// changing the bus shape.
    Consensus,
    /// The durable Bestiary's curation consult — a daemon's anti-entropy/compaction thread asks an
    /// injected curator creature whether to keep / GC / quarantine an entry. **Reserved/draft typed
    /// body** (`bestiary::AICurator` curates in-process today over the injected `mind::Model`; this
    /// topic is the seam for an *external* curator creature, consulted off the synchronous decide
    /// path so the model call never blocks the catalog).
    Curation,
}

impl SeerTopic {
    /// The on-wire string form (matches the serde tag — useful for fmt/log without spinning JSON).
    pub fn as_str(self) -> &'static str {
        match self {
            SeerTopic::Authoring => "authoring",
            SeerTopic::Placement => "placement",
            SeerTopic::Policy => "policy",
            SeerTopic::Budget => "budget",
            SeerTopic::Fitness => "fitness",
            SeerTopic::Consensus => "consensus",
            SeerTopic::Curation => "curation",
        }
    }
}

/// The body of a [`SeerEnvelope`] — one of five conversation moves:
/// - `Query` (outbound from initiator) — *I'm asking; here's the question* + a `query_id` so
///   multi-outstanding-queries-per-corr stay disambiguated.
/// - `Answer` (inbound to initiator) — matched to a `Query` by `(corr, query_id)`. The pairing
///   key survives the wire.
/// - `Steer` (inbound) — mid-flight intervention (`kind` = `"abort"` | `"amend"` | `"info"` by
///   convention; substrate is opaque to meaning).
/// - `Progress` (outbound) — observable trajectory (`stage` + optional `fraction` + optional
///   `note`). Optional fields elide from the wire when `None`.
/// - `Thought` (outbound) — observable reasoning (`channel` distinguishes internal deliberation
///   from external-facing prose).
///
/// `body` (on Query/Answer) is a typed-but-opaque `serde_json::Value` — the per-topic body shape
/// lives in [`topics`] modules and is the consumer's typed contract. The substrate doesn't decode
/// it; the bound creature does.
///
/// Serde tag is `"op"` (not `"kind"`) so the `Steer { kind, payload }` variant's `kind` field
/// doesn't collide with the discriminator. On the wire: `{"op":"query","query_id":1,"body":...}`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SeerKind {
    /// The initiator asks. `query_id` is local to this `corr` thread — a creature with several
    /// outstanding queries uses it to match each [`SeerKind::Answer`] back to the right one.
    Query { query_id: u64, body: serde_json::Value },
    /// The respondent answers. Matched to a [`Query`](SeerKind::Query) by `(envelope.corr,
    /// query_id)`; a mismatch is a stale/spoofed answer and is dropped by the consumer.
    Answer { query_id: u64, body: serde_json::Value },
    /// Inbound mid-flight intervention. `kind` is convention (`"abort"` | `"amend"` | `"info"`);
    /// `payload` is opaque to the substrate. A creature can ignore all steers and the conversation
    /// still completes on its terminal envelope (reduction theorem holds).
    Steer { kind: String, payload: serde_json::Value },
    /// Outbound observable trajectory. `stage` is required; `fraction`/`note` are advisory and
    /// elide from the wire when `None` so a minimal-progress creature emits a tiny envelope.
    Progress {
        stage: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fraction: Option<f32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Outbound observable reasoning — the Loop 2 selection signal (a creature whose reasoning is
    /// observable is selectable by reasoning quality, not just outcome). `channel` distinguishes
    /// internal deliberation from external-facing prose.
    Thought { channel: String, content: String },
}

/// One SEER envelope. Carried as the JSON payload of an [`aether::Envelope`] whose
/// `header.schema` is [`SCHEMA`]. The `Envelope.header.corr` SHOULD match `SeerEnvelope.corr`
/// (the router routes by address; the payload preserves `corr` for self-contained consumers and
/// for journal-by-conversation queries a future router-side index could add).
///
/// **No constructor enforces it**, but creating via [`SeerEnvelope::query`] /
/// [`SeerEnvelope::answer`] / [`SeerEnvelope::steer`] / [`SeerEnvelope::progress`] /
/// [`SeerEnvelope::thought`] is the typed path that keeps the discrimination consistent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SeerEnvelope {
    /// Which conversation kind this envelope belongs to. The consumer reads this and drops
    /// envelopes whose topic doesn't match its binding (topic isolation by creature
    /// discrimination — there's no router-level enforcement, by design).
    pub topic: SeerTopic,
    /// The thread id. Matches the originating envelope's `header.corr`. Mirrored here so a
    /// journal entry's payload self-identifies (journal entries carry `corr` in their header but
    /// not the payload schema).
    pub corr: u64,
    /// What move this envelope makes in the conversation. See [`SeerKind`].
    pub kind: SeerKind,
}

impl SeerEnvelope {
    /// Construct a `Query` envelope on `topic`/`corr` with a typed body. The body is serialized to
    /// `serde_json::Value` (via [`aether::wire::to_value`]) so the consumer can typed-decode it
    /// against the per-topic schema in [`topics`]. A body of an un-serializable shape — a bug, not
    /// a runtime condition for any wire type (see [`aether::wire`]) — trips a `debug_assert!` in dev
    /// and degrades to `serde_json::Value::Null` in release; the consumer reads `Null` as "empty
    /// body" rather than panicking.
    pub fn query<T: Serialize>(topic: SeerTopic, corr: u64, query_id: u64, body: &T) -> Self {
        let body = aether::wire::to_value(body);
        SeerEnvelope { topic, corr, kind: SeerKind::Query { query_id, body } }
    }
    /// Construct an `Answer` envelope on `topic`/`corr` with a typed body.
    pub fn answer<T: Serialize>(topic: SeerTopic, corr: u64, query_id: u64, body: &T) -> Self {
        let body = aether::wire::to_value(body);
        SeerEnvelope { topic, corr, kind: SeerKind::Answer { query_id, body } }
    }
    /// Construct a `Steer` envelope. `kind` is convention (`"abort"` | `"amend"` | `"info"` are
    /// the established ones; consumers are free to define more — substrate is opaque).
    pub fn steer<T: Serialize>(topic: SeerTopic, corr: u64, kind: &str, payload: &T) -> Self {
        let payload = aether::wire::to_value(payload);
        SeerEnvelope { topic, corr, kind: SeerKind::Steer { kind: kind.to_string(), payload } }
    }
    /// Construct a `Progress` envelope. `fraction`/`note` are optional and elide from the wire.
    pub fn progress(
        topic: SeerTopic,
        corr: u64,
        stage: &str,
        fraction: Option<f32>,
        note: Option<&str>,
    ) -> Self {
        SeerEnvelope {
            topic,
            corr,
            kind: SeerKind::Progress {
                stage: stage.to_string(),
                fraction,
                note: note.map(|s| s.to_string()),
            },
        }
    }
    /// Construct a `Thought` envelope. `channel` is `"internal"` (deliberation, audit material)
    /// or `"external"` (prose the creature wants surfaced).
    pub fn thought(topic: SeerTopic, corr: u64, channel: &str, content: &str) -> Self {
        SeerEnvelope {
            topic,
            corr,
            kind: SeerKind::Thought { channel: channel.to_string(), content: content.to_string() },
        }
    }

    /// Serialize for the [`aether::Envelope::payload`] via [`aether::wire::to_bytes`] — infallible
    /// for this type (a `debug_assert!` would fire on the impossible serialize failure; release
    /// degrades to empty, which the receiver drops as malformed).
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    /// Parse from a payload byte slice. Returns the serde error verbatim so the consumer can
    /// surface a structured "malformed seer envelope" rather than a panic.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
    /// Parse from a payload byte slice after enforcing [`MAX_SEER_ENVELOPE_BYTES`].
    pub fn parse_bounded(bytes: &[u8]) -> Result<Self, SeerParseError> {
        Self::parse_with_limit(bytes, MAX_SEER_ENVELOPE_BYTES)
    }
    /// Parse from a payload byte slice with a caller-supplied byte limit.
    pub fn parse_with_limit(bytes: &[u8], limit: usize) -> Result<Self, SeerParseError> {
        if bytes.len() > limit {
            return Err(SeerParseError::TooLarge { len: bytes.len(), limit });
        }
        Ok(Self::parse(bytes)?)
    }
}

/// Per-topic typed body schemas. Reserved even when no consumer ships yet — adding a
/// consumer later doesn't widen the substrate contract. The body of a
/// [`SeerEnvelope::query`]/[`answer`](SeerEnvelope::answer) for a given topic is one of these
/// types, serialized through `serde_json::Value`.
///
/// The discipline: the substrate ships the *shape*; what counts as a "good" answer / "fit"
/// requirement / "valid" steer payload is the consumer's model.
pub mod topics {
    use serde::{Deserialize, Serialize};

    /// Authoring topic — consumed by `creatures/agent-templated`.
    ///
    /// The shapes mirror `AuthoringQuery::{question, options, deadline_ms}` and
    /// `AuthoringAnswer::{content}` minus `corr`+`query_id`, which live on [`super::SeerEnvelope`]
    /// and [`super::SeerKind::Query`]/[`Answer`](super::SeerKind::Answer). That's the
    /// generalization — corr/query_id are substrate-level; topic body is consumer-level.
    pub mod authoring {
        use super::*;

        /// The Query body: a question to the orchestrator, optional discrete options, optional
        /// advisory deadline. Mirrors `AuthoringQuery` minus the corr/query_id (which the
        /// envelope/kind carry).
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueryBody {
            pub question: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub options: Option<Vec<String>>,
            /// **Advisory only — never substrate-enforced.** The substrate ships no clock and
            /// imposes no timeout (module docs: *time is injected policy*). A
            /// `deadline_ms` is a hint the consumer's own model may honor (e.g. an orchestrator that
            /// emits a `Steer{kind:"abort"}` after the window); the bus neither reads nor enforces
            /// it. A future agent must not treat this as a fabric-level deadline.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub deadline_ms: Option<u64>,
        }

        /// The Answer body: the orchestrator's prose response. Richer encodings (a structured
        /// choice, a tool result, an embedded artifact) ride as stringified JSON inside `content`
        /// to keep the wire small — the substrate doesn't define what a "good" answer is.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct AnswerBody {
            pub content: String,
        }
    }

    /// Placement topic — the Distributor consult.
    ///
    /// A `distributor-requirements` creature bound to
    /// [`aether::Role::DISTRIBUTOR`] receives an [`aether::Intent`] envelope, parses its requirements
    /// as `Predicate`s, and consults every known `embodiment-advertiser` via a
    /// [`super::SeerEnvelope::query`] on this topic. Each advertiser checks its configured
    /// `Embodiment` offers against the predicates and answers with the matching
    /// `EmbodimentOffer`s. The distributor reconciles by its own model (round-robin / first-fit /
    /// verifiable-die — operator's call, never substrate's) and routes the Intent to the picked
    /// target.
    ///
    /// **The consult fires even for an N=1 local decision** — that's the S4 mitigation. Wiring the
    /// shape early means richer or cross-node placement does not retrofit a synchronous local code
    /// path into the SEER pattern later.
    pub mod placement {
        use serde::{Deserialize, Serialize};

        /// One predicate the requester demands of any matched [`Embodiment`]. The language is
        /// intentionally minimal — operators extend via injected matchers or by binding a richer
        /// advertiser whose own matching is opaque to substrate.
        ///
        /// On-wire form is the parsed enum (not the raw string) so consumers don't re-parse on
        /// every match. The string surface is the *authoring* form — what a human / config /
        /// authoring agent writes in an `Intent.requirements` slot — and is what [`Predicate::parse`]
        /// consumes; once on the wire it travels structured.
        ///
        /// **Reserved wire form.** Adding a new predicate kind is a one-line addition here + a
        /// parser arm + a match arm on [`Embodiment`]. Existing predicates serialize through their
        /// externally-tagged variant name (`CpuAtLeast` / `MemAtLeast` / …), so a future
        /// consumer that doesn't know about the new variant gets a structured serde error rather
        /// than a silent misread.
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub enum Predicate {
            /// `cpu >= N` — embodiment's `cpu` (cores) ≥ N.
            CpuAtLeast(u32),
            /// `mem >= N` — embodiment's `mem_bytes` ≥ N (bytes; no unit parsing beyond raw u64).
            MemAtLeast(u64),
            /// `accelerator contains X` — `X` appears as an element of `embodiment.accelerators`.
            /// Matched case-insensitively to keep authoring strings ergonomic
            /// (`"nvidia-a100"` matches `"NVIDIA-A100"`).
            AcceleratorContains(String),
            /// `jurisdiction in {a,b,c}` — embodiment's optional `jurisdiction` is one of the set.
            /// A None jurisdiction never matches (unsigned = no claim). Comparison is exact-string.
            JurisdictionIn(Vec<String>),
            /// `connectivity = X` — embodiment's optional `connectivity` equals `X`. A None
            /// connectivity never matches.
            ConnectivityEquals(String),
        }

        /// Predicate parse failure — a structured error, never a panic, so a hostile/garbage Intent
        /// requirements field becomes a Failed Answer rather than a router crash (R9 floor).
        #[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
        pub enum PredicateError {
            #[error("empty predicate string")]
            Empty,
            #[error("unrecognized predicate `{0}` — expected `cpu >= N`, `mem >= N`, `accelerator contains X`, `jurisdiction in {{…}}`, or `connectivity = X`")]
            Unrecognized(String),
            #[error("predicate `{0}`: malformed value: {1}")]
            Malformed(String, String),
        }

        impl Predicate {
            /// Parse one predicate string. Whitespace-tolerant; case-insensitive on the operator
            /// keywords (`contains`, `in`, the field names); case-preserving on the value (so
            /// `"nvidia-a100"` stays `"nvidia-a100"` on the wire even though the *match* is later
            /// case-folded). **Never panics** on hostile input — returns [`PredicateError`].
            pub fn parse(s: &str) -> Result<Self, PredicateError> {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(PredicateError::Empty);
                }
                let lower = trimmed.to_ascii_lowercase();

                if let Some(rest) = lower.strip_prefix("cpu") {
                    let rest = rest.trim_start();
                    let n = strip_op(rest, ">=")
                        .ok_or_else(|| PredicateError::Unrecognized(trimmed.to_string()))?;
                    let n = n.trim().parse::<u32>().map_err(|e| {
                        PredicateError::Malformed(trimmed.to_string(), e.to_string())
                    })?;
                    return Ok(Predicate::CpuAtLeast(n));
                }
                if let Some(rest) = lower.strip_prefix("mem") {
                    let rest = rest.trim_start();
                    let n = strip_op(rest, ">=")
                        .ok_or_else(|| PredicateError::Unrecognized(trimmed.to_string()))?;
                    let n = n.trim().parse::<u64>().map_err(|e| {
                        PredicateError::Malformed(trimmed.to_string(), e.to_string())
                    })?;
                    return Ok(Predicate::MemAtLeast(n));
                }
                if let Some(rest) = lower.strip_prefix("accelerator") {
                    let rest = rest.trim_start();
                    // Validate the keyword is there; the value itself we re-extract from `trimmed`
                    // by offset so case + hyphens survive (`lower` was only used to find keywords).
                    let _kw = rest
                        .strip_prefix("contains")
                        .ok_or_else(|| PredicateError::Unrecognized(trimmed.to_string()))?;
                    let value_offset = trimmed.len() - rest.len() + "contains".len();
                    let value = trimmed[value_offset..].trim();
                    if value.is_empty() {
                        return Err(PredicateError::Malformed(
                            trimmed.to_string(),
                            "missing accelerator name".into(),
                        ));
                    }
                    return Ok(Predicate::AcceleratorContains(value.to_string()));
                }
                if let Some(rest) = lower.strip_prefix("jurisdiction") {
                    let rest = rest.trim_start();
                    let _kw = rest
                        .strip_prefix("in")
                        .ok_or_else(|| PredicateError::Unrecognized(trimmed.to_string()))?;
                    let value_offset = trimmed.len() - rest.len() + "in".len();
                    let value = trimmed[value_offset..].trim();
                    let inner = value
                        .strip_prefix('{')
                        .and_then(|s| s.strip_suffix('}'))
                        .ok_or_else(|| {
                            PredicateError::Malformed(
                                trimmed.to_string(),
                                "expected `{a,b,c}` after `in`".into(),
                            )
                        })?;
                    let items: Vec<String> = inner
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if items.is_empty() {
                        return Err(PredicateError::Malformed(
                            trimmed.to_string(),
                            "empty `in` set".into(),
                        ));
                    }
                    return Ok(Predicate::JurisdictionIn(items));
                }
                if let Some(rest) = lower.strip_prefix("connectivity") {
                    let rest = rest.trim_start();
                    let _kw = strip_op(rest, "=")
                        .ok_or_else(|| PredicateError::Unrecognized(trimmed.to_string()))?;
                    let value_offset = trimmed.len() - rest.len() + 1; // past the `=`
                    let value = trimmed[value_offset..].trim();
                    if value.is_empty() {
                        return Err(PredicateError::Malformed(
                            trimmed.to_string(),
                            "missing connectivity value".into(),
                        ));
                    }
                    return Ok(Predicate::ConnectivityEquals(value.to_string()));
                }

                Err(PredicateError::Unrecognized(trimmed.to_string()))
            }

            /// Whether this predicate is satisfied by `e`. Pure function; cheap; no allocations
            /// past the case-fold scratch where needed.
            pub fn matches(&self, e: &Embodiment) -> bool {
                match self {
                    Predicate::CpuAtLeast(n) => e.cpu >= *n,
                    Predicate::MemAtLeast(n) => e.mem_bytes >= *n,
                    Predicate::AcceleratorContains(name) => {
                        let lname = name.to_ascii_lowercase();
                        e.accelerators.iter().any(|a| a.to_ascii_lowercase() == lname)
                    }
                    Predicate::JurisdictionIn(set) => {
                        e.jurisdiction.as_deref().is_some_and(|j| set.iter().any(|s| s == j))
                    }
                    Predicate::ConnectivityEquals(want) => {
                        e.connectivity.as_deref() == Some(want.as_str())
                    }
                }
            }
        }

        /// Helper for the parse-operator step. `strip_op(rest, op)` returns the value past `op` if
        /// `rest` starts with `op` (after trim); a separate helper because the prefix may itself be
        /// followed by whitespace we want to discard before parsing the value.
        fn strip_op<'a>(rest: &'a str, op: &str) -> Option<&'a str> {
            let stripped = rest.strip_prefix(op)?;
            // accept any whitespace before the value
            Some(stripped.trim_start())
        }

        /// A node's offered embodiment — what an `embodiment-advertiser` knows about a target
        /// (a local creature, a peer Sanctum, …). The fields are intentionally a small superset of
        /// what [`Predicate`]s read; an advertiser may publish richer metadata, but the
        /// predicate language is what matchers use.
        ///
        /// **Optional fields default to "unspecified."** A `jurisdiction: None` is *not* "matches
        /// any jurisdiction" — it's "no claim." A predicate asking `jurisdiction in {us, ca}` fails
        /// against an unspecified embodiment, because the embodiment hasn't asserted *any*. This is
        /// the safer default; an operator who wants permissive matching writes broader predicates,
        /// never the other way round.
        #[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
        pub struct Embodiment {
            /// CPU cores offered.
            #[serde(default)]
            pub cpu: u32,
            /// Total memory offered, bytes.
            #[serde(default)]
            pub mem_bytes: u64,
            /// Accelerators present, free-form labels (`"nvidia-a100"`, `"intel-gaudi-3"`, …).
            /// Empty = none.
            #[serde(default)]
            pub accelerators: Vec<String>,
            /// Declared jurisdiction (`"us"`, `"ca"`, `"eu"` — operator's vocabulary). `None` =
            /// unspecified.
            #[serde(default)]
            pub jurisdiction: Option<String>,
            /// Declared connectivity (`"wired"`, `"satellite"`, `"intermittent"` — operator's
            /// vocabulary). `None` = unspecified.
            #[serde(default)]
            pub connectivity: Option<String>,
            /// Sensors present, free-form labels. Empty = none. Reserved for future predicates; not
            /// matched by any current [`Predicate`] kind yet.
            #[serde(default)]
            pub sensors: Vec<String>,
        }

        /// One advertised offer — the (node, creature_id) target the Distributor would route to, plus
        /// the [`Embodiment`] it claims. The distributor's reconciliation reads both fields: the
        /// target tells it *where* to route, the embodiment tells it *which* offer to prefer (for
        /// pick-models that score, e.g. "best fit by cpu headroom").
        ///
        /// `node` is the [`aether::NodeId`] string form (so the wire is JSON-friendly without a
        /// nested struct), and `creature_id` is the [`aether::CreatureId`] u64. The distributor on
        /// receipt collapses `node == self_node` to [`aether::Address::Creature`] and otherwise
        /// constructs [`aether::Address::Node`] — the same envelope shape either way.
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct EmbodimentOffer {
            /// The advertiser's self-node — distributor maps to local-vs-peer addressing.
            pub node: String,
            /// The local creature id on the advertiser's node.
            pub creature_id: u64,
            /// Metadata for tie-breaking; same fields the predicates read.
            pub embodiment: Embodiment,
        }

        /// The Query body: a Distributor asks "who can place this work?" — the body carries the
        /// requirements as predicate strings (not parsed enums; advertisers parse on receipt so a
        /// distributor that can't parse one predicate still ships the rest — robustness over
        /// strict-acceptance).
        ///
        /// Carrying strings (not parsed [`Predicate`]s) on the wire is deliberate: the *authoring*
        /// surface (operator config, an Intent's `requirements`) is a list of human strings, and
        /// re-parsing per receipt costs microseconds. If a future distributor wants to ship parsed
        /// predicates instead, it can co-emit them; the string form stays canonical.
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct QueryBody {
            /// Predicate strings — each consumer's parser turns them into [`Predicate`]s.
            pub requirements: Vec<String>,
            /// The Intent outcome — useful for advertisers that publish per-outcome (e.g. only
            /// advertise GPU embodiment for outcomes that need it). Optional; omitted-from-wire
            /// when `None` (advertisers ignoring outcome see no field).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub outcome: Option<String>,
        }

        /// The Answer body: zero or more matching offers from this advertiser.
        ///
        /// An advertiser that finds no matches answers with `matches: vec![]` (a positive
        /// "I heard you, nothing fits"); the distributor distinguishes this from "no answer
        /// received" by counting received answers vs queries sent. The empty-matches case is the
        /// "no_match" exit criterion: every advertiser answers, none has anything that fits, the
        /// distributor returns a structured NoProvider — never a silent drop.
        #[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
        pub struct AnswerBody {
            /// Offers the advertiser ranks as fitting all the request's predicates. Order is the
            /// advertiser's preference (first = most preferred); the distributor's reconciliation
            /// model decides whether to honor that ranking.
            #[serde(default)]
            pub matches: Vec<EmbodimentOffer>,
        }

        // ============================================================================================
        // Tests — predicate language + Embodiment match semantics. The wire roundtrip for
        // QueryBody/AnswerBody is exercised by the general SEER roundtrip suite above; here we
        // pin the parser + matcher semantics so the consumer creatures (distributor-requirements
        // + embodiment-advertiser) build against a stable surface.
        // ============================================================================================
        #[cfg(test)]
        mod tests {
            use super::*;

            // ---- parse: happy path -------------------------------------------------------------

            #[test]
            fn parses_cpu_at_least() {
                assert_eq!(Predicate::parse("cpu >= 4").unwrap(), Predicate::CpuAtLeast(4));
                assert_eq!(Predicate::parse("CPU >= 0").unwrap(), Predicate::CpuAtLeast(0));
                assert_eq!(Predicate::parse("  cpu>=8  ").unwrap(), Predicate::CpuAtLeast(8));
            }

            #[test]
            fn parses_mem_at_least() {
                assert_eq!(
                    Predicate::parse("mem >= 1073741824").unwrap(),
                    Predicate::MemAtLeast(1_073_741_824)
                );
                assert_eq!(Predicate::parse("MEM>=0").unwrap(), Predicate::MemAtLeast(0));
            }

            #[test]
            fn parses_accelerator_contains_with_case_and_hyphens() {
                // The value's case is preserved on the wire — `matches` folds at compare time.
                assert_eq!(
                    Predicate::parse("accelerator contains NVIDIA-A100").unwrap(),
                    Predicate::AcceleratorContains("NVIDIA-A100".into())
                );
                assert_eq!(
                    Predicate::parse("ACCELERATOR contains nvidia-a100").unwrap(),
                    Predicate::AcceleratorContains("nvidia-a100".into())
                );
            }

            #[test]
            fn parses_jurisdiction_in_set() {
                assert_eq!(
                    Predicate::parse("jurisdiction in {us, ca}").unwrap(),
                    Predicate::JurisdictionIn(vec!["us".into(), "ca".into()])
                );
                // tolerates extra whitespace and a single-element set
                assert_eq!(
                    Predicate::parse("JURISDICTION in {eu}").unwrap(),
                    Predicate::JurisdictionIn(vec!["eu".into()])
                );
            }

            #[test]
            fn parses_connectivity_equals() {
                assert_eq!(
                    Predicate::parse("connectivity = wired").unwrap(),
                    Predicate::ConnectivityEquals("wired".into())
                );
            }

            // ---- parse: hostile / malformed --------------------------------------------------

            #[test]
            fn rejects_empty_or_garbage_without_panic() {
                assert!(matches!(Predicate::parse(""), Err(PredicateError::Empty)));
                assert!(matches!(Predicate::parse("   "), Err(PredicateError::Empty)));
                assert!(matches!(
                    Predicate::parse("foo bar baz"),
                    Err(PredicateError::Unrecognized(_))
                ));
                assert!(matches!(
                    Predicate::parse("cpu > 4"),
                    Err(PredicateError::Unrecognized(_))
                ));
                assert!(matches!(
                    Predicate::parse("cpu >= not-a-number"),
                    Err(PredicateError::Malformed(_, _))
                ));
                assert!(matches!(
                    Predicate::parse("accelerator contains"),
                    Err(PredicateError::Malformed(_, _))
                ));
                assert!(matches!(
                    Predicate::parse("jurisdiction in [us]"),
                    Err(PredicateError::Malformed(_, _))
                ));
                assert!(matches!(
                    Predicate::parse("jurisdiction in {}"),
                    Err(PredicateError::Malformed(_, _))
                ));
                assert!(matches!(
                    Predicate::parse("connectivity ="),
                    Err(PredicateError::Malformed(_, _))
                ));
            }

            // ---- matches: predicate-vs-embodiment ---------------------------------------------

            fn rich() -> Embodiment {
                Embodiment {
                    cpu: 8,
                    mem_bytes: 16 * 1024 * 1024 * 1024,
                    accelerators: vec!["nvidia-a100".into(), "intel-amx".into()],
                    jurisdiction: Some("us".into()),
                    connectivity: Some("wired".into()),
                    sensors: vec![],
                }
            }

            #[test]
            fn cpu_match_compares_at_least() {
                assert!(Predicate::CpuAtLeast(4).matches(&rich()));
                assert!(Predicate::CpuAtLeast(8).matches(&rich()));
                assert!(!Predicate::CpuAtLeast(9).matches(&rich()));
            }

            #[test]
            fn mem_match_compares_at_least() {
                assert!(Predicate::MemAtLeast(0).matches(&rich()));
                assert!(Predicate::MemAtLeast(8 * 1024 * 1024 * 1024).matches(&rich()));
                assert!(!Predicate::MemAtLeast(u64::MAX).matches(&rich()));
            }

            #[test]
            fn accelerator_match_is_case_insensitive() {
                assert!(Predicate::AcceleratorContains("nvidia-a100".into()).matches(&rich()));
                assert!(Predicate::AcceleratorContains("NVIDIA-A100".into()).matches(&rich()));
                assert!(!Predicate::AcceleratorContains("tpu-v5".into()).matches(&rich()));
            }

            #[test]
            fn jurisdiction_match_requires_membership() {
                assert!(Predicate::JurisdictionIn(vec!["us".into()]).matches(&rich()));
                assert!(Predicate::JurisdictionIn(vec!["ca".into(), "us".into()]).matches(&rich()));
                assert!(!Predicate::JurisdictionIn(vec!["eu".into()]).matches(&rich()));
                // Unspecified jurisdiction never matches an `in {…}` predicate (safer default).
                let mut e = rich();
                e.jurisdiction = None;
                assert!(!Predicate::JurisdictionIn(vec!["us".into()]).matches(&e));
            }

            #[test]
            fn connectivity_match_requires_exact_string() {
                assert!(Predicate::ConnectivityEquals("wired".into()).matches(&rich()));
                assert!(!Predicate::ConnectivityEquals("satellite".into()).matches(&rich()));
                // Unspecified connectivity never matches.
                let mut e = rich();
                e.connectivity = None;
                assert!(!Predicate::ConnectivityEquals("wired".into()).matches(&e));
            }

            // ---- wire roundtrip: shapes survive serde --------------------------------------

            #[test]
            fn query_body_roundtrips_and_elides_optional_outcome() {
                let full = QueryBody {
                    requirements: vec!["cpu >= 2".into(), "connectivity = wired".into()],
                    outcome: Some("reverse-string".into()),
                };
                let bytes = serde_json::to_vec(&full).unwrap();
                let back: QueryBody = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(back, full);
                let minimal = QueryBody { requirements: vec!["cpu >= 1".into()], outcome: None };
                let json = String::from_utf8(serde_json::to_vec(&minimal).unwrap()).unwrap();
                assert!(!json.contains("outcome"), "absent outcome elides: {json}");
            }

            #[test]
            fn answer_body_roundtrips_including_empty_matches() {
                let empty = AnswerBody::default();
                let bytes = serde_json::to_vec(&empty).unwrap();
                let back: AnswerBody = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(back, empty);
                let one = AnswerBody {
                    matches: vec![EmbodimentOffer {
                        node: "node-A".into(),
                        creature_id: 7,
                        embodiment: Embodiment { cpu: 4, ..Default::default() },
                    }],
                };
                let bytes = serde_json::to_vec(&one).unwrap();
                let back: AnswerBody = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(back, one);
            }

            #[test]
            fn predicate_serde_roundtrips_every_variant() {
                let variants = [
                    Predicate::CpuAtLeast(2),
                    Predicate::MemAtLeast(1_000_000),
                    Predicate::AcceleratorContains("tpu".into()),
                    Predicate::JurisdictionIn(vec!["us".into(), "ca".into()]),
                    Predicate::ConnectivityEquals("wired".into()),
                ];
                for v in variants {
                    let bytes = serde_json::to_vec(&v).unwrap();
                    let back: Predicate = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(back, v);
                }
            }
        }
    }

    /// Policy topic — reserved/draft admission consultation.
    ///
    /// **Draft shape — may be revised before any consumer pins it.** The topic is reserved so
    /// consumers don't widen the substrate wire; the field set here is illustrative, not a stable
    /// typed-body contract.
    pub mod policy {
        use super::*;

        /// **Reserved/draft.** A future policy creature consult will likely thicken
        /// this with the candidate manifest's hash + the policy question + the requesting peer.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueryBody {
            pub manifest_hash: String,
        }
        /// **Reserved/draft.** Admit/deny + an audit-trail reason.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct AnswerBody {
            pub admit: bool,
            pub reason: String,
        }
    }

    /// Budget topic — reserved/draft (`BudgetRequest` / `ExtendBudget` consult).
    ///
    /// **Draft shape — may be revised before any consumer ships.** Notably the `AnswerBody`
    /// currently lacks an explicit denied-vs-granted-zero distinction; a real consumer will likely
    /// promote this to an enum or add a `granted: bool` flag.
    pub mod budget {
        use super::*;

        /// **Reserved/draft.** The `BudgetRequest` shape — a creature that
        /// approaches a limit asks the policy creature for grace (extension / softer kind / vector
        /// context).
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueryBody {
            pub request_units: u64,
            pub justification: String,
        }
        /// **Reserved/draft.** Granted units. A `granted_units: 0` is currently ambiguous between
        /// "explicit denial" and "granted nothing"; a real consumer should disambiguate.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct AnswerBody {
            pub granted_units: u64,
        }
    }

    /// Fitness topic — reserved/draft (Loop 2's selection signal).
    ///
    /// **Draft shape — may be revised before any consumer ships.** The `candidate: String` is
    /// likely to become `candidate_hash` (content-addressed) once a real selector lands.
    pub mod fitness {
        use super::*;

        /// **Reserved/draft.** A selector asks "how well does this candidate perform?"
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueryBody {
            pub candidate: String,
            pub criterion: String,
        }
        /// **Reserved/draft.** A fitness score in [0.0, 1.0] with an injected criterion. `f32`
        /// precision may be insufficient for cumulative scoring; a real consumer may widen.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct AnswerBody {
            pub score: f32,
        }
    }

    /// Consensus topic — live topic for weight/vote/VRF-style consults.
    ///
    /// **Draft helper body.** `creatures/omega-federator` already consumes the generic consensus
    /// topic with its own signed reputation body; this helper shape remains illustrative. `weight:
    /// f32` is at risk for accounting use cases; a real typed-body consumer may widen to f64 or a
    /// rational type once it pins the requirements.
    pub mod consensus {
        use super::*;

        /// **Reserved/draft.** A creature asks N peers to vote on a proposition;
        /// reconciles by weight / quorum / VRF — all injected models, never substrate.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueryBody {
            pub proposition: String,
        }
        /// **Reserved/draft.** Vote + weight. The reconciliation model is the
        /// consulter's call.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct AnswerBody {
            pub vote: String,
            pub weight: f32,
        }
    }

    /// Curation topic — reserved/draft (the durable Bestiary's external-curator consult).
    ///
    /// **Draft shape — may be revised before any external curator creature ships.** The in-process
    /// `bestiary::AICurator` curates directly over the injected `mind::Model` today; this topic is the
    /// seam for an *external* curator creature, consulted by a daemon's compaction thread off the
    /// synchronous decide path. The verb the answer carries mirrors `bestiary::CurationDecision`.
    pub mod curation {
        use super::*;

        /// **Reserved/draft.** A daemon asks "what should I do with this entry?" — carrying the key
        /// and the manifest identity so an external curator can reason without a follow-up fetch.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct QueryBody {
            pub realm: String,
            pub artifact_hash: String,
            pub manifest_hash: String,
        }
        /// **Reserved/draft.** The curator's verdict: one of `keep` / `gc` / `quarantine` (mirrors
        /// `bestiary::CurationDecision`) plus an audit-trail reason.
        #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
        pub struct AnswerBody {
            pub decision: String,
            pub reason: String,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------------------------
    // Serde roundtrip across every (topic × kind) combination. The wire is the substrate's
    // commitment: a consumer that binds to this shape today gets the same shape when richer bodies
    // land in `topics::*`. The roundtrip lock is what makes the reserved topic a *seam*, not just
    // a type definition.
    // -----------------------------------------------------------------------------------------

    fn all_topics() -> [SeerTopic; 7] {
        [
            SeerTopic::Authoring,
            SeerTopic::Placement,
            SeerTopic::Policy,
            SeerTopic::Budget,
            SeerTopic::Fitness,
            SeerTopic::Consensus,
            SeerTopic::Curation,
        ]
    }

    #[test]
    fn seer_envelope_serde_roundtrips_for_every_topic_and_kind() {
        for topic in all_topics() {
            let kinds = vec![
                SeerKind::Query { query_id: 1, body: serde_json::json!({"q": "?"}) },
                SeerKind::Answer { query_id: 1, body: serde_json::json!({"a": "!"}) },
                SeerKind::Steer { kind: "abort".into(), payload: serde_json::json!({}) },
                SeerKind::Progress {
                    stage: "midway".into(),
                    fraction: Some(0.5),
                    note: Some("steady".into()),
                },
                SeerKind::Thought { channel: "internal".into(), content: "thinking…".into() },
            ];
            for kind in kinds {
                let env = SeerEnvelope { topic, corr: 42, kind: kind.clone() };
                let bytes = env.to_bytes();
                let back = SeerEnvelope::parse(&bytes).expect("seer envelope decodes");
                assert_eq!(back, env, "roundtrip failed for topic={topic:?} kind={kind:?}");
            }
        }
    }

    #[test]
    fn progress_optional_fields_elide_when_none() {
        // Minimal Progress emits a tight envelope — the optional fields don't appear on the wire
        // when the creature has no estimate to report. Mirror of the AuthoringProgress
        // assertion.
        let env = SeerEnvelope::progress(SeerTopic::Authoring, 7, "started", None, None);
        let json = String::from_utf8(env.to_bytes()).unwrap();
        assert!(!json.contains("fraction"), "absent fraction must not appear: {json}");
        assert!(!json.contains("note"), "absent note must not appear: {json}");
    }

    #[test]
    fn bounded_parse_rejects_oversized_payload_before_json_decode() {
        let payload = vec![b'{'; MAX_SEER_ENVELOPE_BYTES + 1];
        match SeerEnvelope::parse_bounded(&payload) {
            Err(SeerParseError::TooLarge { len, limit }) => {
                assert_eq!(len, MAX_SEER_ENVELOPE_BYTES + 1);
                assert_eq!(limit, MAX_SEER_ENVELOPE_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn bounded_parse_accepts_valid_payload_under_limit() {
        let env = SeerEnvelope::thought(SeerTopic::Authoring, 7, "internal", "ok");
        let back = SeerEnvelope::parse_bounded(&env.to_bytes()).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn authoring_query_body_roundtrips_and_elides_optional_fields() {
        let full = topics::authoring::QueryBody {
            question: "A or B?".into(),
            options: Some(vec!["A".into(), "B".into()]),
            deadline_ms: Some(5_000),
        };
        let bytes = serde_json::to_vec(&full).unwrap();
        let back: topics::authoring::QueryBody = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, full);

        let minimal = topics::authoring::QueryBody {
            question: "open-ended?".into(),
            options: None,
            deadline_ms: None,
        };
        let json = String::from_utf8(serde_json::to_vec(&minimal).unwrap()).unwrap();
        assert!(!json.contains("options"));
        assert!(!json.contains("deadline_ms"));
    }

    // -----------------------------------------------------------------------------------------
    // Reduction theorem (per-topic, unit form). A consumer that answers a topic *immediately* —
    // emitting one terminal envelope, no intermediate Query — produces a wire indistinguishable
    // from a single-shot reply. The SeerEnvelope shape never *requires* a richer
    // conversation; it admits one.
    //
    // We assert this structurally: a single SeerEnvelope::Answer for any topic, byte-roundtripped,
    // is the exact same envelope. There is no orchestrator-mandated Query precursor in the shape.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn reduction_theorem_single_terminal_answer_is_byte_identical_across_topics() {
        for topic in all_topics() {
            let terminal = SeerEnvelope::answer(
                topic,
                123,
                0, // query_id=0 is the "no precursor query" convention — terminal reply on its own
                &serde_json::json!({ "result": "ok" }),
            );
            let bytes = terminal.to_bytes();
            let back = SeerEnvelope::parse(&bytes).unwrap();
            assert_eq!(back, terminal, "terminal answer round-trip failed for {topic:?}");
            // The wire has no intermediate Query — single-shot equivalence preserved per topic.
            assert!(matches!(back.kind, SeerKind::Answer { query_id: 0, .. }));
        }
    }

    // -----------------------------------------------------------------------------------------
    // Steer is generic — works for arbitrary topic. The substrate doesn't bake AUTHORING-ness
    // into Steer; placement / consensus / budget / fitness creatures can be steered too.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn steer_is_generic_across_topics() {
        for topic in all_topics() {
            let s = SeerEnvelope::steer(
                topic,
                99,
                "abort",
                &serde_json::json!({ "reason": "operator changed mind" }),
            );
            let bytes = s.to_bytes();
            let back = SeerEnvelope::parse(&bytes).unwrap();
            match back.kind {
                SeerKind::Steer { kind, payload } => {
                    assert_eq!(kind, "abort");
                    assert_eq!(payload["reason"], "operator changed mind");
                }
                other => panic!("expected Steer, got {other:?} for topic {topic:?}"),
            }
        }
    }

    #[test]
    fn topic_as_str_matches_serde_tag() {
        // The `as_str` helper and the serde-rename tag must agree — otherwise log lines disagree
        // with on-wire bytes and debugging gets painful.
        for topic in all_topics() {
            let s = topic.as_str();
            let json = serde_json::to_string(&topic).unwrap();
            assert_eq!(json, format!("\"{s}\""), "tag mismatch: as_str={s} serde={json}");
        }
    }

    #[test]
    fn schema_constant_is_stable() {
        // A guard against an accidental rename — consumers depend on this being
        // the literal "seer" string (it's what they match on at decode time).
        assert_eq!(SCHEMA, "seer");
    }

    #[test]
    fn seer_envelope_helpers_construct_expected_kinds() {
        let q = SeerEnvelope::query(SeerTopic::Authoring, 1, 5, &"hello");
        matches!(q.kind, SeerKind::Query { query_id: 5, .. });
        let a = SeerEnvelope::answer(SeerTopic::Authoring, 1, 5, &"hi");
        matches!(a.kind, SeerKind::Answer { query_id: 5, .. });
        let s = SeerEnvelope::steer(SeerTopic::Placement, 1, "amend", &serde_json::json!({}));
        matches!(s.kind, SeerKind::Steer { .. });
        let p = SeerEnvelope::progress(SeerTopic::Authoring, 1, "stage", Some(0.5), Some("n"));
        matches!(p.kind, SeerKind::Progress { .. });
        let t = SeerEnvelope::thought(SeerTopic::Authoring, 1, "internal", "x");
        matches!(t.kind, SeerKind::Thought { .. });
    }
}
