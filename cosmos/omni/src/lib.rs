//! omni — the **single command vocabulary** behind every GAWD control surface.
//!
//! Node control rides on GAWD's own bus: control is an injected creature ([`ControlCore`]) on
//! [`Role::CONTROL`], and every surface — the REPL, the HTTP/WS plane, the MCP hub — drives the
//! **same** live [`Kernel`] by sending a [`Verb`] *as an envelope* and reading a [`VerbResult`]
//! *as an envelope*. This crate is spine-only (no tokio/axum/reqwest); the async surfaces are
//! separate creatures that speak this contract over the bus.
//!
//! Design:
//! - [`run_verb`] is the command core. It takes a parsed [`Verb`] + a [`VerbCtx`] (the kernel, a
//!   probe endpoint for request/reply, the corr counter, the [`AiControl`] gate) + a `progress`
//!   callback, and returns a [`VerbResult`] carrying both a machine `json` value and a `human`
//!   string. The REPL prints `human`; a surface serializes `json`.
//! - Every [`Kernel`] method is `&self` (the router is internally synchronized), so multiple
//!   front-ends drive one live node concurrently. Each gets its **own** probe endpoint + corr space,
//!   so request/reply never cross-talks.
//! - Human/AI shared control ([`AiControl`]): a human-held `allow-ai` gate plus an AI activity
//!   status, surfaced live — the GAWD analog of sctl's `session_allow_ai`/`session_ai_status`.
//! - [`ControlCore`] is the bus-facing translator: it receives a [`Verb`] envelope on
//!   [`Role::CONTROL`], runs it against the live node, and replies with a [`VerbResult`] envelope.
//!   Reads run inline (fast); orchestration verbs run on a worker so a cold `author` never
//!   head-of-line-blocks a `status`.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver, Intent, NodeId,
    RealmId, Role, RouteError, Topic,
};
use anima::{Artifact, MAX_ARTIFACT_BYTES};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

use agent_templated::{AgentTemplated, AuthoringReply, AuthoringRequest};
// The registry wire (RegistryOp/RegistryReply) the registry verbs build, and the additive
// `bestiary.op` (BestiaryOp/BestiaryReply) the `bestiary_prove` verb speaks — both from the Bestiary
// contract crate, so `run_verb` names the wire without reaching into a registry creature.
use bestiary::{
    BestiaryOp, BestiaryReply, CatalogEntry, RegistryOp, RegistryReply, BESTIARY_OP_SCHEMA,
    REGISTRY_OP_SCHEMA,
};
use build_cargo::{BuildCargo, BuildConfig, BuildOp, BuildReply, Sandbox};
use build_critter::{BuildCritter, BuildCritterOp};
use monitor::Monitor;
use registry_mem::RegistryMem;
use serde::de::DeserializeOwned;
use transport_tcp::{TransportCtl, TransportCtlReply, CTL_SCHEMA};

use serde_json::{json, Value};

mod control;
pub use control::{
    ControlCore, ControlTarget, CONTROL_PROGRESS_SCHEMA, CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA,
};

/// The one-line command summary printed by the REPL banner and the `help` verb.
pub const COMMANDS: &str = "commands: author [--critter] <request> | load <manifest> <artifact> | registry publish <manifest> <artifact> [realm] | registry fetch <artifact-hash> [realm] | registry list [realm] | registry fetch-load <artifact-hash> [<node-id> <registry-id>] [realm] | bestiary prove <artifact-hash> <realm> | send <[node-id:]id> <text> | intent <outcome> <text> | bind <role> <id> | unload <id> | allow-ai <on|off> | cluster [join <id@host:port#pubkey>] | list | status | journal | watch | help | quit";

/// Control-surface manifests are JSON metadata, not artifacts. Keep the node-local path reader
/// bounded so a granted surface caller cannot make the control plane slurp an arbitrary local file.
pub const MAX_CONTROL_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Artifact bytes may cross the bus for registry publish, and beast/critter path-loads are read into
/// memory by their engines. Native daemons still load by path for `dlopen`, but bus-carried artifacts
/// and non-native path loads get this hard ceiling.
pub const MAX_CONTROL_ARTIFACT_BYTES: u64 = MAX_ARTIFACT_BYTES;
/// A `control_verb` is a command envelope, not an artifact carrier. Bound it before JSON parsing so
/// remote/bus control cannot spend unbounded memory deserializing a command body.
pub const MAX_CONTROL_VERB_BYTES: usize = 1024 * 1024;
/// A `control_result` is metadata + operator-facing text, not a bulk-data carrier. Bound it before
/// surface-side JSON parsing so a malformed or hostile control responder cannot force unbounded
/// allocation in HTTP/MCP callers.
pub const MAX_CONTROL_RESULT_BYTES: usize = MAX_CONTROL_VERB_BYTES;
/// Maximum bytes shown when a control surface presents an arbitrary creature reply or sense payload.
///
/// Control is an operator/API surface, not a bulk-data transport. Small replies stay exact; larger
/// replies are returned as a lossy UTF-8 preview with byte counts and a truncation flag.
pub const MAX_PRESENTED_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum Unicode scalar values retained in AI activity/status text.
///
/// These strings are written to operator-facing terminals and live streams. Strip control
/// characters and bound their displayed length at the shared control layer so every surface gets the
/// same safe text.
pub const MAX_AI_STATUS_TEXT_CHARS: usize = 512;
/// Maximum bytes in a role name accepted by the public control `bind` verb.
///
/// `Role` remains an open socket type for in-process boot/composition, but public control input is
/// operator-visible retained metadata. Keep it a bounded ASCII token before inserting into the
/// router's role table.
pub const MAX_CONTROL_ROLE_NAME_BYTES: usize = 256;
/// Maximum bytes of natural-language request text in one `author`/`author --critter` verb.
///
/// This is the AUTHORING contract's own field cap surfaced at the control plane, so every surface
/// advertises and enforces the limit the authoring bindees actually apply in
/// `decode_authoring_request` — a request that passes the front door never fails the same size
/// check deeper in the pipeline.
pub const MAX_CONTROL_AUTHOR_REQUEST_BYTES: usize =
    agent_templated::MAX_AUTHORING_REQUEST_TEXT_BYTES;
/// Maximum bytes read while probing ancestor `Cargo.toml` files for `[workspace]`.
const MAX_WORKSPACE_MANIFEST_BYTES: u64 = 1024 * 1024;
/// The control worker runs slow request/reply orchestration off the kernel drain thread. Bound its
/// queue so a slow `author`/`send` cannot accumulate unbounded pending jobs.
pub const CONTROL_WORKER_QUEUE_CAP: usize = 64;

/// Authoring replies carry source text and manifest metadata, not artifacts. Keep them bounded
/// before the control core deserializes a role response.
const MAX_AUTHORING_REPLY_BYTES: usize = 8 * 1024 * 1024;
/// Build replies can legitimately carry one max-size artifact as a hex string.
/// Size this around the existing 128 MiB artifact ceiling plus manifest/error overhead.
const MAX_ARTIFACT_ROLE_REPLY_BYTES: usize =
    (MAX_CONTROL_ARTIFACT_BYTES as usize * 2) + (8 * 1024 * 1024);
/// Registry publish replies are tiny acknowledgements/errors, never artifacts.
const MAX_REGISTRY_ACK_REPLY_BYTES: usize = 1024 * 1024;
/// Registry metadata listing is a control-surface read, not anti-entropy; keep it byte-light.
const MAX_REGISTRY_METADATA_REPLY_BYTES: usize = 8 * 1024 * 1024;
/// Registry fetch uses the metadata-only registry op; it should never inherit artifact-sized caps.
const MAX_REGISTRY_FETCH_REPLY_BYTES: usize = MAX_REGISTRY_METADATA_REPLY_BYTES;
/// `bestiary prove` and compaction replies are metadata/proofs, never artifacts.
const MAX_BESTIARY_REPLY_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// Human/AI shared control (modeled on sctl session_allow_ai / session_ai_status)
// ---------------------------------------------------------------------------------------------

/// What the AI is currently doing on this node, reported via `ai-status` (the AI announces intent so
/// a human watching the REPL/stream can see it and revoke). Empty `activity` means "idle".
#[derive(Clone, Debug, Default)]
pub struct AiStatus {
    pub working: bool,
    /// `"read"` (no side effects) or `"write"` (mutating) — sctl's two-level activity badge.
    pub activity: String,
    pub message: String,
}

/// The node-level allow-AI gate + the AI's live activity status. Shared (`Arc`) across the REPL and
/// the API. The gate defaults **off**: a remote AI can do nothing mutating until a human grants it
/// (at the REPL with `allow-ai on`, or at startup with `--allow-ai`). Read-only verbs are never
/// gated; the local REPL is never gated (the terminal is the trusted human seat).
#[derive(Debug)]
pub struct AiControl {
    allowed: AtomicBool,
    status: Mutex<AiStatus>,
}

impl AiControl {
    pub fn new(allowed: bool) -> Self {
        Self { allowed: AtomicBool::new(allowed), status: Mutex::new(AiStatus::default()) }
    }
    pub fn allowed(&self) -> bool {
        self.allowed.load(Ordering::SeqCst)
    }
    pub fn set_allowed(&self, v: bool) {
        self.allowed.store(v, Ordering::SeqCst);
    }
    pub fn status(&self) -> AiStatus {
        self.status.lock().map(|g| g.clone()).unwrap_or_default()
    }
    pub fn set_status(&self, working: bool, activity: String, message: String) {
        if let Ok(mut g) = self.status.lock() {
            *g = AiStatus {
                working,
                activity: sanitize_ai_status_text(&activity),
                message: sanitize_ai_status_text(&message),
            };
        }
    }
    fn status_json(&self) -> Value {
        let s = self.status();
        json!({ "working": s.working, "activity": s.activity, "message": s.message })
    }
}

/// Strip terminal control characters from caller-supplied AI status text and bound displayed length.
pub fn sanitize_ai_status_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(MAX_AI_STATUS_TEXT_CHARS).collect()
}

fn validate_control_role_name(role: &str) -> Result<(), &'static str> {
    if role.is_empty() {
        return Err("role name must not be empty");
    }
    if role.len() > MAX_CONTROL_ROLE_NAME_BYTES {
        return Err("role name exceeds control byte limit");
    }
    if !role.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return Err("role name must be ASCII [A-Za-z0-9._-]");
    }
    Ok(())
}

impl Default for AiControl {
    fn default() -> Self {
        Self::new(false)
    }
}

// ---------------------------------------------------------------------------------------------
// The verb vocabulary
// ---------------------------------------------------------------------------------------------

/// A parsed command. Both the REPL ([`parse_verb`]) and a surface (from JSON, or off the bus)
/// construct one of these and hand it to [`run_verb`] — the single point where a command becomes an
/// effect on the kernel.
///
/// **Serializable:** a `Verb` is the payload of a `control_verb` envelope, so control is
/// plain bus traffic — a surface ships the `Verb`, [`ControlCore`] runs it, a [`VerbResult`] rides
/// back. The tag is `verb` (`{"verb":"author","request":"…"}`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum Verb {
    Help,
    List,
    Status,
    Journal {
        limit: usize,
    },
    Watch,
    /// Read this node's view of the cluster graph.
    Cluster,
    /// Admit + dial a cluster peer — the operator/AI-gated join; gossip propagates it from there.
    ClusterJoin {
        node_id: String,
        addr: String,
        pubkey: String,
    },
    Author {
        request: String,
    },
    AuthorCritter {
        request: String,
    },
    Load {
        manifest_path: String,
        artifact_path: String,
    },
    /// Publish a creature into the catalogue **by node-local path** — reads the manifest + artifact
    /// off *this node's* filesystem (the same operator caveat as [`Verb::Load`]; not a client upload),
    /// then ships a `RegistryOp::Publish` (optional `realm`) to `Role::REGISTRY`. Mutating → gated.
    RegistryPublish {
        manifest_path: String,
        artifact_path: String,
        /// `None` publishes into `RealmId::local()`; `Some(r)` into the named Realm. `serde(default)`
        /// so a surface may omit it on the wire.
        #[serde(default)]
        realm: Option<RealmId>,
    },
    /// Look up a catalogue entry by `artifact_hash` and return its manifest **metadata** + artifact
    /// length (never the raw bytes inline — a control reply must not carry a multi-megabyte artifact).
    /// Read-only → ungated.
    RegistryFetch {
        artifact_hash: String,
        #[serde(default)]
        realm: Option<RealmId>,
    },
    /// Snapshot the catalogue (`None` = every Realm, `Some(r)` = one). Read-only → ungated.
    RegistryList {
        #[serde(default)]
        realm: Option<RealmId>,
    },
    /// Ask the durable Bestiary for a standalone, signed [`EntryProof`](bestiary::EntryProof) over
    /// `(realm, artifact_hash)` — rides the additive `bestiary.op` schema (a `registry-mem` stub
    /// answers a structured error; only a `bestiary-daemon` proves). Read-only → ungated.
    BestiaryProve {
        artifact_hash: String,
        realm: RealmId,
    },
    /// Fetch a creature artifact over **GX** from a registry, assemble + integrity-check it, and
    /// **load** it into this node — the operator path that the `m2_two_node` test hand-scripted. Drives
    /// `FetchGxPlan` → a windowed `FetchGxChunk` pull (re-requesting only the gaps on a stall, so a
    /// dropped chunk resumes rather than restarts) → `gawdxfer::ChunkAssembler` (per-chunk + whole-file
    /// SHA-256) → `kernel.load` (which re-verifies signature + bytes at admission). Loads code → gated;
    /// request/reply → needs the worker probe.
    FetchLoad {
        /// `sha256(artifact_bytes)` hex — the content-address key to fetch.
        artifact_hash: String,
        /// `Some(node-id)` fetches from a peer node's registry over the cluster; `None` fetches from
        /// the local `Role::REGISTRY`. `#[serde(default)]` so a surface may omit it.
        #[serde(default)]
        node: Option<String>,
        /// The peer registry's [`CreatureId`] — **required** when `node` is `Some` (Role addressing is
        /// node-local, so a cross-node op must name the target creature). Ignored when `node` is `None`.
        #[serde(default)]
        registry_id: Option<u64>,
        /// `None` fetches from `RealmId::local()`; `Some(r)` from the named Realm.
        #[serde(default)]
        realm: Option<RealmId>,
        /// Requested GX chunk size; `None` lets the registry pick its default. The registry clamps it.
        #[serde(default)]
        chunk_size: Option<u32>,
    },
    Send {
        id: u64,
        text: String,
        /// `Some(node-id)` routes the send cross-node via `Address::Node` over the cluster;
        /// `None` is a local creature send. `#[serde(default)]` so a surface may omit it on the wire.
        #[serde(default)]
        node: Option<String>,
    },
    Intent {
        outcome: String,
        text: String,
    },
    Bind {
        role: String,
        id: u64,
    },
    Unload {
        id: u64,
    },
    /// Flip the allow-AI gate. REPL-only (the trusted human seat): refused when `ctx.gated`.
    AllowAi {
        allowed: bool,
    },
    /// The AI reports what it is doing (read/write + a human-readable note). Not gated.
    AiStatus {
        working: bool,
        activity: String,
        message: String,
    },
    Quit,
}

impl Verb {
    /// Mutating / effectful verbs honor the allow-AI gate when invoked over a gated front-end.
    fn is_gated(&self) -> bool {
        matches!(
            self,
            Verb::Author { .. }
                | Verb::AuthorCritter { .. }
                | Verb::Load { .. }
                | Verb::RegistryPublish { .. }
                | Verb::FetchLoad { .. }
                | Verb::Send { .. }
                | Verb::Intent { .. }
                | Verb::Bind { .. }
                | Verb::Unload { .. }
                | Verb::ClusterJoin { .. }
        )
    }
}

/// The result of running a verb: a machine-readable `json` (what a surface returns) and a `human`
/// string (what the REPL prints). `keep_going` is false only for `quit`. `ok` drives the HTTP status.
///
/// **Serializable:** a `VerbResult` is the payload of a `control_result` reply envelope,
/// so a surface that drove [`Role::CONTROL`] over the bus reconstructs the same structured result a
/// local caller of [`run_verb`] would see.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VerbResult {
    pub json: Value,
    pub human: String,
    pub keep_going: bool,
    pub ok: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadPreview {
    pub text: String,
    pub bytes: usize,
    pub truncated: bool,
    pub limit: usize,
}

pub fn payload_preview(payload: &[u8]) -> PayloadPreview {
    let take = payload.len().min(MAX_PRESENTED_PAYLOAD_BYTES);
    PayloadPreview {
        text: String::from_utf8_lossy(&payload[..take]).to_string(),
        bytes: payload.len(),
        truncated: payload.len() > MAX_PRESENTED_PAYLOAD_BYTES,
        limit: MAX_PRESENTED_PAYLOAD_BYTES,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlResultDecodeError {
    TooLarge { len: usize, limit: usize },
    Json(String),
}

impl fmt::Display for ControlResultDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, limit } => {
                write!(f, "control result payload is {len} bytes, exceeds {limit} byte limit")
            }
            Self::Json(e) => write!(f, "could not parse control result: {e}"),
        }
    }
}

pub fn parse_control_result(payload: &[u8]) -> Result<VerbResult, ControlResultDecodeError> {
    if payload.len() > MAX_CONTROL_RESULT_BYTES {
        return Err(ControlResultDecodeError::TooLarge {
            len: payload.len(),
            limit: MAX_CONTROL_RESULT_BYTES,
        });
    }
    serde_json::from_slice(payload).map_err(|e| ControlResultDecodeError::Json(e.to_string()))
}

/// Serialize a [`Verb`] for a `control_verb` envelope under the control-plane byte ceiling.
///
/// Surfaces call this before parking a corr or emitting onto the bus; [`ControlCore`] repeats the
/// same cap on receive so remote or non-standard senders cannot bypass it.
pub fn control_verb_payload(verb: &Verb) -> Result<Vec<u8>, VerbResult> {
    let payload = serde_json::to_vec(verb).map_err(|e| {
        VerbResult::err(
            json!({ "error": "control-verb-encode-failed", "detail": e.to_string() }),
            format!("control: could not encode the verb: {e}"),
        )
    })?;
    if payload.len() > MAX_CONTROL_VERB_BYTES {
        return Err(VerbResult::err(
            json!({
                "error": "control-verb-too-large",
                "bytes": payload.len(),
                "limit": MAX_CONTROL_VERB_BYTES
            }),
            format!(
                "control: verb payload is {} bytes, exceeds {} byte limit",
                payload.len(),
                MAX_CONTROL_VERB_BYTES
            ),
        ));
    }
    Ok(payload)
}

pub(crate) fn control_result_payload(res: VerbResult) -> Vec<u8> {
    let payload = serde_json::to_vec(&res).unwrap_or_else(|_| b"{}".to_vec());
    if payload.len() <= MAX_CONTROL_RESULT_BYTES {
        return payload;
    }
    serde_json::to_vec(&control_result_decode_failure(ControlResultDecodeError::TooLarge {
        len: payload.len(),
        limit: MAX_CONTROL_RESULT_BYTES,
    }))
    .unwrap_or_else(|_| b"{}".to_vec())
}

pub fn control_result_decode_failure(err: ControlResultDecodeError) -> VerbResult {
    match err {
        ControlResultDecodeError::TooLarge { len, limit } => VerbResult::err(
            json!({ "error": "control-result-too-large", "bytes": len, "limit": limit }),
            format!("control: result payload is {len} bytes, exceeds {limit} byte limit"),
        ),
        ControlResultDecodeError::Json(detail) => VerbResult::err(
            json!({ "error": "bad-control-result", "detail": detail }),
            format!("control: could not parse the result: {detail}"),
        ),
    }
}

impl VerbResult {
    /// A successful result — `json` is the machine body, `human` the REPL line. `pub` so a surface
    /// creature (out-of-crate) can build one when short-circuiting before the bus round-trip.
    pub fn ok(json: Value, human: impl Into<String>) -> Self {
        Self { json, human: human.into(), keep_going: true, ok: true }
    }
    /// A failed result (HTTP 400-class). `pub` for the same reason as [`VerbResult::ok`].
    pub fn err(json: Value, human: impl Into<String>) -> Self {
        Self { json, human: human.into(), keep_going: true, ok: false }
    }
    /// The allow-AI gate refused a mutating verb. The API maps this to HTTP 403.
    fn gated_block() -> Self {
        Self::err(
            json!({ "error": "ai-not-allowed", "hint": "a human must grant access (`allow-ai on` at the REPL, or start with --allow-ai)" }),
            "ai-not-allowed: a human must grant access (`allow-ai on` at the REPL)",
        )
    }
    /// True when the gate refused this verb — lets the API answer 403 rather than a generic 400.
    pub fn is_gate_block(&self) -> bool {
        !self.ok && self.json.get("error").and_then(Value::as_str) == Some("ai-not-allowed")
    }
}

fn reply_result(payload: &[u8]) -> VerbResult {
    let preview = payload_preview(payload);
    if preview.truncated {
        VerbResult::ok(
            json!({
                "reply": preview.text,
                "reply_bytes": preview.bytes,
                "reply_truncated": true,
                "reply_limit": preview.limit
            }),
            format!(
                "reply: {} ... (truncated; {} bytes total, showing {} bytes)",
                preview.text, preview.bytes, preview.limit
            ),
        )
    } else {
        VerbResult::ok(json!({ "reply": preview.text }), format!("reply: {}", preview.text))
    }
}

/// Everything [`run_verb`] needs to act on the kernel. `ai`/`kernel` are shared; `gated` is false
/// for the local REPL (never gated) and true for remote front-ends (subject to the allow-AI gate).
///
/// `probe` (a request/reply endpoint) is **optional**: the request-reply verbs (`author`, `send`,
/// `intent`) need it, the rest don't. A front-end with no probe (e.g. an API read handler) builds a
/// [`VerbCtx::no_probe`] ctx and runs only probe-free verbs; the API routes the four probe verbs to a
/// single worker thread that owns one long-lived probe (`InboxReceiver` is `!Sync`, so a probe can't
/// be shared across threads, and there is no endpoint-deregister, so we don't open one per request).
pub struct VerbCtx<'a> {
    pub kernel: &'a Kernel,
    probe: Option<(&'a BusHandle, &'a InboxReceiver)>,
    pub critter_builder: Option<CreatureId>,
    /// The TRANSPORT organ's id when this node is clustered (`--cluster-listen`); the `cluster` verbs
    /// address their control ops to it. `None` on a single node (clustering disabled).
    pub transport: Option<CreatureId>,
    pub ai: &'a AiControl,
    pub gated: bool,
    corr: u64,
}

impl<'a> VerbCtx<'a> {
    /// A ctx with a request/reply probe — drives every verb (the REPL + the API's probe worker).
    pub fn with_probe(
        kernel: &'a Kernel,
        bus: &'a BusHandle,
        rx: &'a InboxReceiver,
        critter_builder: Option<CreatureId>,
        ai: &'a AiControl,
        gated: bool,
    ) -> Self {
        Self {
            kernel,
            probe: Some((bus, rx)),
            critter_builder,
            transport: None,
            ai,
            gated,
            corr: 1,
        }
    }
    /// A probe-free ctx — for verbs that only read/mutate kernel state (`list`/`status`/`journal`/
    /// `load`/`bind`/`unload`/`allow-ai`/`ai-status`). A probe verb on this ctx returns an error.
    pub fn no_probe(
        kernel: &'a Kernel,
        critter_builder: Option<CreatureId>,
        ai: &'a AiControl,
        gated: bool,
    ) -> Self {
        Self { kernel, probe: None, critter_builder, transport: None, ai, gated, corr: 1 }
    }
    fn next_corr(&mut self) -> u64 {
        let c = self.corr;
        self.corr += 1;
        c
    }
}

fn no_probe_err() -> VerbResult {
    VerbResult::err(
        json!({ "error": "no-probe", "hint": "this verb needs a request/reply endpoint" }),
        "internal: this verb needs a probe endpoint (routing error)",
    )
}

fn read_node_file_bounded(path: &str, label: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("read {label} {path}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("read {label} {path}: not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "read {label} {path}: file is {} bytes, exceeds {} byte limit",
            metadata.len(),
            max_bytes
        ));
    }

    let file = File::open(path).map_err(|e| format!("read {label} {path}: {e}"))?;
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len().min(1024 * 1024) as usize);
    reader.read_to_end(&mut bytes).map_err(|e| format!("read {label} {path}: {e}"))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
        return Err(format!(
            "read {label} {path}: file grew past {} byte limit while reading",
            max_bytes
        ));
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------------------------
// Parsing (REPL / --exec / --script). The API constructs `Verb`s directly from JSON.
// ---------------------------------------------------------------------------------------------

/// Parse one REPL line into a [`Verb`]. `Err` carries a usage string. A blank line is `Ok(None)`.
pub fn parse_verb(line: &str) -> Result<Option<Verb>, String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let v = match parts.as_slice() {
        [] => return Ok(None),
        ["quit"] | ["exit"] => Verb::Quit,
        ["help"] => Verb::Help,
        ["list"] => Verb::List,
        ["status"] => Verb::Status,
        ["journal"] => Verb::Journal { limit: 20 },
        ["watch"] => Verb::Watch,
        ["cluster"] => Verb::Cluster,
        ["cluster", "join", spec] => parse_cluster_spec(spec)?,
        ["cluster", ..] => {
            return Err("usage: cluster | cluster join <node-id@host:port#pubkey-hex>".into())
        }
        ["allow-ai", "on"] => Verb::AllowAi { allowed: true },
        ["allow-ai", "off"] => Verb::AllowAi { allowed: false },
        ["allow-ai", ..] => return Err("usage: allow-ai <on|off>".into()),
        ["author", "--critter", req @ ..] if !req.is_empty() => {
            Verb::AuthorCritter { request: req.join(" ") }
        }
        ["author", req @ ..] if !req.is_empty() && req[0] != "--critter" => {
            Verb::Author { request: req.join(" ") }
        }
        ["author"] | ["author", "--critter"] => {
            return Err("usage: author [--critter] <natural-language request>".into())
        }
        ["load", manifest_path, artifact_path] => Verb::Load {
            manifest_path: (*manifest_path).to_string(),
            artifact_path: (*artifact_path).to_string(),
        },
        ["load", ..] => return Err("usage: load <manifest> <artifact>".into()),
        ["registry", "publish", manifest_path, artifact_path] => Verb::RegistryPublish {
            manifest_path: (*manifest_path).to_string(),
            artifact_path: (*artifact_path).to_string(),
            realm: None,
        },
        ["registry", "publish", manifest_path, artifact_path, realm] => Verb::RegistryPublish {
            manifest_path: (*manifest_path).to_string(),
            artifact_path: (*artifact_path).to_string(),
            realm: Some(RealmId::new(*realm)),
        },
        ["registry", "fetch", artifact_hash] => {
            Verb::RegistryFetch { artifact_hash: (*artifact_hash).to_string(), realm: None }
        }
        ["registry", "fetch", artifact_hash, realm] => Verb::RegistryFetch {
            artifact_hash: (*artifact_hash).to_string(),
            realm: Some(RealmId::new(*realm)),
        },
        ["registry", "list"] => Verb::RegistryList { realm: None },
        ["registry", "list", realm] => Verb::RegistryList { realm: Some(RealmId::new(*realm)) },
        ["registry", "fetch-load", artifact_hash] => Verb::FetchLoad {
            artifact_hash: (*artifact_hash).to_string(),
            node: None,
            registry_id: None,
            realm: None,
            chunk_size: None,
        },
        ["registry", "fetch-load", artifact_hash, realm] => Verb::FetchLoad {
            artifact_hash: (*artifact_hash).to_string(),
            node: None,
            registry_id: None,
            realm: Some(RealmId::new(*realm)),
            chunk_size: None,
        },
        ["registry", "fetch-load", artifact_hash, node, registry_id] => {
            match registry_id.parse::<u64>() {
                Ok(rid) => Verb::FetchLoad {
                    artifact_hash: (*artifact_hash).to_string(),
                    node: Some((*node).to_string()),
                    registry_id: Some(rid),
                    realm: None,
                    chunk_size: None,
                },
                Err(_) => return Err(FETCH_LOAD_USAGE.into()),
            }
        }
        ["registry", "fetch-load", artifact_hash, node, registry_id, realm] => {
            match registry_id.parse::<u64>() {
                Ok(rid) => Verb::FetchLoad {
                    artifact_hash: (*artifact_hash).to_string(),
                    node: Some((*node).to_string()),
                    registry_id: Some(rid),
                    realm: Some(RealmId::new(*realm)),
                    chunk_size: None,
                },
                Err(_) => return Err(FETCH_LOAD_USAGE.into()),
            }
        }
        ["registry", ..] => {
            return Err("usage: registry publish <manifest> <artifact> [realm] | registry fetch <artifact-hash> [realm] | registry list [realm] | registry fetch-load <artifact-hash> [<node-id> <registry-id>] [realm]".into())
        }
        ["bestiary", "prove", artifact_hash, realm] => Verb::BestiaryProve {
            artifact_hash: (*artifact_hash).to_string(),
            realm: RealmId::new(*realm),
        },
        ["bestiary", ..] => return Err("usage: bestiary prove <artifact-hash> <realm>".into()),
        ["unload", id_str] => {
            let id = id_str.parse::<u64>().map_err(|_| "usage: unload <id>".to_string())?;
            Verb::Unload { id }
        }
        ["bind", role, id_str] => {
            let id = id_str.parse::<u64>().map_err(|_| "usage: bind <role> <id>".to_string())?;
            Verb::Bind { role: (*role).to_string(), id }
        }
        ["send", target, text @ ..] => {
            // `send <id> <text>` is local; `send <node-id>:<id> <text>` routes across the cluster.
            let (node, id_str) = match target.split_once(':') {
                Some((n, i)) => (Some(n.to_string()), i),
                None => (None, *target),
            };
            let id = id_str
                .parse::<u64>()
                .map_err(|_| "usage: send <[node-id:]id> <text>".to_string())?;
            Verb::Send { id, text: text.join(" "), node }
        }
        ["intent", outcome, text @ ..] => {
            Verb::Intent { outcome: (*outcome).to_string(), text: text.join(" ") }
        }
        _ => return Err(COMMANDS.into()),
    };
    Ok(Some(v))
}

// ---------------------------------------------------------------------------------------------
// The command core
// ---------------------------------------------------------------------------------------------

/// Run one [`Verb`] against the kernel. The single source of truth for every front-end.
///
/// `progress` is called with short status lines during long verbs (e.g. `author`'s "compiling…"),
/// so the REPL keeps its live feedback and the API can stream the line onto the WS sense channel.
pub fn run_verb(verb: Verb, ctx: &mut VerbCtx, progress: &mut dyn FnMut(&str)) -> VerbResult {
    // The allow-AI gate: a gated (remote) front-end may not run a mutating verb until a human grants
    // it. The local REPL is never gated; read-only verbs are never gated.
    if ctx.gated && verb.is_gated() && !ctx.ai.allowed() {
        return VerbResult::gated_block();
    }
    match verb {
        Verb::Help => VerbResult::ok(json!({ "commands": COMMANDS }), COMMANDS),
        Verb::Quit => VerbResult {
            json: json!({ "ok": true }),
            human: "bye.".into(),
            keep_going: false,
            ok: true,
        },
        Verb::List => {
            let v = creatures_json(ctx.kernel);
            VerbResult::ok(json!({ "creatures": v }), render_list(&v))
        }
        Verb::Status => {
            let j = status_json(ctx.kernel, ctx.ai);
            let human = render_status(&j);
            VerbResult::ok(j, human)
        }
        Verb::Journal { limit } => {
            let (total, entries) = journal_json(ctx.kernel, limit);
            let human = render_journal(total, &entries);
            VerbResult::ok(json!({ "total": total, "entries": entries }), human)
        }
        Verb::Watch => {
            let human = "the monitor is tailing PROPRIOCEPTION + FITNESS on stdout above; use `journal` for the bus history, or connect a client to /api/ws for the live stream.";
            VerbResult::ok(json!({ "ok": true, "note": human }), human)
        }
        Verb::AllowAi { allowed } => {
            if ctx.gated {
                return VerbResult::err(
                    json!({ "error": "repl-only", "hint": "the allow-AI gate is controlled at the local REPL (or --allow-ai at startup), not over the API" }),
                    "allow-ai is REPL-only (the human seat); it cannot be flipped over the API",
                );
            }
            ctx.ai.set_allowed(allowed);
            let human = format!(
                "allow-ai is now {}",
                if allowed {
                    "ON — remote AI may author/load/mutate"
                } else {
                    "OFF — remote AI is read-only"
                }
            );
            VerbResult::ok(json!({ "ok": true, "ai_allowed": allowed }), human)
        }
        Verb::AiStatus { working, activity, message } => {
            let activity = sanitize_ai_status_text(&activity);
            let message = sanitize_ai_status_text(&message);
            ctx.ai.set_status(working, activity.clone(), message.clone());
            let human = if working {
                format!("[ai] {activity}: {message}")
            } else {
                "[ai] idle".to_string()
            };
            VerbResult::ok(json!({ "ok": true }), human)
        }
        Verb::Bind { role, id } => {
            if let Err(reason) = validate_control_role_name(&role) {
                return VerbResult::err(
                    json!({
                        "error": "invalid-role-name",
                        "reason": reason,
                        "limit": MAX_CONTROL_ROLE_NAME_BYTES
                    }),
                    format!("invalid role name: {reason}"),
                );
            }
            ctx.kernel.bind_role(Role::new(&role), CreatureId(id));
            VerbResult::ok(
                json!({ "ok": true, "role": role, "id": id }),
                format!("bound role `{role}` -> id={id}"),
            )
        }
        Verb::Unload { id } => match ctx.kernel.unload(CreatureId(id), Deadline::default()) {
            Ok(()) => {
                VerbResult::ok(json!({ "ok": true, "unloaded": id }), format!("unloaded {id}"))
            }
            Err(e) => VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("unload failed: {e}"),
            ),
        },
        Verb::Load { manifest_path, artifact_path } => {
            verb_load(ctx, &manifest_path, &artifact_path)
        }
        Verb::RegistryPublish { manifest_path, artifact_path, realm } => {
            verb_registry_publish(ctx, &manifest_path, &artifact_path, realm)
        }
        Verb::RegistryFetch { artifact_hash, realm } => {
            verb_registry_fetch(ctx, &artifact_hash, realm)
        }
        Verb::RegistryList { realm } => verb_registry_list(ctx, realm),
        Verb::FetchLoad { artifact_hash, node, registry_id, realm, chunk_size } => {
            verb_fetch_load(ctx, &artifact_hash, node.as_deref(), registry_id, realm, chunk_size)
        }
        Verb::BestiaryProve { artifact_hash, realm } => {
            verb_bestiary_prove(ctx, &artifact_hash, realm)
        }
        Verb::Send { id, text, node } => verb_send(ctx, id, &text, node.as_deref()),
        Verb::Intent { outcome, text } => verb_intent(ctx, &outcome, &text),
        Verb::Author { request } => verb_author(ctx, &request, progress),
        Verb::AuthorCritter { request } => verb_author_critter(ctx, &request, progress),
        Verb::Cluster => verb_cluster(ctx),
        Verb::ClusterJoin { node_id, addr, pubkey } => {
            verb_cluster_join(ctx, &node_id, &addr, &pubkey)
        }
    }
}

fn verb_load(ctx: &mut VerbCtx, manifest_path: &str, artifact_path: &str) -> VerbResult {
    let m_bytes =
        match read_node_file_bounded(manifest_path, "manifest", MAX_CONTROL_MANIFEST_BYTES) {
            Ok(b) => b,
            Err(e) => {
                return VerbResult::err(
                    json!({ "ok": false, "error": e }),
                    format!("load failed: {e}"),
                )
            }
        };
    let m = match Manifest::parse(&m_bytes) {
        Ok(m) => m,
        Err(e) => {
            return VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("load failed: {e}"),
            )
        }
    };
    let artifact = match m.abi.backend {
        Backend::Daemon => Artifact::Path(artifact_path.into()),
        Backend::Beast | Backend::Critter => {
            match read_node_file_bounded(artifact_path, "artifact", MAX_CONTROL_ARTIFACT_BYTES) {
                Ok(bytes) => Artifact::Bytes(bytes),
                Err(e) => {
                    return VerbResult::err(
                        json!({ "ok": false, "error": e }),
                        format!("load failed: {e}"),
                    )
                }
            }
        }
    };
    match ctx.kernel.load(m, artifact) {
        Ok(id) => VerbResult::ok(
            json!({ "ok": true, "creature_id": id.0 }),
            format!("loaded id={}", id.0),
        ),
        Err(e) => VerbResult::err(
            json!({ "ok": false, "error": e.to_string() }),
            format!("load failed: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Registry / Bestiary verbs — operator/AI-driven catalogue ops over the bus to Role::REGISTRY.
// Unlike `load` (inline kernel call), these do a request/reply round-trip, so they need a probe.
// ---------------------------------------------------------------------------------------------

/// Bound for a registry/bestiary op round-trip. The registry creature replies promptly (in-memory in
/// ms; the durable daemon does a small fs write); this only bites if nothing is bound to REGISTRY.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum RoleReplyDecodeError {
    TooLarge { len: usize, limit: usize },
    Json(serde_json::Error),
}

impl fmt::Display for RoleReplyDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, limit } => {
                write!(f, "payload is {len} bytes, exceeds {limit} byte limit")
            }
            Self::Json(e) => write!(f, "{e}"),
        }
    }
}

fn parse_role_reply<T: DeserializeOwned>(
    payload: &[u8],
    limit: usize,
) -> Result<T, RoleReplyDecodeError> {
    if payload.len() > limit {
        return Err(RoleReplyDecodeError::TooLarge { len: payload.len(), limit });
    }
    serde_json::from_slice(payload).map_err(RoleReplyDecodeError::Json)
}

/// Ship a `RegistryOp` to `Role::REGISTRY` and decode the `RegistryReply`. The `Err` arm is a
/// ready-to-return [`VerbResult`] (no probe / route failure / timeout / parse error), so callers
/// `match` on the reply variant and bubble `Err(res)` through.
fn registry_request(
    ctx: &mut VerbCtx,
    op: RegistryOp,
    reply_limit: usize,
) -> Result<RegistryReply, VerbResult> {
    let Some((bus, rx)) = ctx.probe else { return Err(no_probe_err()) };
    let payload = match serde_json::to_vec(&op) {
        Ok(p) => p,
        Err(e) => {
            return Err(VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("registry op encode failed: {e}"),
            ))
        }
    };
    let c = ctx.next_corr();
    let d = Dispatch::to(Address::Role(Role::new(Role::REGISTRY)), payload)
        .with_schema(REGISTRY_OP_SCHEMA)
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(c);
    match request_reply(bus, rx, d, c, REGISTRY_TIMEOUT) {
        Ok(Some(env)) => {
            parse_role_reply::<RegistryReply>(&env.payload, reply_limit).map_err(|e| {
                VerbResult::err(
                    json!({ "ok": false, "error": e.to_string() }),
                    format!("registry reply parse failed: {e}"),
                )
            })
        }
        Ok(None) => Err(VerbResult::err(
            json!({ "ok": false, "error": "nothing bound to REGISTRY" }),
            "registry op failed: nothing bound to REGISTRY (running --minimal?)",
        )),
        Err(e) => Err(VerbResult::err(
            json!({ "ok": false, "unrouted": true, "error": e.to_string() }),
            format!("registry op failed: {e}"),
        )),
    }
}

/// Like [`registry_request`] but over the additive `bestiary.op` schema, decoding a [`BestiaryReply`].
fn bestiary_request(ctx: &mut VerbCtx, op: BestiaryOp) -> Result<BestiaryReply, VerbResult> {
    let Some((bus, rx)) = ctx.probe else { return Err(no_probe_err()) };
    let c = ctx.next_corr();
    let d = Dispatch::to(Address::Role(Role::new(Role::REGISTRY)), op.to_bytes())
        .with_schema(BESTIARY_OP_SCHEMA)
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(c);
    match request_reply(bus, rx, d, c, REGISTRY_TIMEOUT) {
        Ok(Some(env)) => parse_role_reply::<BestiaryReply>(&env.payload, MAX_BESTIARY_REPLY_BYTES)
            .map_err(|e| {
                VerbResult::err(
                    json!({ "ok": false, "error": e.to_string() }),
                    format!("bestiary reply parse failed: {e}"),
                )
            }),
        Ok(None) => Err(VerbResult::err(
            json!({ "ok": false, "error": "nothing bound to REGISTRY" }),
            "bestiary op failed: nothing bound to REGISTRY (running --minimal?)",
        )),
        Err(e) => Err(VerbResult::err(
            json!({ "ok": false, "unrouted": true, "error": e.to_string() }),
            format!("bestiary op failed: {e}"),
        )),
    }
}

fn registry_unexpected(reply: RegistryReply) -> VerbResult {
    VerbResult::err(
        json!({ "ok": false, "error": format!("unexpected registry reply: {reply:?}") }),
        format!("registry op: unexpected reply: {reply:?}"),
    )
}

fn verb_registry_publish(
    ctx: &mut VerbCtx,
    manifest_path: &str,
    artifact_path: &str,
    realm: Option<RealmId>,
) -> VerbResult {
    // NODE-LOCAL paths — the same operator caveat as `load`: these name files on the node's own
    // filesystem, not client uploads. A surface caller hands the node a path it can already read.
    let m_bytes =
        match read_node_file_bounded(manifest_path, "manifest", MAX_CONTROL_MANIFEST_BYTES) {
            Ok(b) => b,
            Err(e) => {
                return VerbResult::err(
                    json!({ "ok": false, "error": e }),
                    format!("registry publish failed: {e}"),
                )
            }
        };
    let manifest = match Manifest::parse(&m_bytes) {
        Ok(m) => m,
        Err(e) => {
            return VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("registry publish failed: {e}"),
            )
        }
    };
    let artifact =
        match read_node_file_bounded(artifact_path, "artifact", MAX_CONTROL_ARTIFACT_BYTES) {
            Ok(b) => b,
            Err(e) => {
                return VerbResult::err(
                    json!({ "ok": false, "error": e }),
                    format!("registry publish failed: {e}"),
                )
            }
        };
    let op = RegistryOp::Publish { manifest, artifact, realm };
    match registry_request(ctx, op, MAX_REGISTRY_ACK_REPLY_BYTES) {
        Ok(RegistryReply::Published { artifact_hash, realm }) => VerbResult::ok(
            json!({ "ok": true, "artifact_hash": artifact_hash, "realm": realm.0 }),
            format!("published artifact {artifact_hash} into realm `{}`", realm.0),
        ),
        Ok(other) => registry_unexpected(other),
        Err(res) => res,
    }
}

/// Render a metadata-only fetched entry — never raw artifact bytes inline.
fn fetched_metadata_ok(entry: &CatalogEntry, artifact_len: usize) -> VerbResult {
    let manifest = &entry.manifest;
    let realm_str = entry.realm.0.clone();
    let j = json!({
        "ok": true,
        "name": manifest.name,
        "version": manifest.version,
        "content_address": manifest.content_address,
        "artifact_len": artifact_len,
        "realm": realm_str,
    });
    VerbResult::ok(
        j,
        format!(
            "entry `{}` v{} ({} bytes) in realm `{}`",
            manifest.name, manifest.version, artifact_len, realm_str
        ),
    )
}

fn verb_registry_fetch(
    ctx: &mut VerbCtx,
    artifact_hash: &str,
    realm: Option<RealmId>,
) -> VerbResult {
    let op = RegistryOp::FetchMetadata { artifact_hash: artifact_hash.to_string(), realm };
    match registry_request(ctx, op, MAX_REGISTRY_FETCH_REPLY_BYTES) {
        Ok(RegistryReply::FetchedMetadata { entry, artifact_len }) => {
            fetched_metadata_ok(&entry, artifact_len)
        }
        Ok(RegistryReply::NotFound) => VerbResult::err(
            json!({ "ok": false, "not_found": true, "artifact_hash": artifact_hash }),
            format!("registry fetch: no entry for {artifact_hash}"),
        ),
        Ok(other) => registry_unexpected(other),
        Err(res) => res,
    }
}

fn verb_registry_list(ctx: &mut VerbCtx, realm: Option<RealmId>) -> VerbResult {
    let scope = realm.as_ref().map(|r| r.0.clone()).unwrap_or_else(|| "(all realms)".to_string());
    match registry_request(
        ctx,
        RegistryOp::ListMetadata { realm },
        MAX_REGISTRY_METADATA_REPLY_BYTES,
    ) {
        Ok(RegistryReply::Metadata { entries }) => {
            let mut entries = entries;
            entries.sort_by(|a, b| {
                a.realm
                    .0
                    .cmp(&b.realm.0)
                    .then_with(|| a.manifest.name.cmp(&b.manifest.name))
                    .then_with(|| a.manifest.version.cmp(&b.manifest.version))
                    .then_with(|| a.artifact_hash.cmp(&b.artifact_hash))
            });
            let arr: Vec<Value> = entries
                .iter()
                .map(|e| {
                    json!({
                        "artifact_hash": e.artifact_hash,
                        "realm": e.realm.0,
                        "name": e.manifest.name,
                        "version": e.manifest.version,
                        "reputation": e.reputation.as_ref().map(|r| r.score),
                        "quarantined": e.quarantine.is_some(),
                    })
                })
                .collect();
            let mut human = format!(
                "catalogue {scope}: {} entr{}",
                arr.len(),
                if arr.len() == 1 { "y" } else { "ies" }
            );
            for e in &entries {
                human.push_str(&format!(
                    "\n  {} {:<24} v{:<8} realm={}{}",
                    &e.artifact_hash[..e.artifact_hash.len().min(12)],
                    e.manifest.name,
                    e.manifest.version,
                    e.realm.0,
                    if e.quarantine.is_some() { " [quarantined]" } else { "" }
                ));
            }
            VerbResult::ok(json!({ "ok": true, "count": arr.len(), "entries": arr }), human)
        }
        Ok(other) => registry_unexpected(other),
        Err(res) => res,
    }
}

/// Usage string for the `registry fetch-load` REPL form, shared by the parse arms.
const FETCH_LOAD_USAGE: &str =
    "usage: registry fetch-load <artifact-hash> [<node-id> <registry-id>] [realm]";

/// Overall wall-clock budget for a whole GX fetch-and-load (plan + every chunk). A large artifact over
/// a slow link can legitimately take a while; this only fires on a genuinely dead transfer.
const FETCH_LOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// How long one `recv` blocks before we treat the transfer as stalled and re-request the gaps. Short
/// enough to recover a dropped chunk promptly, long enough not to spin.
const GX_STALL: Duration = Duration::from_millis(2000);
/// How many chunk requests we keep roughly in flight — backpressure that bounds the registry's reply
/// burst instead of asking for the whole artifact at once.
const GX_PULL_WINDOW: u32 = 8;

/// The bus address a fetch-load op targets: a peer node's registry creature (cross-node, over the
/// cluster) or this node's local `Role::REGISTRY`.
fn fetch_load_target(node: Option<&str>, registry_id: Option<u64>) -> Result<Address, VerbResult> {
    match (node, registry_id) {
        (Some(n), Some(rid)) => {
            Ok(Address::Node(aether::NodeId(n.to_string()), aether::CreatureId(rid)))
        }
        (Some(_), None) => Err(VerbResult::err(
            json!({ "ok": false, "error": "cross-node fetch-load needs <registry-id>" }),
            "fetch-load: a cross-node fetch needs the peer registry's id (registry addressing is node-local)",
        )),
        (None, _) => Ok(Address::Role(Role::new(Role::REGISTRY))),
    }
}

/// Build the plan-only GX op for a realm. The GX bulk ops keep their explicit `*InRealm` split (the
/// small full-artifact ops collapsed their pairs in 0.4.1; the bulk ones did not).
fn gx_plan_op(artifact_hash: &str, realm: Option<&RealmId>, chunk_size: Option<u32>) -> RegistryOp {
    match realm {
        None => RegistryOp::FetchGxPlan { artifact_hash: artifact_hash.to_string(), chunk_size },
        Some(r) => RegistryOp::FetchGxPlanInRealm {
            artifact_hash: artifact_hash.to_string(),
            realm: r.clone(),
            chunk_size,
        },
    }
}

/// Send one `FetchGxChunk` (or its realm-explicit twin) to `target`, correlated by `corr` so the raw
/// chunk frame routes back to our probe. Errors map to a `VerbResult`.
/// The transfer-invariant context for pulling GX chunks: everything a `FetchGxChunk` request needs
/// except the chunk index. Built once per fetch-load, then `request`ed per index (prime, refill, and
/// gap re-request all go through it).
struct GxChunkPuller<'a> {
    bus: &'a BusHandle,
    target: &'a Address,
    artifact_hash: &'a str,
    realm: Option<&'a RealmId>,
    transfer_id: &'a str,
    chunk_size: u32,
    corr: u64,
}

impl GxChunkPuller<'_> {
    /// Send one `FetchGxChunk` (or its realm-explicit twin), correlated by `corr` so the raw chunk
    /// frame routes back to our probe. Errors map to a `VerbResult`.
    fn request(&self, chunk_index: u32) -> Result<(), VerbResult> {
        let op = match self.realm {
            None => RegistryOp::FetchGxChunk {
                artifact_hash: self.artifact_hash.to_string(),
                transfer_id: self.transfer_id.to_string(),
                chunk_size: self.chunk_size,
                chunk_index,
            },
            Some(r) => RegistryOp::FetchGxChunkInRealm {
                artifact_hash: self.artifact_hash.to_string(),
                realm: r.clone(),
                transfer_id: self.transfer_id.to_string(),
                chunk_size: self.chunk_size,
                chunk_index,
            },
        };
        let payload = serde_json::to_vec(&op).map_err(|e| {
            VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("fetch-load: chunk op encode failed: {e}"),
            )
        })?;
        let d = Dispatch::to(self.target.clone(), payload)
            .with_schema(REGISTRY_OP_SCHEMA)
            .with_reply_to(Address::Creature(self.bus.id()))
            .with_corr(self.corr);
        self.bus.send(d).map_err(|e| {
            VerbResult::err(
                json!({ "ok": false, "unrouted": true, "error": e.to_string() }),
                format!("fetch-load: chunk request failed: {e}"),
            )
        })
    }
}

/// Fetch a creature artifact over GX, assemble + integrity-check it, and load it into this node. This
/// is the operator path the `m2_two_node` test hand-scripted: `FetchGxPlan` → a windowed `FetchGxChunk`
/// pull (re-requesting only the gaps on a stall, so a dropped chunk resumes rather than restarts) →
/// `ChunkAssembler` (per-chunk + whole-file SHA-256) → `kernel.load` (which re-verifies signature +
/// bytes at admission, so a tampered fetch is refused there).
fn verb_fetch_load(
    ctx: &mut VerbCtx,
    artifact_hash: &str,
    node: Option<&str>,
    registry_id: Option<u64>,
    realm: Option<RealmId>,
    chunk_size: Option<u32>,
) -> VerbResult {
    if let Some(message) = bestiary::artifact_hash_shape_error(artifact_hash) {
        return VerbResult::err(
            json!({ "ok": false, "error": message }),
            format!("fetch-load: {message}"),
        );
    }
    let target = match fetch_load_target(node, registry_id) {
        Ok(t) => t,
        Err(res) => return res,
    };
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };

    // --- step 1: ask for a plan-only GX transfer (we pace the chunk pull ourselves) ---
    let plan_corr = ctx.next_corr();
    let plan_payload =
        match serde_json::to_vec(&gx_plan_op(artifact_hash, realm.as_ref(), chunk_size)) {
            Ok(p) => p,
            Err(e) => {
                return VerbResult::err(
                    json!({ "ok": false, "error": e.to_string() }),
                    format!("fetch-load: plan op encode failed: {e}"),
                )
            }
        };
    let plan_dispatch = Dispatch::to(target.clone(), plan_payload)
        .with_schema(REGISTRY_OP_SCHEMA)
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(plan_corr);
    let plan_env =
        match request_reply(bus, rx, plan_dispatch, plan_corr, REGISTRY_TIMEOUT) {
            Ok(Some(env)) => env,
            Ok(None) => return VerbResult::err(
                json!({ "ok": false, "error": "no GX plan reply" }),
                "fetch-load: no plan reply (nothing bound to REGISTRY, or the peer is unreachable)",
            ),
            Err(e) => {
                return VerbResult::err(
                    json!({ "ok": false, "unrouted": true, "error": e.to_string() }),
                    format!("fetch-load: plan request failed: {e}"),
                )
            }
        };
    let plan_reply = match parse_role_reply::<RegistryReply>(
        &plan_env.payload,
        MAX_REGISTRY_FETCH_REPLY_BYTES,
    ) {
        Ok(r) => r,
        Err(e) => {
            return VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("fetch-load: plan reply parse failed: {e}"),
            )
        }
    };
    let (manifest, plan) = match plan_reply {
        // Both the realm-implicit and realm-explicit GX plan replies carry the same plan fields; the
        // extra `realm` on the `InRealm` reply is irrelevant here (`..`).
        RegistryReply::FetchedGx {
            manifest,
            artifact_hash: reply_artifact_hash,
            transfer_id,
            file_size,
            file_hash,
            chunk_size,
            ..
        }
        | RegistryReply::FetchedGxInRealm {
            manifest,
            artifact_hash: reply_artifact_hash,
            transfer_id,
            file_size,
            file_hash,
            chunk_size,
            ..
        } => {
            if reply_artifact_hash != artifact_hash || file_hash != artifact_hash {
                let message = format!(
                    "registry returned GX plan for artifact_hash `{reply_artifact_hash}` with file_hash `{file_hash}`, expected `{artifact_hash}`"
                );
                let human = format!("fetch-load: {message}");
                return VerbResult::err(json!({ "ok": false, "error": message }), human);
            }
            match gawdxfer::TransferPlan::new(transfer_id, file_size, file_hash, chunk_size) {
                Ok(plan) => (manifest, plan),
                Err(e) => {
                    return VerbResult::err(
                        json!({ "ok": false, "error": e.to_string() }),
                        format!("fetch-load: registry returned an invalid GX plan: {e}"),
                    )
                }
            }
        }
        RegistryReply::NotFound => {
            return VerbResult::err(
                json!({ "ok": false, "not_found": true, "artifact_hash": artifact_hash }),
                format!("fetch-load: no entry for {artifact_hash}"),
            )
        }
        RegistryReply::Error { message } => {
            return VerbResult::err(
                json!({ "ok": false, "error": message }),
                format!("fetch-load: registry refused the plan: {message}"),
            )
        }
        other => return registry_unexpected(other),
    };

    // --- step 2: pull chunks in a sliding window, re-requesting gaps on a stall (resume) ---
    let total_chunks = plan.total_chunks;
    let plan_chunk_size = plan.chunk_size;
    let file_size = plan.file_size;
    let transfer_id = plan.transfer_id.clone();
    let mut assembler = match gawdxfer::ChunkAssembler::new(plan) {
        Ok(a) => a,
        Err(e) => {
            return VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("fetch-load: cannot hold the artifact in memory to assemble it: {e}"),
            )
        }
    };
    let chunk_corr = ctx.next_corr();
    let puller = GxChunkPuller {
        bus,
        target: &target,
        artifact_hash,
        realm: realm.as_ref(),
        transfer_id: &transfer_id,
        chunk_size: plan_chunk_size,
        corr: chunk_corr,
    };

    // Prime the window, then keep ~`GX_PULL_WINDOW` requests outstanding by requesting one fresh index
    // per accepted chunk. `next` is the high-water mark of indices ever requested.
    let mut next: u32 = 0;
    while next < total_chunks && next < GX_PULL_WINDOW {
        if let Err(res) = puller.request(next) {
            return res;
        }
        next += 1;
    }

    let deadline = std::time::Instant::now() + FETCH_LOAD_TIMEOUT;
    while !assembler.is_complete() {
        if std::time::Instant::now() >= deadline {
            let missing = assembler.missing_chunks();
            return VerbResult::err(
                json!({ "ok": false, "error": "gx-timeout", "missing_chunks": missing.len() }),
                format!(
                    "fetch-load: timed out with {} of {total_chunks} chunks still missing",
                    missing.len()
                ),
            );
        }
        match rx.recv_timeout(GX_STALL) {
            Ok(env)
                if env.header.corr == Some(chunk_corr)
                    && env.header.schema == gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA =>
            {
                // A corrupt frame is dropped (the stall path will re-request the gap); a good one
                // advances the window by requesting the next never-requested index.
                if assembler.accept_binary_frame(&env.payload).is_ok() && next < total_chunks {
                    if let Err(res) = puller.request(next) {
                        return res;
                    }
                    next += 1;
                }
            }
            Ok(env)
                if env.header.corr == Some(chunk_corr) && env.header.schema == "registry.reply" =>
            {
                // The registry answered a chunk request with an error/not-found rather than a frame.
                if let Ok(reply) =
                    parse_role_reply::<RegistryReply>(&env.payload, MAX_REGISTRY_FETCH_REPLY_BYTES)
                {
                    match reply {
                        RegistryReply::Error { message } => {
                            return VerbResult::err(
                                json!({ "ok": false, "error": message }),
                                format!("fetch-load: registry refused a chunk: {message}"),
                            )
                        }
                        RegistryReply::NotFound => {
                            return VerbResult::err(
                                json!({ "ok": false, "not_found": true }),
                                "fetch-load: registry lost the entry mid-transfer",
                            )
                        }
                        _ => {}
                    }
                }
            }
            Ok(_) => {} // an unrelated envelope on the probe inbox — ignore
            Err(_) => {
                // Stall: re-request the gaps. Idempotent — the registry is content-addressed and the
                // assembler dedups, so re-asking is always safe (this is the "resume" path).
                for &gap in assembler.missing_chunks().iter().take(GX_PULL_WINDOW as usize) {
                    if let Err(res) = puller.request(gap) {
                        return res;
                    }
                }
            }
        }
    }

    // --- step 3: integrity-check the whole artifact, then admit + load it ---
    let artifact = match assembler.finish() {
        Ok(bytes) => bytes,
        Err(e) => {
            return VerbResult::err(
                json!({ "ok": false, "error": e.to_string() }),
                format!("fetch-load: assembled artifact failed its integrity check: {e}"),
            )
        }
    };
    let realm_str = realm.as_ref().map(|r| r.0.clone()).unwrap_or_else(|| RealmId::local().0);
    match ctx.kernel.load(manifest, Artifact::Bytes(artifact)) {
        Ok(id) => VerbResult::ok(
            json!({
                "ok": true,
                "creature_id": id.0,
                "artifact_hash": artifact_hash,
                "realm": realm_str,
                "chunks": total_chunks,
                "bytes": file_size,
            }),
            format!(
                "fetch-load: pulled {file_size} bytes in {total_chunks} GX chunks from realm `{realm_str}`, admitted + loaded as id={}",
                id.0
            ),
        ),
        Err(e) => VerbResult::err(
            json!({ "ok": false, "error": e.to_string() }),
            format!("fetch-load: admission/load rejected the fetched artifact: {e}"),
        ),
    }
}

fn verb_bestiary_prove(ctx: &mut VerbCtx, artifact_hash: &str, realm: RealmId) -> VerbResult {
    let realm_name = realm.0.clone();
    let op = BestiaryOp::ProveEntry { artifact_hash: artifact_hash.to_string(), realm };
    match bestiary_request(ctx, op) {
        Ok(BestiaryReply::EntryProof { proof }) => {
            let human = format!(
                "entry proof for {} in realm `{}` (first_seen={}, attester={})",
                proof.artifact_hash, proof.realm.0, proof.first_seen, proof.attester
            );
            let proof_json = serde_json::to_value(&proof).unwrap_or_else(|_| json!({}));
            VerbResult::ok(json!({ "ok": true, "proof": proof_json }), human)
        }
        Ok(BestiaryReply::NotFound) => VerbResult::err(
            json!({ "ok": false, "not_found": true, "artifact_hash": artifact_hash }),
            format!("bestiary prove: no entry for {artifact_hash} in realm `{realm_name}`"),
        ),
        Ok(BestiaryReply::Error { message }) => VerbResult::err(
            json!({ "ok": false, "error": message }),
            format!("bestiary prove failed: {message}"),
        ),
        Ok(other) => VerbResult::err(
            json!({ "ok": false, "error": format!("unexpected bestiary reply: {other:?}") }),
            format!("bestiary prove: unexpected reply: {other:?}"),
        ),
        Err(res) => res,
    }
}

fn verb_send(ctx: &mut VerbCtx, id: u64, text: &str, node: Option<&str>) -> VerbResult {
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
    let c = ctx.next_corr();
    // A cross-node send (`Some(node)`) rides the cluster: the transport ships it to the peer and
    // rewrites our `reply_to` so the reply routes back here. A local send is `Module`.
    let to = match node {
        Some(n) => Address::Node(NodeId(n.to_string()), CreatureId(id)),
        None => Address::Creature(CreatureId(id)),
    };
    let d = Dispatch::to(to, text.as_bytes().to_vec())
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(c);
    // A local reply is in-process (sub-ms); a cross-node reply makes a full mesh round-trip plus the
    // peer's own handling, which on a WAN can exceed the local budget. Give the cross-node case a
    // wider window so a healthy-but-distant peer isn't falsely reported as a timeout.
    let (budget, window) = if node.is_some() {
        (Duration::from_secs(10), "10s")
    } else {
        (Duration::from_secs(2), "2s")
    };
    match request_reply(bus, rx, d, c, budget) {
        Ok(Some(env)) => reply_result(&env.payload),
        Ok(None) => {
            VerbResult::ok(json!({ "timeout": true }), format!("(no reply within {window})"))
        }
        Err(e) => VerbResult::err(
            json!({ "ok": false, "unrouted": true, "error": e.to_string() }),
            format!("send failed: {e}"),
        ),
    }
}

fn verb_intent(ctx: &mut VerbCtx, outcome: &str, text: &str) -> VerbResult {
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
    let c = ctx.next_corr();
    let d = Dispatch::to(
        Address::Intent(Intent { outcome: outcome.to_string(), requirements: vec![] }),
        text.as_bytes().to_vec(),
    )
    .with_reply_to(Address::Creature(bus.id()))
    .with_corr(c);
    match bus.send(d) {
        Ok(()) => match recv_corr(rx, c, Duration::from_secs(2)) {
            Some(env) => reply_result(&env.payload),
            None => VerbResult::ok(json!({ "timeout": true }), "(no reply within 2s)"),
        },
        Err(e) => VerbResult::err(
            json!({ "unrouted": true, "error": e.to_string(), "hint": "bind a placement creature first (e.g. `bind distributor <id>`)" }),
            format!("intent unrouted: {e} — bind a placement creature first (e.g. `bind distributor <id>`)."),
        ),
    }
}

/// How long the control plane waits for an AUTHORING reply. The templated author replies
/// synchronously (ms); a model-backed author (`agent-mind`) runs the call **off the drain thread**
/// and can take many seconds, so the boot recipe sizes this from the bound model's own timeout (plus
/// margin) when it binds one — see [`boot_organs_with`]. Without that, the live single-shot author
/// would hit a 5 s wall and report a misleading "nothing bound to AUTHORING" while the worker runs.
///
/// Process-scoped (a `OnceLock`, set once at boot from the chosen model config — NOT read from the
/// environment). v0.4.1 binds one author per node; per-realm model routing would key this by context.
static AUTHORING_BUDGET: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

fn authoring_reply_budget() -> Duration {
    AUTHORING_BUDGET.get().copied().unwrap_or(Duration::from_secs(5))
}

fn verb_author(ctx: &mut VerbCtx, request: &str, progress: &mut dyn FnMut(&str)) -> VerbResult {
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
    if request.len() > MAX_CONTROL_AUTHOR_REQUEST_BYTES {
        return author_err(format!(
            "author request is {} bytes, exceeds {} byte limit",
            request.len(),
            MAX_CONTROL_AUTHOR_REQUEST_BYTES
        ));
    }
    let c1 = ctx.next_corr();
    let payload = match serde_json::to_vec(&AuthoringRequest {
        request: request.into(),
        ..Default::default()
    }) {
        Ok(p) => p,
        Err(e) => return author_err(format!("author failed: {e}")),
    };
    let env = match request_reply(
        bus,
        rx,
        Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(c1),
        c1,
        authoring_reply_budget(),
    ) {
        Ok(Some(e)) => e,
        Ok(None) | Err(_) => {
            return author_err(
                "author failed: nothing bound to AUTHORING (running --minimal?)".into(),
            )
        }
    };
    let resp = match parse_role_reply::<AuthoringReply>(&env.payload, MAX_AUTHORING_REPLY_BYTES) {
        Ok(AuthoringReply::Authored(r)) => r,
        Ok(AuthoringReply::Failed(e)) => return author_err(format!("authoring failed: {e}")),
        Err(e) => return author_err(format!("author parse failed: {e}")),
    };
    progress(&format!(
        "authored crate `{}` ({} bytes of Rust); compiling… (first build warms the cache, ~tens of seconds)",
        resp.crate_name,
        resp.source.len()
    ));

    let c2 = ctx.next_corr();
    let op = BuildOp::Build {
        crate_name: resp.crate_name.clone(),
        crate_version: resp.crate_version.clone(),
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
        deps: resp.deps.clone(),
    };
    let build_payload = match serde_json::to_vec(&op) {
        Ok(p) => p,
        Err(e) => return author_err(format!("author failed: {e}")),
    };
    let env = match request_reply(
        bus,
        rx,
        Dispatch::to(Address::Role(Role::new(Role::BUILD)), build_payload)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(c2),
        c2,
        Duration::from_secs(360),
    ) {
        Ok(Some(e)) => e,
        Ok(None) => return author_err("author failed: nothing bound to BUILD".into()),
        Err(e) => return author_err(format!("author failed: BUILD route failed: {e}")),
    };
    let (manifest, artifact) = match parse_role_reply::<BuildReply>(
        &env.payload,
        MAX_ARTIFACT_ROLE_REPLY_BYTES,
    ) {
        Ok(BuildReply::Built { manifest, artifact }) => (manifest, artifact),
        Ok(BuildReply::Failed { kind, message, stderr, .. }) => {
            let human = if stderr.trim().is_empty() {
                format!("build failed ({kind:?}): {message}")
            } else {
                format!("build failed ({kind:?}): {message}\n--- cargo stderr ---\n{stderr}")
            };
            return VerbResult::err(
                json!({ "ok": false, "stage": "build", "kind": format!("{kind:?}"), "error": message, "stderr": stderr }),
                human,
            );
        }
        Err(e) => return author_err(format!("build parse failed: {e}")),
    };
    let crate_name = manifest.name.clone();
    match ctx.kernel.load(manifest, Artifact::Bytes(artifact)) {
        Ok(id) => VerbResult::ok(
            json!({ "ok": true, "stage": "loaded", "crate_name": crate_name, "creature_id": id.0 }),
            format!(
                "✓ authored → compiled → signed → admitted → hot-loaded as id={}. Try: send {} <text>",
                id.0, id.0
            ),
        ),
        Err(e) => VerbResult::err(
            json!({ "ok": false, "stage": "load", "error": e.to_string() }),
            format!("load rejected: {e}"),
        ),
    }
}

fn verb_author_critter(
    ctx: &mut VerbCtx,
    request: &str,
    progress: &mut dyn FnMut(&str),
) -> VerbResult {
    let Some(builder) = ctx.critter_builder else {
        return author_err(
            "author --critter: no critter builder bound (running --minimal?)".into(),
        );
    };
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
    // Nudge the templated agent toward its critter template (its matcher is keyword-based). The
    // nudged form is what the AUTHORING bindee decodes, so the size check covers it — the error
    // reports the *effective* operator-facing limit rather than a size the operator never sent.
    let nudged = format!("{request} critter");
    if nudged.len() > MAX_CONTROL_AUTHOR_REQUEST_BYTES {
        return author_err(format!(
            "author --critter request is {} bytes, exceeds {} byte limit",
            request.len(),
            MAX_CONTROL_AUTHOR_REQUEST_BYTES - (nudged.len() - request.len())
        ));
    }
    let c1 = ctx.next_corr();
    let payload =
        match serde_json::to_vec(&AuthoringRequest { request: nudged, ..Default::default() }) {
            Ok(p) => p,
            Err(e) => return author_err(format!("author failed: {e}")),
        };
    let env = match request_reply(
        bus,
        rx,
        Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(c1),
        c1,
        authoring_reply_budget(),
    ) {
        Ok(Some(e)) => e,
        Ok(None) | Err(_) => {
            return author_err(
                "author failed: nothing bound to AUTHORING (running --minimal?)".into(),
            )
        }
    };
    let resp = match parse_role_reply::<AuthoringReply>(&env.payload, MAX_AUTHORING_REPLY_BYTES) {
        Ok(AuthoringReply::Authored(r)) => r,
        Ok(AuthoringReply::Failed(e)) => return author_err(format!("authoring failed: {e}")),
        Err(e) => return author_err(format!("author parse failed: {e}")),
    };
    progress(&format!(
        "authored `{}` ({} bytes of Rhai); signing (no cargo)…",
        resp.crate_name,
        resp.source.len()
    ));

    let c2 = ctx.next_corr();
    let op = BuildCritterOp::Author {
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
    };
    let env = match request_reply(
        bus,
        rx,
        Dispatch::to(Address::Creature(builder), op.to_bytes())
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(c2),
        c2,
        Duration::from_secs(10),
    ) {
        Ok(Some(e)) => e,
        Ok(None) => return author_err("author failed: no reply from build-critter".into()),
        Err(e) => return author_err(format!("author failed: build-critter route failed: {e}")),
    };
    let (manifest, artifact) = match parse_role_reply::<BuildReply>(
        &env.payload,
        MAX_ARTIFACT_ROLE_REPLY_BYTES,
    ) {
        Ok(BuildReply::Built { manifest, artifact }) => (manifest, artifact),
        Ok(BuildReply::Failed { kind, message, .. }) => {
            return VerbResult::err(
                json!({ "ok": false, "stage": "build", "kind": format!("{kind:?}"), "error": message }),
                format!("critter build failed ({kind:?}): {message}"),
            )
        }
        Err(e) => return author_err(format!("build parse failed: {e}")),
    };
    let crate_name = manifest.name.clone();
    match ctx.kernel.load(manifest, Artifact::Bytes(artifact)) {
        Ok(id) => VerbResult::ok(
            json!({ "ok": true, "stage": "loaded", "crate_name": crate_name, "creature_id": id.0 }),
            format!(
                "✓ authored → signed → admitted → hot-loaded critter as id={} (no compiler). Try: send {} <text>",
                id.0, id.0
            ),
        ),
        Err(e) => VerbResult::err(
            json!({ "ok": false, "stage": "load", "error": e.to_string() }),
            format!("load rejected: {e}"),
        ),
    }
}

fn author_err(human: String) -> VerbResult {
    VerbResult::err(json!({ "ok": false, "error": human.clone() }), human)
}

// ---------------------------------------------------------------------------------------------
// Clustering: query the graph / join a peer via the TRANSPORT organ's control op.
// ---------------------------------------------------------------------------------------------

/// Parse a cluster peer spec `node-id@host:port#pubkey-hex` into a join verb.
fn parse_cluster_spec(spec: &str) -> Result<Verb, String> {
    let usage = "usage: cluster join <node-id@host:port#pubkey-hex>".to_string();
    let (node_id, rest) = spec.split_once('@').ok_or_else(|| usage.clone())?;
    let (addr, pubkey) = rest.split_once('#').ok_or_else(|| usage.clone())?;
    if node_id.is_empty() || addr.is_empty() || pubkey.is_empty() {
        return Err(usage);
    }
    Ok(Verb::ClusterJoin {
        node_id: node_id.to_string(),
        addr: addr.to_string(),
        pubkey: pubkey.to_string(),
    })
}

fn cluster_disabled() -> VerbResult {
    VerbResult::err(
        json!({ "error": "cluster-disabled", "hint": "start `alpha node` with --cluster-listen <addr> to enable clustering" }),
        "clustering is not enabled on this node (start with --cluster-listen <addr>)",
    )
}

fn verb_cluster(ctx: &mut VerbCtx) -> VerbResult {
    let Some(tid) = ctx.transport else { return cluster_disabled() };
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
    let c = ctx.next_corr();
    let d = Dispatch::to(Address::Creature(tid), TransportCtl::Members.to_bytes())
        .with_schema(CTL_SCHEMA)
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(c);
    match request_reply(bus, rx, d, c, Duration::from_secs(3)) {
        Ok(Some(env)) => match TransportCtlReply::parse(&env.payload) {
            Some(TransportCtlReply::Members { self_node, members }) => {
                let connected = members.iter().filter(|m| m.connected).count();
                let json = json!({
                    "self": self_node,
                    "connected": connected,
                    "members": members.iter().map(|m| json!({ "node_id": m.node_id, "addr": m.addr, "connected": m.connected })).collect::<Vec<_>>(),
                });
                let mut human = format!(
                    "cluster: {self_node} (this node) — {connected}/{} peer(s) connected",
                    members.len()
                );
                for m in &members {
                    human.push_str(&format!(
                        "\n  {} {:<22} {}",
                        if m.connected { "●" } else { "○" },
                        m.node_id,
                        m.addr
                    ));
                }
                VerbResult::ok(json, human)
            }
            _ => VerbResult::err(
                json!({ "error": "bad-cluster-reply" }),
                "cluster: unexpected reply from the transport",
            ),
        },
        Ok(None) => {
            VerbResult::ok(json!({ "timeout": true }), "(no reply from the transport within 3s)")
        }
        Err(e) => {
            VerbResult::err(json!({ "error": e.to_string() }), format!("cluster query failed: {e}"))
        }
    }
}

fn verb_cluster_join(ctx: &mut VerbCtx, node_id: &str, addr: &str, pubkey: &str) -> VerbResult {
    let Some(tid) = ctx.transport else { return cluster_disabled() };
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
    let c = ctx.next_corr();
    let op = TransportCtl::Connect {
        node_id: node_id.to_string(),
        pubkey_hex: pubkey.to_string(),
        addr: addr.to_string(),
    };
    let d = Dispatch::to(Address::Creature(tid), op.to_bytes())
        .with_schema(CTL_SCHEMA)
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(c);
    match request_reply(bus, rx, d, c, Duration::from_secs(3)) {
        // Decode the reply: a member-table-cap refusal comes back as `Rejected`, not a silent
        // success. Reporting `ok` on a `Rejected` would tell the operator the node joined when it did
        // not (mirrors `verb_cluster`, which also decodes the typed reply).
        Ok(Some(env)) => match TransportCtlReply::parse(&env.payload) {
            Some(TransportCtlReply::Connecting { node_id }) => VerbResult::ok(
                json!({ "ok": true, "joined": node_id, "addr": addr }),
                format!("admitted + dialing `{node_id}` ({addr}); gossip will spread it across the mesh. Run `cluster` to watch it converge."),
            ),
            Some(TransportCtlReply::Rejected { reason }) => VerbResult::err(
                json!({ "ok": false, "error": reason }),
                format!("cluster join rejected: {reason}"),
            ),
            _ => VerbResult::err(
                json!({ "error": "bad-cluster-reply" }),
                "cluster join: unexpected reply from the transport",
            ),
        },
        Ok(None) => VerbResult::ok(json!({ "timeout": true }), "(no ack from the transport within 3s)"),
        Err(e) => VerbResult::err(
            json!({ "error": e.to_string() }),
            format!("cluster join failed: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Shared JSON builders (used by run_verb AND the API's fast read paths)
// ---------------------------------------------------------------------------------------------

/// The loaded roster as a JSON array (sorted by id): `[{id,name,backend}]`.
pub fn creatures_json(kernel: &Kernel) -> Value {
    let mut roster = kernel.roster();
    roster.sort_by_key(|(id, _, _)| id.0);
    Value::Array(
        roster
            .into_iter()
            .map(|(id, name, backend)| json!({ "id": id.0, "name": name, "backend": backend_str(backend) }))
            .collect(),
    )
}

/// Node status as JSON: loaded count, bound roles, journal length, the allow-AI gate + AI status.
pub fn status_json(kernel: &Kernel, ai: &AiControl) -> Value {
    let mut roles = kernel.router().bound_roles();
    roles.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
    let roles: Vec<Value> =
        roles.into_iter().map(|(r, id)| json!({ "role": r.0, "id": id.0 })).collect();
    json!({
        "loaded": kernel.loaded_count(),
        "roles": roles,
        "journal_entries": kernel.router().journal_snapshot().len(),
        "ai_allowed": ai.allowed(),
        "ai_status": ai.status_json(),
    })
}

/// The last `limit` journal entries as `(total, [{seq,stamp,from,to}])`.
pub fn journal_json(kernel: &Kernel, limit: usize) -> (usize, Vec<Value>) {
    let j = kernel.router().journal_snapshot();
    let total = j.len();
    let start = total.saturating_sub(limit);
    let entries = j[start..]
        .iter()
        .map(|e| json!({ "seq": e.seq, "stamp": e.stamp, "from": format!("{:?}", e.from), "to": format!("{:?}", e.to) }))
        .collect();
    (total, entries)
}

fn render_list(creatures: &Value) -> String {
    let arr = creatures.as_array().cloned().unwrap_or_default();
    if arr.is_empty() {
        return "(no creatures loaded)".to_string();
    }
    let mut s = String::new();
    for c in arr {
        let id = c.get("id").and_then(Value::as_u64).unwrap_or(0);
        let name = c.get("name").and_then(Value::as_str).unwrap_or("");
        let backend = c.get("backend").and_then(Value::as_str).unwrap_or("");
        s.push_str(&format!("  id={id:<3} {name:<24} [{backend}]\n"));
    }
    s.truncate(s.trim_end().len());
    s
}

fn render_status(j: &Value) -> String {
    let mut s =
        format!("loaded creatures: {}\n", j.get("loaded").and_then(Value::as_u64).unwrap_or(0));
    match j.get("roles").and_then(Value::as_array) {
        Some(roles) if !roles.is_empty() => {
            for r in roles {
                let role = r.get("role").and_then(Value::as_str).unwrap_or("");
                let id = r.get("id").and_then(Value::as_u64).unwrap_or(0);
                s.push_str(&format!("  role {role:<16} → id={id}\n"));
            }
        }
        _ => s.push_str("bound roles: (none)\n"),
    }
    s.push_str(&format!(
        "journal entries: {}\n",
        j.get("journal_entries").and_then(Value::as_u64).unwrap_or(0)
    ));
    let allowed = j.get("ai_allowed").and_then(Value::as_bool).unwrap_or(false);
    s.push_str(&format!("allow-ai: {}", if allowed { "ON" } else { "OFF" }));
    if let Some(st) = j.get("ai_status") {
        if st.get("working").and_then(Value::as_bool).unwrap_or(false) {
            let act = st.get("activity").and_then(Value::as_str).unwrap_or("");
            let msg = st.get("message").and_then(Value::as_str).unwrap_or("");
            s.push_str(&format!("  [ai {act}: {msg}]"));
        }
    }
    s
}

fn render_journal(total: usize, entries: &[Value]) -> String {
    let mut s = format!("journal (last {} of {} entries):\n", entries.len(), total);
    for e in entries {
        let seq = e.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let stamp = e.get("stamp").and_then(Value::as_u64).unwrap_or(0);
        let from = e.get("from").and_then(Value::as_str).unwrap_or("");
        let to = e.get("to").and_then(Value::as_str).unwrap_or("");
        s.push_str(&format!("  seq={seq:<4} stamp={stamp:<5} {from} → {to}\n"));
    }
    s.truncate(s.trim_end().len());
    s
}

pub fn backend_str(b: Backend) -> &'static str {
    match b {
        Backend::Daemon => "daemon",
        Backend::Beast => "beast",
        Backend::Critter => "critter",
    }
}

// ---------------------------------------------------------------------------------------------
// Request/reply helpers (shared by run_verb and any front-end that needs a raw round-trip)
// ---------------------------------------------------------------------------------------------

/// Send a dispatch and wait (bounded) for the reply correlated by `corr`, skipping stray
/// proprio/fitness/late envelopes on the probe inbox.
pub fn request_reply(
    bus: &BusHandle,
    rx: &InboxReceiver,
    d: Dispatch,
    corr: u64,
    budget: Duration,
) -> Result<Option<Envelope>, RouteError> {
    bus.send(d)?;
    Ok(recv_corr(rx, corr, budget))
}

/// Wait (bounded) for the reply correlated by `corr`. A late reply from an earlier command must never
/// be misattributed, so every reply read is corr-filtered.
pub fn recv_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            _ => continue,
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Boot recipe (self-hosting the substrate's own organs) — shared by main.rs and the API host
// ---------------------------------------------------------------------------------------------

/// Which creature binds `Role::AUTHORING`, chosen by the composition root (the operator surface) and
/// passed into [`boot_organs_with`] as **data** — the core never reads the environment to decide.
/// This is the literal "ASI is the fabric, not the model": the model is injected here.
pub enum Authoring {
    /// The deterministic `agent-templated` reference (the default; byte-identical to v0.4.0).
    Templated,
    /// A real model-backed author (`agent-mind`) on the given model config. Requires building with
    /// `--features openai`; without that feature, binding this returns an error.
    Model(mind::ModelConfig),
}

impl Authoring {
    /// A short human label for boot banners ("agent-templated" / "agent-mind (model …)").
    pub fn describe(&self) -> String {
        match self {
            Authoring::Templated => "agent-templated".to_string(),
            Authoring::Model(cfg) => format!("agent-mind (model {})", cfg.model),
        }
    }
}

/// Self-host the substrate's own organs onto their Roles, binding the deterministic `agent-templated`
/// author. Returns the `build-critter` organ's id: `Role::BUILD` is single-binding (held by
/// build-cargo for daemons), so `author --critter` addresses the no-cargo critter builder by id.
pub fn boot_organs(kernel: &Kernel) -> Result<CreatureId, String> {
    boot_organs_with_monitor(kernel, true)
}

/// Like [`boot_organs`] but with control over the stdout monitor (omitted when stdout must stay
/// machine-readable, e.g. `--json --exec`). Binds the deterministic `agent-templated` author.
pub fn boot_organs_with_monitor(
    kernel: &Kernel,
    attach_stdout_monitor: bool,
) -> Result<CreatureId, String> {
    boot_organs_with(kernel, attach_stdout_monitor, Authoring::Templated)
}

/// The full boot recipe: self-host the substrate's own organs onto their Roles, binding the
/// `authoring` author the composition root chose (see [`Authoring`]). The default
/// [`Authoring::Templated`] keeps the boot byte-identical to v0.4.0; [`Authoring::Model`] binds the
/// real model-backed `agent-mind` (in-process only — never a `.so`) onto the same `Role::AUTHORING`
/// socket — the literal "ASI is the fabric, not the model." swap.
pub fn boot_organs_with(
    kernel: &Kernel,
    attach_stdout_monitor: bool,
    authoring: Authoring,
) -> Result<CreatureId, String> {
    let abode = Ed25519KeyMaterial::from_seed([7u8; 32]).map_err(|e| e.to_string())?;
    let author = abode.public_hex().to_string();

    // Bind the AUTHORING organ chosen by the composition root (data, not ambient state).
    let agent_id = bind_authoring_organ(kernel, &authoring)?;
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    let critter_build_id = kernel
        .load_instance(
            boot_manifest("build-critter"),
            Box::new(BuildCritter::new(abode.clone(), author.clone())),
        )
        .map_err(|e| format!("build-critter: {e}"))?;

    // The SDK crates (forge/aether/sigil) an authored creature path-deps against live under
    // `cosmos/`, so that — not the workspace root — is the build creature's path-dep
    // base. The shared build cache still lives under the true workspace root's `target/`.
    let mut cfg = BuildConfig::with_workspace_root(workspace_root().join("cosmos"), abode, author);
    cfg.target_dir = workspace_root().join("target").join("gawd-build-cache");
    cfg.sandbox = Sandbox::None;
    cfg.cargo_timeout = Duration::from_secs(300);
    let build_id = kernel
        .load_instance(boot_manifest("build-cargo"), Box::new(BuildCargo::new(cfg)))
        .map_err(|e| format!("build: {e}"))?;
    kernel.bind_role(Role::new(Role::BUILD), build_id);

    let reg_id = kernel
        .load_instance(boot_manifest("registry-mem"), Box::new(RegistryMem::new()))
        .map_err(|e| format!("registry: {e}"))?;
    kernel.bind_role(Role::new(Role::REGISTRY), reg_id);

    if attach_stdout_monitor {
        let mon_id = kernel
            .load_instance(boot_manifest("monitor"), Box::new(Monitor::new("node")))
            .map_err(|e| format!("monitor: {e}"))?;
        kernel.subscribe(Topic::new(Topic::PROPRIOCEPTION), mon_id);
        kernel.subscribe(Topic::new(Topic::FITNESS), mon_id);
    }
    Ok(critter_build_id)
}

pub fn boot_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

/// Load the AUTHORING organ chosen by the composition root and return its id.
/// [`Authoring::Templated`] binds the deterministic reference; [`Authoring::Model`] binds the real
/// model-backed `agent-mind` (in-process only — never a `.so`) and requires `--features openai`.
fn bind_authoring_organ(kernel: &Kernel, authoring: &Authoring) -> Result<CreatureId, String> {
    match authoring {
        Authoring::Templated => kernel
            .load_instance(boot_manifest("agent-templated"), Box::new(AgentTemplated::new()))
            .map_err(|e| format!("agent: {e}")),
        Authoring::Model(cfg) => bind_model_author(kernel, cfg),
    }
}

/// Bind the model-backed `agent-mind` author on the given model config (feature `openai`). Sizes the
/// control plane's AUTHORING reply budget from the model's own timeout (+margin) so the live
/// single-shot author doesn't hit a short wall while the off-drain worker is still running.
#[cfg(feature = "openai")]
fn bind_model_author(kernel: &Kernel, cfg: &mind::ModelConfig) -> Result<CreatureId, String> {
    let _ = AUTHORING_BUDGET.set(cfg.timeout.saturating_add(Duration::from_secs(10)));
    let model = std::sync::Arc::new(mind::OpenAiModel::new(cfg.clone()));
    kernel
        .load_instance(boot_manifest("agent-mind"), Box::new(agent_mind::AgentMind::new(model)))
        .map_err(|e| format!("agent-mind: {e}"))
}

/// Without `--features openai` there is no model HTTP path linked, so a model-backed author cannot be
/// bound — refuse rather than silently fall back, so a misconfigured deployment is visible.
#[cfg(not(feature = "openai"))]
fn bind_model_author(_kernel: &Kernel, _cfg: &mind::ModelConfig) -> Result<CreatureId, String> {
    Err("a model-backed author requires building Alpha with `--features openai`".to_string())
}

/// Load the [`ControlCore`] translator and bind it to [`Role::CONTROL`], so the node
/// answers control over the bus: a surface ships a [`Verb`] envelope (`control_verb`) to
/// `Role::CONTROL` and reads a [`VerbResult`] envelope (`control_result`) back. Returns its
/// [`CreatureId`] — a remote surface reaching this node addresses `Address::Node(this_node, that_id)`.
/// Loading the control organ is itself a privileged act; a node that wants no control
/// plane simply never calls this. `ai` is the shared allow-AI gate (the REPL and the surfaces hold
/// the same `Arc`); `critter_builder` / `transport` mirror the REPL's [`VerbCtx`] wiring.
pub fn boot_control(
    kernel: &std::sync::Arc<Kernel>,
    ai: &std::sync::Arc<AiControl>,
    critter_builder: Option<CreatureId>,
    transport: Option<CreatureId>,
) -> Result<CreatureId, String> {
    let id = kernel
        .load_instance(
            boot_manifest("omni"),
            Box::new(ControlCore::new(kernel, ai.clone(), critter_builder, transport)),
        )
        .map_err(|e| format!("omni: {e}"))?;
    kernel.bind_role(Role::new(Role::CONTROL), id);
    Ok(id)
}

/// The true workspace root — the directory holding the `Cargo.toml` with the `[workspace]` table.
///
/// Layout-robust by design: `omni` lives under `cosmos/`, so the root is more than one
/// parent up, and walking to the workspace manifest means no future relocation can silently return
/// the wrong directory. The build creature resolves authored-creature path-deps against
/// `<root>/cosmos` and places its shared cache under `<root>/target`, so this must be exact.
pub fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for dir in manifest_dir.ancestors() {
        if cargo_manifest_has_workspace_table(dir) {
            return dir.to_path_buf();
        }
    }
    // Fallback (e.g. a packaged single-crate build with no workspace manifest): two parents up,
    // which is `cosmos/omni` → root under the workspace layout.
    manifest_dir.parent().and_then(|p| p.parent()).map(PathBuf::from).unwrap_or(manifest_dir)
}

fn cargo_manifest_has_workspace_table(dir: &Path) -> bool {
    let path = dir.join("Cargo.toml");
    let Ok(metadata) = std::fs::metadata(&path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > MAX_WORKSPACE_MANIFEST_BYTES {
        return false;
    }
    let Ok(file) = File::open(&path) else {
        return false;
    };
    let mut reader = file.take(MAX_WORKSPACE_MANIFEST_BYTES.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len().min(1024 * 1024) as usize);
    if reader.read_to_end(&mut bytes).is_err()
        || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_WORKSPACE_MANIFEST_BYTES)
    {
        return false;
    }
    String::from_utf8(bytes)
        .map(|text| text.lines().any(|line| line.trim() == "[workspace]"))
        .unwrap_or(false)
}

/// Open a fresh probe endpoint with default capabilities (the unrestricted `calls` gate a control
/// front-end needs to drive any role or creature).
pub fn open_probe(kernel: &Kernel) -> (CreatureId, BusHandle, InboxReceiver) {
    kernel.open_endpoint(Capabilities::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_control_result_accepts_bounded_result() {
        let original = VerbResult::ok(json!({ "ok": true }), "ready");
        let payload = serde_json::to_vec(&original).unwrap();

        let parsed = parse_control_result(&payload).unwrap();

        assert!(parsed.ok);
        assert_eq!(parsed.json, json!({ "ok": true }));
        assert_eq!(parsed.human, "ready");
    }

    #[test]
    fn parse_fetch_load_grammar_covers_local_realm_and_cross_node_forms() {
        let hash = "a".repeat(64);

        // local
        match parse_verb(&format!("registry fetch-load {hash}")).unwrap().unwrap() {
            Verb::FetchLoad { artifact_hash, node, registry_id, realm, chunk_size } => {
                assert_eq!(artifact_hash, hash);
                assert_eq!(node, None);
                assert_eq!(registry_id, None);
                assert_eq!(realm, None);
                assert_eq!(chunk_size, None);
            }
            other => panic!("expected FetchLoad, got {other:?}"),
        }

        // local, realm-scoped
        match parse_verb(&format!("registry fetch-load {hash} crew")).unwrap().unwrap() {
            Verb::FetchLoad { node, registry_id, realm, .. } => {
                assert_eq!(node, None);
                assert_eq!(registry_id, None);
                assert_eq!(realm, Some(RealmId::new("crew")));
            }
            other => panic!("expected FetchLoad, got {other:?}"),
        }

        // cross-node
        match parse_verb(&format!("registry fetch-load {hash} node-b 7")).unwrap().unwrap() {
            Verb::FetchLoad { node, registry_id, realm, .. } => {
                assert_eq!(node, Some("node-b".to_string()));
                assert_eq!(registry_id, Some(7));
                assert_eq!(realm, None);
            }
            other => panic!("expected FetchLoad, got {other:?}"),
        }

        // cross-node, realm-scoped
        match parse_verb(&format!("registry fetch-load {hash} node-b 7 crew")).unwrap().unwrap() {
            Verb::FetchLoad { node, registry_id, realm, .. } => {
                assert_eq!(node, Some("node-b".to_string()));
                assert_eq!(registry_id, Some(7));
                assert_eq!(realm, Some(RealmId::new("crew")));
            }
            other => panic!("expected FetchLoad, got {other:?}"),
        }

        // a non-numeric registry-id is a usage error, not a silent mis-parse
        assert!(parse_verb(&format!("registry fetch-load {hash} node-b not-a-number")).is_err());

        // FetchLoad loads code → gated, and runs on the worker (needs a probe).
        let v = Verb::FetchLoad {
            artifact_hash: hash,
            node: None,
            registry_id: None,
            realm: None,
            chunk_size: None,
        };
        assert!(v.is_gated(), "fetch-load loads code, so it is gated by allow-AI");
    }

    #[test]
    fn control_verb_payload_accepts_bounded_verb() {
        let payload = control_verb_payload(&Verb::Status).unwrap();

        let parsed: Verb = serde_json::from_slice(&payload).unwrap();
        assert!(matches!(parsed, Verb::Status));
    }

    #[test]
    fn control_verb_payload_rejects_oversized_verb_before_surface_emit() {
        let err =
            control_verb_payload(&Verb::Author { request: "x".repeat(MAX_CONTROL_VERB_BYTES) })
                .unwrap_err();

        assert!(!err.ok);
        assert_eq!(err.json["error"].as_str(), Some("control-verb-too-large"));
        assert!(err.json["bytes"].as_u64().unwrap() > MAX_CONTROL_VERB_BYTES as u64);
        assert_eq!(err.json["limit"].as_u64(), Some(MAX_CONTROL_VERB_BYTES as u64));
    }

    #[test]
    fn ai_status_text_is_sanitized_and_bounded_at_shared_state() {
        let ai = AiControl::new(false);
        ai.set_status(
            true,
            "read\n\x1b[2J".to_string(),
            format!("{}\rhidden", "m".repeat(MAX_AI_STATUS_TEXT_CHARS + 16)),
        );

        let status = ai.status();
        assert!(status.working);
        assert_eq!(status.activity, "read[2J");
        assert_eq!(status.message.len(), MAX_AI_STATUS_TEXT_CHARS);
        assert!(status.message.chars().all(|c| !c.is_control()));
    }

    #[test]
    fn control_role_names_are_bounded_ascii_tokens() {
        assert!(validate_control_role_name("distributor").is_ok());
        assert!(validate_control_role_name("realm-gateway.v2_test").is_ok());

        assert_eq!(validate_control_role_name("").unwrap_err(), "role name must not be empty");
        assert_eq!(
            validate_control_role_name(&"r".repeat(MAX_CONTROL_ROLE_NAME_BYTES + 1)).unwrap_err(),
            "role name exceeds control byte limit"
        );
        assert_eq!(
            validate_control_role_name("bad role").unwrap_err(),
            "role name must be ASCII [A-Za-z0-9._-]"
        );
        assert_eq!(
            validate_control_role_name("bad\nrole").unwrap_err(),
            "role name must be ASCII [A-Za-z0-9._-]"
        );
    }

    #[test]
    fn control_result_payload_replaces_oversized_result_with_small_error() {
        let original =
            VerbResult::ok(json!({ "blob": "x".repeat(MAX_CONTROL_RESULT_BYTES) }), "huge result");

        let payload = control_result_payload(original);

        assert!(
            payload.len() <= MAX_CONTROL_RESULT_BYTES,
            "control_result emission must stay under the surface-side decode cap"
        );
        let parsed = parse_control_result(&payload).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.json["error"].as_str(), Some("control-result-too-large"));
        assert!(parsed.json["bytes"].as_u64().unwrap() > MAX_CONTROL_RESULT_BYTES as u64);
    }

    #[test]
    fn parse_control_result_rejects_oversized_payload_before_json_decode() {
        let payload = vec![b'{'; MAX_CONTROL_RESULT_BYTES + 1];

        let err = parse_control_result(&payload).unwrap_err();

        assert_eq!(
            err,
            ControlResultDecodeError::TooLarge {
                len: MAX_CONTROL_RESULT_BYTES + 1,
                limit: MAX_CONTROL_RESULT_BYTES,
            }
        );
        let res = control_result_decode_failure(err);
        assert!(!res.ok);
        assert_eq!(res.json["error"].as_str(), Some("control-result-too-large"));
    }

    #[test]
    fn parse_control_result_reports_malformed_json() {
        let err = parse_control_result(b"{not json").unwrap_err();

        assert!(matches!(err, ControlResultDecodeError::Json(_)));
        let res = control_result_decode_failure(err);
        assert!(!res.ok);
        assert_eq!(res.json["error"].as_str(), Some("bad-control-result"));
    }

    #[test]
    fn parse_role_reply_rejects_payloads_over_its_domain_limit() {
        let payload = serde_json::to_vec(&RegistryReply::NotFound).unwrap();

        let parsed = parse_role_reply::<RegistryReply>(&payload, payload.len()).unwrap();
        assert!(matches!(parsed, RegistryReply::NotFound));

        let err = parse_role_reply::<RegistryReply>(&payload, payload.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            RoleReplyDecodeError::TooLarge {
                len,
                limit
            } if len == payload.len() && limit == payload.len() - 1
        ));
    }

    #[test]
    fn workspace_manifest_probe_is_bounded() {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "alpha-omni-workspace-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let manifest = root.join("Cargo.toml");
        std::fs::write(&manifest, "[workspace]\nmembers = []\n").unwrap();

        assert!(cargo_manifest_has_workspace_table(&root));

        std::fs::File::create(&manifest)
            .unwrap()
            .set_len(MAX_WORKSPACE_MANIFEST_BYTES + 1)
            .unwrap();
        assert!(!cargo_manifest_has_workspace_table(&root));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // deliberate compile-time cap invariants
    fn registry_fetch_and_list_use_metadata_reply_cap() {
        assert_eq!(
            MAX_REGISTRY_FETCH_REPLY_BYTES, MAX_REGISTRY_METADATA_REPLY_BYTES,
            "metadata fetch should share the byte-light metadata cap"
        );
        assert!(
            MAX_REGISTRY_FETCH_REPLY_BYTES < MAX_ARTIFACT_ROLE_REPLY_BYTES,
            "metadata fetch should not inherit the artifact-sized role reply cap"
        );
        let list_payload =
            serde_json::to_vec(&RegistryReply::Metadata { entries: Vec::new() }).unwrap();

        let parsed =
            parse_role_reply::<RegistryReply>(&list_payload, MAX_REGISTRY_METADATA_REPLY_BYTES)
                .unwrap();

        assert!(matches!(parsed, RegistryReply::Metadata { entries } if entries.is_empty()));

        let fetch_payload = serde_json::to_vec(&RegistryReply::FetchedMetadata {
            entry: CatalogEntry {
                artifact_hash: "h".into(),
                realm: RealmId::local(),
                manifest: Manifest::new("c", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                reputation: None,
                quarantine: None,
            },
            artifact_len: 3,
        })
        .unwrap();
        let parsed =
            parse_role_reply::<RegistryReply>(&fetch_payload, MAX_REGISTRY_FETCH_REPLY_BYTES)
                .unwrap();
        assert!(
            matches!(parsed, RegistryReply::FetchedMetadata { artifact_len: 3, .. }),
            "metadata fetch reply decodes under the metadata cap"
        );
    }
}
