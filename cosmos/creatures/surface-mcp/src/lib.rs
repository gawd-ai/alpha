//! surface-mcp — a **loadable** MCP (Model Context Protocol) control surface.
//!
//! The MCP host (Claude/Codex) spawns a headless Alpha Sanctum — the *MCP control-hub* (`alpha mcp`)
//! — and speaks newline-delimited JSON-RPC 2.0 to it on stdio. This creature **owns that stdio** (no
//! separate shim process), terminates the MCP protocol, and turns each tool call into a [`Verb`]
//! envelope on GAWD's own bus, routed to a [`ControlTarget`] (the hub's own `Role::CONTROL`, or a
//! peer node's over the mesh). The [`VerbResult`] rides back and is wrapped in the MCP content
//! envelope. The consumer↔MCP edge stays the world's standard; the MCP-server↔node hop is GAWD
//! protocol — no REST side-channel.
//!
//! Being a creature, it is composable like any other surface: a node loads it only when it wants an
//! MCP face, and can unload it when done. It holds **no kernel** — only its bus identity, used to
//! emit control verbs (`reply_to` itself, corr-matched in [`handle`](SurfaceMcp)).

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, Outcome, RealmId,
};
use gawdfn::{
    DeploymentQueryV1, DeploymentReceiptV1, DeploymentRequestV1, EventQueryV1, JobControlV1,
    JobGetV1, JobSubmitV1, ResolutionReceiptV1, ResolveRequestV1, SignedRecordV1,
    UndeployRequestV1,
};
use omni::{ControlTarget, Verb, VerbResult, CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA};
use serde::de::DeserializeOwned;

use serde_json::{json, Value};

const SERVER_NAME: &str = "alpha-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2025-11-25";
/// Maximum bytes of a client-supplied MCP protocolVersion reflected in initialize.
const MAX_PROTOCOL_VERSION_BYTES: usize = 64;
/// Bound one JSON-RPC input line. MCP requests are small JSON objects; a 1 MiB line is roomy for
/// authoring prompts and prevents one hostile stdio peer from growing this process without bound.
const MAX_JSON_RPC_LINE_BYTES: usize = 1024 * 1024;
/// Maximum bytes copied into an error token preview (unknown method/tool/parameter names).
const MAX_ERROR_TOKEN_BYTES: usize = 256;
/// Maximum bytes for MCP text-like payload arguments. The whole JSON-RPC line is capped at 1 MiB;
/// this per-field guard rejects oversized strings before `Verb` construction.
const MAX_TEXT_ARG_BYTES: usize = omni::MAX_CONTROL_VERB_BYTES;
/// Maximum bytes for an authoring request — the AUTHORING contract's own field cap, so the
/// advertised tool schema promises exactly what the authoring bindees downstream accept.
const MAX_AUTHOR_ARG_BYTES: usize = omni::MAX_CONTROL_AUTHOR_REQUEST_BYTES;
/// Maximum bytes for node-local path strings accepted by MCP tools.
const MAX_PATH_ARG_BYTES: usize = 4096;
/// Maximum bytes for artifact hashes accepted by MCP tools.
const MAX_HASH_ARG_BYTES: usize = 128;
/// Maximum bytes for Realm id strings accepted by MCP tools.
const MAX_REALM_ARG_BYTES: usize = 256;
/// Maximum bytes for peer node ids accepted by MCP tools.
const MAX_NODE_ARG_BYTES: usize = 256;
/// Maximum bytes for peer dial addresses accepted by MCP tools.
const MAX_ADDR_ARG_BYTES: usize = 512;
/// Maximum bytes for peer pubkeys accepted by MCP tools.
const MAX_PUBKEY_ARG_BYTES: usize = 128;
/// Maximum bytes for AI status text before the shared control layer sanitizes/truncates it further.
const MAX_AI_STATUS_ARG_BYTES: usize = 4096;
/// Bound in-flight control requests parked by the MCP bridge. The stdio loop is synchronous, but a
/// bounded table keeps the surface robust if that bridge grows concurrent request handling later or
/// stale replies accumulate under unusual host behavior.
const MAX_PENDING_CONTROL_REQUESTS: usize = 256;

/// Generous ceiling for a cold `author` (a real `cargo build`); everything else replies in ms.
const AUTHOR_TIMEOUT: Duration = Duration::from_secs(400);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared between the stdio loop and the creature's `handle` (which delivers control replies).
struct SurfaceState {
    bus: Mutex<Option<Arc<dyn Bus>>>,
    me: Mutex<Option<CreatureId>>,
    corr: AtomicU64,
    pending: Mutex<HashMap<u64, PendingReply>>,
    target: ControlTarget,
    stop: AtomicBool,
}

struct PendingReply {
    capability: String,
    tx: Sender<VerbResult>,
}

impl SurfaceState {
    fn me(&self) -> Option<CreatureId> {
        *self.me.lock().unwrap()
    }
    fn bus(&self) -> Option<Arc<dyn Bus>> {
        self.bus.lock().unwrap().clone()
    }
    fn register_pending(
        &self,
        corr: u64,
        capability: String,
        tx: Sender<VerbResult>,
    ) -> Result<(), VerbResult> {
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING_CONTROL_REQUESTS {
            return Err(surface_busy(pending.len()));
        }
        pending.insert(corr, PendingReply { capability, tx });
        Ok(())
    }
    fn take_pending(&self, corr: u64, capability: Option<&str>) -> Option<Sender<VerbResult>> {
        let mut pending = self.pending.lock().unwrap();
        let matches = pending
            .get(&corr)
            .is_some_and(|expected| capability == Some(expected.capability.as_str()));
        matches.then(|| pending.remove(&corr).expect("matched pending reply").tx)
    }
    fn remove_pending(&self, corr: u64) {
        self.pending.lock().unwrap().remove(&corr);
    }
}

/// The MCP control surface creature.
pub struct SurfaceMcp {
    state: Arc<SurfaceState>,
    /// Set true when the stdio loop exits (the MCP host closed stdin). The hub binary watches this
    /// to shut the node down cleanly on EOF instead of lingering until killed.
    done: Arc<AtomicBool>,
    stdio_thread: Option<JoinHandle<()>>,
}

impl SurfaceMcp {
    /// Construct over a control target — `ControlTarget::Local` for the hub's own node, or
    /// `ControlTarget::Node { .. }` to front a peer node's control plane over the mesh.
    pub fn new(target: ControlTarget) -> Self {
        Self {
            state: Arc::new(SurfaceState {
                bus: Mutex::new(None),
                me: Mutex::new(None),
                corr: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                target,
                stop: AtomicBool::new(false),
            }),
            done: Arc::new(AtomicBool::new(false)),
            stdio_thread: None,
        }
    }

    /// A flag the stdio loop sets when the MCP host closes stdin (EOF). The hub binary watches it to
    /// shut the node down cleanly. Grab it before loading the creature.
    pub fn done_flag(&self) -> Arc<AtomicBool> {
        self.done.clone()
    }
}

impl Creature for SurfaceMcp {
    fn bind(&mut self, ctx: CreatureCtx) {
        *self.state.bus.lock().unwrap() = Some(ctx.bus);
        *self.state.me.lock().unwrap() = Some(ctx.me);
        let state = self.state.clone();
        let done = self.done.clone();
        match std::thread::Builder::new().name("surface-mcp-stdio".into()).spawn(move || {
            run_stdio(state);
            done.store(true, Ordering::Relaxed);
        }) {
            Ok(h) => self.stdio_thread = Some(h),
            Err(e) => eprintln!("surface-mcp: failed to spawn the stdio thread: {e}"),
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Only control replies arrive here (this creature subscribes to nothing). Wake the stdio
        // loop's request waiting on this corr.
        if env.header.schema == CONTROL_RESULT_SCHEMA {
            if let Some(corr) = env.header.corr {
                if let Some(tx) = self.state.take_pending(corr, env.header.commitment.as_deref()) {
                    let res = omni::parse_control_result(&env.payload)
                        .unwrap_or_else(omni::control_result_decode_failure);
                    let _ = tx.send(res);
                }
            }
        }
        Outcome::none()
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // Signal the stdio loop to stop after its current line. A blocking `read_line` cannot be
        // interrupted portably, so the thread exits on the next line or on EOF (the host closing
        // stdin). Join only if it already reached that point; otherwise detach the handle so
        // shutdown cannot hang the node's teardown path waiting on open stdin.
        self.state.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.stdio_thread.take() {
            join_stdio_thread_if_finished(h);
        }
    }
}

fn join_stdio_thread_if_finished(h: JoinHandle<()>) -> bool {
    if h.is_finished() {
        let _ = h.join();
        true
    } else {
        eprintln!(
            "surface-mcp: stdio thread is still blocked during shutdown; detaching until stdin closes"
        );
        false
    }
}

// ---- the stdio JSON-RPC loop -------------------------------------------------------------------

fn run_stdio(state: Arc<SurfaceState>) {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut reader = stdin.lock();
    loop {
        if state.stop.load(Ordering::Relaxed) {
            break;
        }
        let line = match read_line_capped(&mut reader, MAX_JSON_RPC_LINE_BYTES) {
            Ok(RpcLine::Eof) => break, // EOF — the host closed stdin
            Ok(RpcLine::Line(line)) => line,
            Ok(RpcLine::TooLong) => {
                write_msg(
                    &mut stdout,
                    &error(
                        Value::Null,
                        -32700,
                        &format!(
                            "Parse error: JSON-RPC line exceeds {MAX_JSON_RPC_LINE_BYTES} bytes"
                        ),
                    ),
                );
                continue;
            }
            Err(e) => {
                eprintln!("surface-mcp: stdin read error: {e}");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                write_msg(&mut stdout, &error(Value::Null, -32700, &format!("Parse error: {e}")));
                continue;
            }
        };
        if !request.is_object() {
            write_msg(
                &mut stdout,
                &error(Value::Null, -32600, "Invalid Request: expected a JSON-RPC object"),
            );
            continue;
        }
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        // Notifications (no id) get no response.
        let Some(id) = id else { continue };

        let response = match method {
            "initialize" => {
                let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
                result(id, initialize_result(&params))
            }
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({ "tools": tool_list() })),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
                result(id, call_tool(&state, &params))
            }
            other => error(id, -32601, &format!("Method not found: {}", preview_token(other))),
        };
        write_msg(&mut stdout, &response);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RpcLine {
    Line(String),
    Eof,
    TooLong,
}

fn read_line_capped<R: BufRead>(reader: &mut R, max: usize) -> std::io::Result<RpcLine> {
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if out.is_empty() { Ok(RpcLine::Eof) } else { bytes_to_line(out) };
        }

        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map_or(available.len(), |i| i + 1);
        let over_limit = out.len().saturating_add(take) > max;
        if over_limit {
            reader.consume(take);
            if newline.is_none() {
                drain_line(reader)?;
            }
            return Ok(RpcLine::TooLong);
        }

        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return bytes_to_line(out);
        }
    }
}

fn drain_line<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map_or(available.len(), |i| i + 1);
        reader.consume(take);
        if newline.is_some() {
            return Ok(());
        }
    }
}

fn bytes_to_line(bytes: Vec<u8>) -> std::io::Result<RpcLine> {
    String::from_utf8(bytes)
        .map(RpcLine::Line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn initialize_result(params: &Value) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= MAX_PROTOCOL_VERSION_BYTES)
        .unwrap_or(PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
        "instructions":
            "alpha-mcp drives a running Alpha Sanctum over GAWD's own bus: each tool call is \
             a Verb envelope routed to Role::CONTROL, and the result rides back. The MCP \
             server is itself a headless Sanctum (a control-hub node). DEV posture: the bundled dev \
             admission policy admits everything. A local non-clustered hub uses a stub bus signer; a \
             remote hub and clustered target use their authenticated ed25519 node identities. Neither \
             posture is a hardened deployment. Mutating tools \
             (alpha_author, alpha_author_critter, alpha_load, alpha_registry_publish, \
             alpha_registry_fetch_load, alpha_function_resolve, alpha_function_deploy, alpha_function_undeploy, alpha_job_submit, \
             alpha_job_control, alpha_send, \
             alpha_intent, alpha_bind, alpha_unload, alpha_cluster_connect) are gated by the target \
             node's allow-AI switch; while it is off they return an `ai-not-allowed` error. In local \
             mode this MCP node is headless, so only `alpha mcp --allow-ai` at startup opens its gate. \
             In remote mode the target owns the gate: grant at the target's REPL or boot that target \
             with `--allow-ai`; the hub's own flag cannot change it. There is deliberately NO tool to \
             flip the switch, so a remote AI can never grant itself permission; that is why no \
             `alpha_allow_ai` tool exists. Read-only tools (alpha_status, alpha_list, alpha_journal, alpha_watch, \
             alpha_registry_fetch, alpha_registry_list, alpha_bestiary_prove, \
             alpha_function_deployments, alpha_job_get, alpha_job_events, alpha_cluster) are not \
             blocked by allow-AI. Call alpha_ai_status before mutating so an operator can observe your \
             activity; an interactive target can revoke at its REPL, while a headless target closes \
             the gate by restarting without `--allow-ai`. Prefer alpha_author_critter (Rhai, \
             milliseconds) over alpha_author (a cold cargo build can take minutes and blocks the call)."
    })
}

fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn write_msg(stdout: &mut std::io::Stdout, msg: &Value) {
    let mut s = serde_json::to_string(msg).unwrap_or_default();
    s.push('\n');
    let _ = stdout.write_all(s.as_bytes());
    let _ = stdout.flush();
}

fn preview_bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = s[..cut].to_string();
    out.push_str("...");
    out
}

fn preview_token(s: &str) -> String {
    preview_bounded(s, MAX_ERROR_TOKEN_BYTES)
}

// ---- the async↔bus bridge (synchronous: the stdio loop is one blocking stream) -----------------

/// Ship `verb` to the control target and block (bounded) for its [`VerbResult`].
fn request_control(state: &SurfaceState, verb: Verb, timeout: Duration) -> VerbResult {
    let (me, bus) = match (state.me(), state.bus()) {
        (Some(me), Some(bus)) => (me, bus),
        _ => {
            return VerbResult::err(
                json!({ "error": "surface-unbound" }),
                "internal: the MCP surface is not bound to the bus yet",
            )
        }
    };
    let payload = match omni::control_verb_payload(&verb) {
        Ok(payload) => payload,
        Err(res) => return res,
    };
    let reply_capability = match omni::fresh_control_reply_capability() {
        Ok(capability) => capability,
        Err(detail) => {
            return VerbResult::err(
                json!({ "error": "control-reply-capability-unavailable", "detail": detail }),
                "control reply capability could not be generated; request was not sent",
            )
        }
    };
    let corr = state.corr.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = channel::<VerbResult>();
    if let Err(res) = state.register_pending(corr, reply_capability.clone(), tx) {
        return res;
    };
    let d = Dispatch::to(state.target.address(), payload)
        .with_schema(CONTROL_SCHEMA)
        .with_reply_to(Address::Creature(me))
        .with_corr(corr)
        .with_commitment(reply_capability);
    if let Err(e) = bus.emit(d) {
        state.remove_pending(corr);
        return VerbResult::err(
            json!({ "error": "control-unreachable", "detail": e.to_string() }),
            format!("control plane unreachable: {e}"),
        );
    }
    match rx.recv_timeout(timeout) {
        Ok(res) => res,
        Err(_) => {
            state.remove_pending(corr);
            VerbResult::err(
                json!({ "error": "control-timeout" }),
                "control plane did not reply in time",
            )
        }
    }
}

fn surface_busy(pending: usize) -> VerbResult {
    VerbResult::err(
        json!({
            "error": "surface-busy",
            "pending": pending,
            "limit": MAX_PENDING_CONTROL_REQUESTS,
        }),
        format!(
            "MCP control surface busy: {pending} pending requests (limit {MAX_PENDING_CONTROL_REQUESTS})"
        ),
    )
}

// ---- the tool catalog + dispatch ---------------------------------------------------------------

fn tool(name: &str, description: &str, schema: Value, read_only: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema,
        "annotations": { "readOnlyHint": read_only },
    })
}

fn no_args() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

fn signed_record_arg(description: &str) -> Value {
    json!({
        "type": "object",
        "description": description,
        "properties": {
            "schema": { "type": "string" },
            "signer": { "type": "string" },
            "payload": { "type": "object" },
            "signature": { "type": "string" }
        },
        "required": ["schema", "signer", "payload", "signature"],
        "additionalProperties": false
    })
}

/// The full tool list returned by `tools/list`. (Same surface as the legacy HTTP-backed proxy, so an
/// MCP host sees no change — only the transport beneath changed, to GAWD's own bus.)
fn tool_list() -> Value {
    json!([
        tool("alpha_status", "Snapshot of the live node: loaded-creature count, bound roles, journal length, and the allow-AI gate + last AI activity. Read-only.", no_args(), true),
        tool("alpha_list", "List the creatures currently loaded on the node (the roster): creature id, name, backend tier (daemon/beast/critter).", no_args(), true),
        tool("alpha_journal", "Recent bus journal entries (the node's short-term memory of routed envelopes). Read-only.", json!({ "type": "object", "properties": { "limit": { "type": "integer", "description": "How many recent entries to return (default 20)." } }, "additionalProperties": false }), true),
        tool("alpha_watch", "A combined glance: current status plus the last 10 journal entries. Read-only.", no_args(), true),
        tool("alpha_author", "Author a NEW daemon-tier (native .so) creature from a natural-language request. Triggers a real cargo build and CAN TAKE MINUTES (the call blocks). Prefer alpha_author_critter. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": { "type": "string", "maxLength": MAX_AUTHOR_ARG_BYTES, "description": "What the creature should do, in plain language." } }, "required": ["request"], "additionalProperties": false }), false),
        tool("alpha_author_critter", "Author a NEW critter-tier (Rhai script) creature from a natural-language request. No compiler — returns in milliseconds. The preferred authoring path. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": { "type": "string", "maxLength": MAX_AUTHOR_ARG_BYTES, "description": "What the critter should do, in plain language." } }, "required": ["request"], "additionalProperties": false }), false),
        tool("alpha_load", "Load a creature from a manifest + artifact already on the node's filesystem. Gated by allow-AI.", json!({ "type": "object", "properties": { "manifest_path": { "type": "string", "maxLength": MAX_PATH_ARG_BYTES }, "artifact_path": { "type": "string", "maxLength": MAX_PATH_ARG_BYTES } }, "required": ["manifest_path", "artifact_path"], "additionalProperties": false }), false),
        tool("alpha_registry_publish", "Publish a creature into the catalogue (the Bestiary) from a manifest + artifact already on the NODE's filesystem (same node-local caveat as alpha_load — not a client upload). Optional `realm` scopes the catalogue. Gated by allow-AI.", json!({ "type": "object", "properties": { "manifest_path": { "type": "string", "maxLength": MAX_PATH_ARG_BYTES }, "artifact_path": { "type": "string", "maxLength": MAX_PATH_ARG_BYTES }, "realm": { "type": "string", "maxLength": MAX_REALM_ARG_BYTES, "description": "Optional Realm name; omit for the local Realm." } }, "required": ["manifest_path", "artifact_path"], "additionalProperties": false }), false),
        tool("alpha_registry_fetch", "Look up a catalogue entry by artifact hash and return its manifest metadata (name, version, content_address) plus the artifact length — NOT the raw bytes. Optional `realm`. Read-only.", json!({ "type": "object", "properties": { "artifact_hash": { "type": "string", "maxLength": MAX_HASH_ARG_BYTES }, "realm": { "type": "string", "maxLength": MAX_REALM_ARG_BYTES, "description": "Optional Realm name; omit for the local Realm." } }, "required": ["artifact_hash"], "additionalProperties": false }), true),
        tool("alpha_registry_list", "Snapshot the catalogue (the Bestiary): each entry's artifact hash, name, version, Realm, reputation, and quarantine flag. Optional `realm` scopes to one Realm; omit to list all. Read-only.", json!({ "type": "object", "properties": { "realm": { "type": "string", "maxLength": MAX_REALM_ARG_BYTES, "description": "Optional Realm name; omit to list every Realm." } }, "additionalProperties": false }), true),
        tool("alpha_registry_fetch_load", "Fetch a creature artifact over GX (bounded, resumable chunks) from a registry, integrity-check it, and LOAD it into this node. Omit `node` to fetch from the local registry; set `node` + `registry_id` to fetch from a peer over the cluster. Optional `realm`. A large transfer can take a while (the call blocks). Loads code → gated by allow-AI.", json!({ "type": "object", "properties": { "artifact_hash": { "type": "string", "maxLength": MAX_HASH_ARG_BYTES }, "node": { "type": "string", "maxLength": MAX_NODE_ARG_BYTES, "description": "Optional peer node-id; with registry_id, fetches cross-node over the cluster." }, "registry_id": { "type": "integer", "description": "The peer registry's creature id — required when `node` is set (registry addressing is node-local)." }, "realm": { "type": "string", "maxLength": MAX_REALM_ARG_BYTES, "description": "Optional Realm name; omit for the local Realm." }, "chunk_size": { "type": "integer", "minimum": 0, "maximum": u32::MAX, "description": "Optional GX chunk size; omit to let the registry choose." } }, "required": ["artifact_hash"], "additionalProperties": false }), false),
        tool("alpha_bestiary_prove", "Ask the durable Bestiary for a standalone, signed EntryProof attestation over (realm, artifact_hash) — survives compaction and is independently verifiable. Only a durable bestiary-daemon answers (the in-memory stub returns an error). Read-only.", json!({ "type": "object", "properties": { "artifact_hash": { "type": "string", "maxLength": MAX_HASH_ARG_BYTES }, "realm": { "type": "string", "maxLength": MAX_REALM_ARG_BYTES } }, "required": ["artifact_hash", "realm"], "additionalProperties": false }), true),
        tool("alpha_function_resolve", "Resolve an already-signed gawdfn selector to one immutable signed function receipt. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed ResolveRequestV1") }, "required": ["request"], "additionalProperties": false }), false),
        tool("alpha_function_deploy", "Load and register an exact resolved function from a manifest + artifact already on the NODE's filesystem (not a client upload). Requires signed deployment authorization and resolution receipt. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed DeploymentRequestV1"), "resolution": signed_record_arg("Signed ResolutionReceiptV1"), "manifest_path": { "type": "string", "maxLength": MAX_PATH_ARG_BYTES }, "artifact_path": { "type": "string", "maxLength": MAX_PATH_ARG_BYTES } }, "required": ["request", "resolution", "manifest_path", "artifact_path"], "additionalProperties": false }), false),
        tool("alpha_function_undeploy", "Durably tombstone one exact deployment at its stable executor, verify its signed acknowledgement is bound to the current role responder, then unload only the exact manifest and measured artifact bytes still occupying the deployment receipt's local target id. Requires signed undeploy authorization and the exact signed deployment receipt. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed UndeployRequestV1"), "deployment": signed_record_arg("Signed DeploymentReceiptV1") }, "required": ["request", "deployment"], "additionalProperties": false }), false),
        tool("alpha_function_deployments", "Read a bounded list of signed live deployment receipts from the function executor.", json!({ "type": "object", "properties": { "query": { "type": "object", "properties": { "function": { "type": "object", "properties": { "manifest_content_address": { "type": "string" }, "entrypoint": { "type": "string" } }, "required": ["manifest_content_address", "entrypoint"], "additionalProperties": false }, "realm": { "type": "string" }, "node": { "type": "string" }, "limit": { "type": "integer", "minimum": 1, "maximum": gawdfn::MAX_EVENT_PAGE_ITEMS } }, "required": ["limit"], "additionalProperties": false } }, "required": ["query"], "additionalProperties": false }), true),
        tool("alpha_job_submit", "Submit an already-signed job with exact signed resolution and deployment pins. Returns durable Accepted only; execution remains asynchronous. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed JobSubmitV1"), "resolution": signed_record_arg("Signed ResolutionReceiptV1"), "deployment": signed_record_arg("Signed DeploymentReceiptV1") }, "required": ["request", "resolution", "deployment"], "additionalProperties": false }), false),
        tool("alpha_job_get", "Read a job as the complete route-bound relay request plus signed snapshot response proof.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed JobGetV1") }, "required": ["request"], "additionalProperties": false }), true),
        tool("alpha_job_events", "Read a bounded event page as the complete route-bound relay request plus signed page response proof.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed EventQueryV1") }, "required": ["request"], "additionalProperties": false }), true),
        tool("alpha_job_control", "Apply an already-signed cooperative steer, cancel, or access command at the job home. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": signed_record_arg("Signed JobControlV1") }, "required": ["request"], "additionalProperties": false }), false),
        tool("alpha_send", "Send a text message to a creature by creature id and read its reply. Add `node` to route to a creature on a peer node over the cluster. Gated by allow-AI.", json!({ "type": "object", "properties": { "id": { "type": "integer" }, "text": { "type": "string", "maxLength": MAX_TEXT_ARG_BYTES }, "node": { "type": "string", "maxLength": MAX_NODE_ARG_BYTES, "description": "Optional peer node-id — routes the send across the cluster." } }, "required": ["id", "text"], "additionalProperties": false }), false),
        tool("alpha_intent", "Express an intent on a Role (outcome + text) and read the reply from whatever creature is bound there. Gated by allow-AI.", json!({ "type": "object", "properties": { "outcome": { "type": "string", "maxLength": omni::MAX_CONTROL_ROLE_NAME_BYTES }, "text": { "type": "string", "maxLength": MAX_TEXT_ARG_BYTES } }, "required": ["outcome", "text"], "additionalProperties": false }), false),
        tool("alpha_bind", "Bind a loaded creature to a Role so intents addressed to that Role route to it. Gated by allow-AI.", json!({ "type": "object", "properties": { "role": { "type": "string", "maxLength": omni::MAX_CONTROL_ROLE_NAME_BYTES, "pattern": "^[A-Za-z0-9._-]+$" }, "id": { "type": "integer" } }, "required": ["role", "id"], "additionalProperties": false }), false),
        tool("alpha_unload", "Unload a creature by creature id (runs its orderly teardown). Gated by allow-AI.", json!({ "type": "object", "properties": { "id": { "type": "integer" } }, "required": ["id"], "additionalProperties": false }), false),
        tool("alpha_ai_status", "Record what you (the AI) are doing on this shared node so every control surface reports the same current activity. MCP stores the update; unlike the HTTP endpoint, it does not itself push a tape/WebSocket frame. Call it before a mutating action. Not gated.", json!({ "type": "object", "properties": { "working": { "type": "boolean" }, "activity": { "type": "string", "maxLength": MAX_AI_STATUS_ARG_BYTES }, "message": { "type": "string", "maxLength": MAX_AI_STATUS_ARG_BYTES } }, "required": ["working"], "additionalProperties": false }), false),
        tool("alpha_cluster", "Read this node's view of the cluster graph: which peer Sanctums it knows and which are connected. Read-only.", no_args(), true),
        tool("alpha_cluster_connect", "Admit + dial a cluster peer (the cluster join); gossip then spreads it across the mesh. Gated by allow-AI.", json!({ "type": "object", "properties": { "node_id": { "type": "string", "maxLength": MAX_NODE_ARG_BYTES }, "addr": { "type": "string", "maxLength": MAX_ADDR_ARG_BYTES }, "pubkey": { "type": "string", "maxLength": MAX_PUBKEY_ARG_BYTES } }, "required": ["node_id", "addr", "pubkey"], "additionalProperties": false }), false),
    ])
}

/// Handle a `tools/call`: dispatch to a verb, then wrap in the MCP content envelope.
fn call_tool(state: &SurfaceState, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let (is_error, value) = dispatch(state, name, &args);
    let text = serde_json::to_string_pretty(&value).unwrap_or_default();
    let mut result = json!({ "content": [ { "type": "text", "text": text } ] });
    if is_error {
        result["isError"] = json!(true);
    }
    result
}

/// Map a tool name + args to a [`Verb`], run it over the bus, and normalize to `(is_error, body)`.
fn dispatch(state: &SurfaceState, name: &str, args: &Value) -> (bool, Value) {
    if !known_tool(name) {
        return (true, json!({ "error": format!("unknown tool: {}", preview_token(name)) }));
    }
    if let Err(e) = validate_args(name, args) {
        return (true, json!({ "error": e }));
    }
    if name == "alpha_watch" {
        let status = request_control(state, Verb::Status, READ_TIMEOUT);
        if !status.ok {
            return (true, status.json);
        }
        let journal = request_control(state, Verb::Journal { limit: 10 }, READ_TIMEOUT);
        if !journal.ok {
            return (true, journal.json);
        }
        return (false, json!({ "status": status.json, "journal": journal.json }));
    }
    if let Some(typed) = function_job_verb(name, args) {
        let verb = match typed {
            Ok(verb) => verb,
            Err(error) => return (true, json!({ "error": error })),
        };
        let res = request_control(state, verb, READ_TIMEOUT);
        return (!res.ok, res.json);
    }
    let (verb, timeout) = match name {
        "alpha_status" => (Verb::Status, READ_TIMEOUT),
        "alpha_list" => (Verb::List, READ_TIMEOUT),
        "alpha_journal" => (
            Verb::Journal {
                limit: args.get("limit").and_then(Value::as_u64).unwrap_or(20) as usize,
            },
            READ_TIMEOUT,
        ),
        "alpha_author" => (Verb::Author { request: sarg(args, "request") }, AUTHOR_TIMEOUT),
        "alpha_author_critter" => {
            (Verb::AuthorCritter { request: sarg(args, "request") }, AUTHOR_TIMEOUT)
        }
        "alpha_load" => (
            Verb::Load {
                manifest_path: sarg(args, "manifest_path"),
                artifact_path: sarg(args, "artifact_path"),
            },
            READ_TIMEOUT,
        ),
        "alpha_registry_publish" => (
            Verb::RegistryPublish {
                manifest_path: sarg(args, "manifest_path"),
                artifact_path: sarg(args, "artifact_path"),
                realm: oarg_realm(args, "realm"),
            },
            READ_TIMEOUT,
        ),
        "alpha_registry_fetch" => (
            Verb::RegistryFetch {
                artifact_hash: sarg(args, "artifact_hash"),
                realm: oarg_realm(args, "realm"),
            },
            READ_TIMEOUT,
        ),
        "alpha_registry_list" => {
            (Verb::RegistryList { realm: oarg_realm(args, "realm") }, READ_TIMEOUT)
        }
        "alpha_registry_fetch_load" => (
            Verb::FetchLoad {
                artifact_hash: sarg(args, "artifact_hash"),
                node: args.get("node").and_then(Value::as_str).map(str::to_string),
                registry_id: args.get("registry_id").and_then(Value::as_u64),
                realm: oarg_realm(args, "realm"),
                chunk_size: args
                    .get("chunk_size")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok()),
            },
            AUTHOR_TIMEOUT,
        ),
        "alpha_bestiary_prove" => (
            Verb::BestiaryProve {
                artifact_hash: sarg(args, "artifact_hash"),
                realm: RealmId::new(sarg(args, "realm")),
            },
            READ_TIMEOUT,
        ),
        "alpha_send" => (
            Verb::Send {
                id: uarg(args, "id"),
                text: sarg(args, "text"),
                node: args.get("node").and_then(Value::as_str).map(str::to_string),
            },
            READ_TIMEOUT,
        ),
        "alpha_intent" => (
            Verb::Intent { outcome: sarg(args, "outcome"), text: sarg(args, "text") },
            READ_TIMEOUT,
        ),
        "alpha_bind" => {
            (Verb::Bind { role: sarg(args, "role"), id: uarg(args, "id") }, READ_TIMEOUT)
        }
        "alpha_unload" => (Verb::Unload { id: uarg(args, "id") }, READ_TIMEOUT),
        "alpha_ai_status" => (
            Verb::AiStatus {
                working: args.get("working").and_then(Value::as_bool).unwrap_or(false),
                activity: sarg(args, "activity"),
                message: sarg(args, "message"),
            },
            READ_TIMEOUT,
        ),
        "alpha_cluster" => (Verb::Cluster, READ_TIMEOUT),
        "alpha_cluster_connect" => (
            Verb::ClusterJoin {
                node_id: sarg(args, "node_id"),
                addr: sarg(args, "addr"),
                pubkey: sarg(args, "pubkey"),
            },
            READ_TIMEOUT,
        ),
        _ => unreachable!("known_tool and dispatch match must stay in lock-step"),
    };
    let res = request_control(state, verb, timeout);
    (!res.ok, res.json)
}

fn function_job_verb(name: &str, args: &Value) -> Option<Result<Verb, String>> {
    let parsed = match name {
        "alpha_function_resolve" => typed_arg::<SignedRecordV1<ResolveRequestV1>>(args, "request")
            .map(|request| Verb::FunctionResolve { request }),
        "alpha_function_deploy" => (|| {
            Ok(Verb::FunctionDeploy {
                request: typed_arg::<SignedRecordV1<DeploymentRequestV1>>(args, "request")?,
                resolution: typed_arg::<SignedRecordV1<ResolutionReceiptV1>>(args, "resolution")?,
                manifest_path: sarg(args, "manifest_path"),
                artifact_path: sarg(args, "artifact_path"),
            })
        })(),
        "alpha_function_undeploy" => (|| {
            Ok(Verb::FunctionUndeploy {
                request: typed_arg::<SignedRecordV1<UndeployRequestV1>>(args, "request")?,
                deployment: typed_arg::<SignedRecordV1<DeploymentReceiptV1>>(args, "deployment")?,
            })
        })(),
        "alpha_function_deployments" => typed_arg::<DeploymentQueryV1>(args, "query")
            .map(|query| Verb::FunctionDeployments { query }),
        "alpha_job_submit" => (|| {
            Ok(Verb::JobSubmit {
                request: Box::new(typed_arg::<SignedRecordV1<JobSubmitV1>>(args, "request")?),
                resolution: typed_arg::<SignedRecordV1<ResolutionReceiptV1>>(args, "resolution")?,
                deployment: typed_arg::<SignedRecordV1<DeploymentReceiptV1>>(args, "deployment")?,
            })
        })(),
        "alpha_job_get" => typed_arg::<SignedRecordV1<JobGetV1>>(args, "request")
            .map(|request| Verb::JobGet { request }),
        "alpha_job_events" => typed_arg::<SignedRecordV1<EventQueryV1>>(args, "request")
            .map(|request| Verb::JobEvents { request }),
        "alpha_job_control" => typed_arg::<SignedRecordV1<JobControlV1>>(args, "request")
            .map(|request| Verb::JobControl { request }),
        _ => return None,
    };
    Some(parsed)
}

fn typed_arg<T: DeserializeOwned>(args: &Value, key: &str) -> Result<T, String> {
    let value =
        args.get(key).cloned().ok_or_else(|| format!("missing required parameter `{key}`"))?;
    serde_json::from_value(value).map_err(|e| format!("parameter `{key}` is invalid: {e}"))
}

// ---- argument validation (mirrors the advertised inputSchema) ----------------------------------

#[derive(Clone, Copy)]
enum ArgType {
    String,
    U64,
    U32,
    Bool,
    Object,
}

impl ArgType {
    fn label(self) -> &'static str {
        match self {
            ArgType::String => "string",
            ArgType::U64 => "non-negative integer",
            ArgType::U32 => "integer in u32 range",
            ArgType::Bool => "boolean",
            ArgType::Object => "object",
        }
    }
    fn matches(self, v: &Value) -> bool {
        match self {
            ArgType::String => v.is_string(),
            ArgType::U64 => v.as_u64().is_some(),
            ArgType::U32 => v.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
            ArgType::Bool => v.is_boolean(),
            ArgType::Object => v.is_object(),
        }
    }
}

struct ArgSpec {
    name: &'static str,
    ty: ArgType,
    required: bool,
    max_bytes: Option<usize>,
}

impl ArgSpec {
    const fn string(name: &'static str, required: bool, max_bytes: usize) -> Self {
        Self { name, ty: ArgType::String, required, max_bytes: Some(max_bytes) }
    }

    const fn u64(name: &'static str, required: bool) -> Self {
        Self { name, ty: ArgType::U64, required, max_bytes: None }
    }

    const fn u32(name: &'static str, required: bool) -> Self {
        Self { name, ty: ArgType::U32, required, max_bytes: None }
    }

    const fn bool(name: &'static str, required: bool) -> Self {
        Self { name, ty: ArgType::Bool, required, max_bytes: None }
    }

    const fn object(name: &'static str, required: bool) -> Self {
        Self { name, ty: ArgType::Object, required, max_bytes: None }
    }
}

const ARGS_NONE: &[ArgSpec] = &[];
const ARGS_JOURNAL: &[ArgSpec] = &[ArgSpec::u64("limit", false)];
const ARGS_AUTHOR: &[ArgSpec] = &[ArgSpec::string("request", true, MAX_AUTHOR_ARG_BYTES)];
const ARGS_LOAD: &[ArgSpec] = &[
    ArgSpec::string("manifest_path", true, MAX_PATH_ARG_BYTES),
    ArgSpec::string("artifact_path", true, MAX_PATH_ARG_BYTES),
];
const ARGS_REGISTRY_PUBLISH: &[ArgSpec] = &[
    ArgSpec::string("manifest_path", true, MAX_PATH_ARG_BYTES),
    ArgSpec::string("artifact_path", true, MAX_PATH_ARG_BYTES),
    ArgSpec::string("realm", false, MAX_REALM_ARG_BYTES),
];
const ARGS_REGISTRY_FETCH: &[ArgSpec] = &[
    ArgSpec::string("artifact_hash", true, MAX_HASH_ARG_BYTES),
    ArgSpec::string("realm", false, MAX_REALM_ARG_BYTES),
];
const ARGS_REGISTRY_LIST: &[ArgSpec] = &[ArgSpec::string("realm", false, MAX_REALM_ARG_BYTES)];
const ARGS_REGISTRY_FETCH_LOAD: &[ArgSpec] = &[
    ArgSpec::string("artifact_hash", true, MAX_HASH_ARG_BYTES),
    ArgSpec::string("node", false, MAX_NODE_ARG_BYTES),
    ArgSpec::u64("registry_id", false),
    ArgSpec::string("realm", false, MAX_REALM_ARG_BYTES),
    ArgSpec::u32("chunk_size", false),
];
const ARGS_BESTIARY_PROVE: &[ArgSpec] = &[
    ArgSpec::string("artifact_hash", true, MAX_HASH_ARG_BYTES),
    ArgSpec::string("realm", true, MAX_REALM_ARG_BYTES),
];
const ARGS_FUNCTION_RESOLVE: &[ArgSpec] = &[ArgSpec::object("request", true)];
const ARGS_FUNCTION_DEPLOY: &[ArgSpec] = &[
    ArgSpec::object("request", true),
    ArgSpec::object("resolution", true),
    ArgSpec::string("manifest_path", true, MAX_PATH_ARG_BYTES),
    ArgSpec::string("artifact_path", true, MAX_PATH_ARG_BYTES),
];
const ARGS_FUNCTION_UNDEPLOY: &[ArgSpec] =
    &[ArgSpec::object("request", true), ArgSpec::object("deployment", true)];
const ARGS_FUNCTION_DEPLOYMENTS: &[ArgSpec] = &[ArgSpec::object("query", true)];
const ARGS_JOB_SUBMIT: &[ArgSpec] = &[
    ArgSpec::object("request", true),
    ArgSpec::object("resolution", true),
    ArgSpec::object("deployment", true),
];
const ARGS_JOB_REQUEST: &[ArgSpec] = &[ArgSpec::object("request", true)];
const ARGS_SEND: &[ArgSpec] = &[
    ArgSpec::u64("id", true),
    ArgSpec::string("text", true, MAX_TEXT_ARG_BYTES),
    ArgSpec::string("node", false, MAX_NODE_ARG_BYTES),
];
const ARGS_INTENT: &[ArgSpec] = &[
    ArgSpec::string("outcome", true, omni::MAX_CONTROL_ROLE_NAME_BYTES),
    ArgSpec::string("text", true, MAX_TEXT_ARG_BYTES),
];
const ARGS_BIND: &[ArgSpec] =
    &[ArgSpec::string("role", true, omni::MAX_CONTROL_ROLE_NAME_BYTES), ArgSpec::u64("id", true)];
const ARGS_UNLOAD: &[ArgSpec] = &[ArgSpec::u64("id", true)];
const ARGS_CLUSTER_CONNECT: &[ArgSpec] = &[
    ArgSpec::string("node_id", true, MAX_NODE_ARG_BYTES),
    ArgSpec::string("addr", true, MAX_ADDR_ARG_BYTES),
    ArgSpec::string("pubkey", true, MAX_PUBKEY_ARG_BYTES),
];
const ARGS_AI_STATUS: &[ArgSpec] = &[
    ArgSpec::bool("working", true),
    ArgSpec::string("activity", false, MAX_AI_STATUS_ARG_BYTES),
    ArgSpec::string("message", false, MAX_AI_STATUS_ARG_BYTES),
];

fn known_tool(name: &str) -> bool {
    matches!(
        name,
        "alpha_status"
            | "alpha_list"
            | "alpha_journal"
            | "alpha_watch"
            | "alpha_author"
            | "alpha_author_critter"
            | "alpha_load"
            | "alpha_registry_publish"
            | "alpha_registry_fetch"
            | "alpha_registry_list"
            | "alpha_registry_fetch_load"
            | "alpha_bestiary_prove"
            | "alpha_function_resolve"
            | "alpha_function_deploy"
            | "alpha_function_undeploy"
            | "alpha_function_deployments"
            | "alpha_job_submit"
            | "alpha_job_get"
            | "alpha_job_events"
            | "alpha_job_control"
            | "alpha_send"
            | "alpha_intent"
            | "alpha_bind"
            | "alpha_unload"
            | "alpha_ai_status"
            | "alpha_cluster"
            | "alpha_cluster_connect"
    )
}

fn arg_specs(name: &str) -> &'static [ArgSpec] {
    match name {
        "alpha_journal" => ARGS_JOURNAL,
        "alpha_author" | "alpha_author_critter" => ARGS_AUTHOR,
        "alpha_load" => ARGS_LOAD,
        "alpha_registry_publish" => ARGS_REGISTRY_PUBLISH,
        "alpha_registry_fetch" => ARGS_REGISTRY_FETCH,
        "alpha_registry_list" => ARGS_REGISTRY_LIST,
        "alpha_registry_fetch_load" => ARGS_REGISTRY_FETCH_LOAD,
        "alpha_bestiary_prove" => ARGS_BESTIARY_PROVE,
        "alpha_function_resolve" => ARGS_FUNCTION_RESOLVE,
        "alpha_function_deploy" => ARGS_FUNCTION_DEPLOY,
        "alpha_function_undeploy" => ARGS_FUNCTION_UNDEPLOY,
        "alpha_function_deployments" => ARGS_FUNCTION_DEPLOYMENTS,
        "alpha_job_submit" => ARGS_JOB_SUBMIT,
        "alpha_job_get" | "alpha_job_events" | "alpha_job_control" => ARGS_JOB_REQUEST,
        "alpha_send" => ARGS_SEND,
        "alpha_intent" => ARGS_INTENT,
        "alpha_bind" => ARGS_BIND,
        "alpha_unload" => ARGS_UNLOAD,
        "alpha_cluster_connect" => ARGS_CLUSTER_CONNECT,
        "alpha_ai_status" => ARGS_AI_STATUS,
        _ => ARGS_NONE,
    }
}

fn validate_args(name: &str, args: &Value) -> Result<(), String> {
    let Some(obj) = args.as_object() else {
        return Err(format!("arguments for {name} must be a JSON object"));
    };
    let specs = arg_specs(name);
    for key in obj.keys() {
        if !specs.iter().any(|s| s.name == key) {
            return Err(format!("unknown parameter `{}` for {name}", preview_token(key)));
        }
    }
    for spec in specs {
        match obj.get(spec.name) {
            None | Some(Value::Null) => {
                if spec.required {
                    return Err(format!("missing required parameter `{}` for {name}", spec.name));
                }
            }
            Some(value) => {
                if !spec.ty.matches(value) {
                    return Err(format!(
                        "parameter `{}` for {name} must be a {}",
                        spec.name,
                        spec.ty.label()
                    ));
                }
                if let (Some(max), Some(s)) = (spec.max_bytes, value.as_str()) {
                    if s.len() > max {
                        return Err(format!(
                            "parameter `{}` for {name} is {} bytes, exceeds {} byte limit",
                            spec.name,
                            s.len(),
                            max
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn sarg(args: &Value, key: &str) -> String {
    args.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn uarg(args: &Value, key: &str) -> u64 {
    args.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// An optional Realm argument: a present, non-empty string → `Some(RealmId)`; absent/empty → `None`
/// (the local Realm). Keeps the implicit-Realm path off the wire, matching the `Verb` field default.
fn oarg_realm(args: &Value, key: &str) -> Option<RealmId> {
    args.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(RealmId::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::mpsc::channel as std_channel;
    use std::time::{Duration, Instant};

    fn test_state() -> SurfaceState {
        SurfaceState {
            bus: Mutex::new(None),
            me: Mutex::new(None),
            corr: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            target: ControlTarget::Local,
            stop: AtomicBool::new(false),
        }
    }

    #[test]
    fn capped_reader_accepts_normal_json_rpc_lines() {
        let mut reader = Cursor::new(b"{\"jsonrpc\":\"2.0\",\"id\":1}\n");
        assert_eq!(
            read_line_capped(&mut reader, MAX_JSON_RPC_LINE_BYTES).unwrap(),
            RpcLine::Line("{\"jsonrpc\":\"2.0\",\"id\":1}\n".into())
        );
        assert_eq!(read_line_capped(&mut reader, MAX_JSON_RPC_LINE_BYTES).unwrap(), RpcLine::Eof);
    }

    #[test]
    fn capped_reader_drains_oversized_lines_and_continues() {
        let mut bytes = vec![b'a'; 17];
        bytes.extend_from_slice(b"\n{\"id\":2}\n");
        let mut reader = Cursor::new(bytes);

        assert_eq!(read_line_capped(&mut reader, 16).unwrap(), RpcLine::TooLong);
        assert_eq!(
            read_line_capped(&mut reader, 16).unwrap(),
            RpcLine::Line("{\"id\":2}\n".into())
        );
    }

    #[test]
    fn initialize_reflects_only_bounded_protocol_versions() {
        let exact = "v".repeat(MAX_PROTOCOL_VERSION_BYTES);
        assert_eq!(
            initialize_result(&json!({ "protocolVersion": exact }))["protocolVersion"],
            json!(exact)
        );

        assert_eq!(
            initialize_result(
                &json!({ "protocolVersion": "v".repeat(MAX_PROTOCOL_VERSION_BYTES + 1) })
            )["protocolVersion"],
            json!(PROTOCOL_VERSION)
        );
    }

    #[test]
    fn pending_control_requests_are_bounded() {
        let st = test_state();
        let mut receivers = Vec::new();

        for corr in 0..MAX_PENDING_CONTROL_REQUESTS as u64 {
            let (tx, rx) = channel();
            st.register_pending(corr, format!("cap-{corr}"), tx).expect("under cap");
            receivers.push(rx);
        }

        let (tx, _rx) = channel();
        let err = st.register_pending(999_999, "cap-new".into(), tx).expect_err("at cap refuses");
        assert!(!err.ok);
        assert_eq!(err.json["error"].as_str(), Some("surface-busy"));
        assert_eq!(err.json["limit"].as_u64(), Some(MAX_PENDING_CONTROL_REQUESTS as u64));
        assert_eq!(
            st.pending.lock().unwrap().len(),
            MAX_PENDING_CONTROL_REQUESTS,
            "refused request is not parked"
        );

        assert!(
            st.take_pending(0, Some("cap-0")).is_some(),
            "existing corr and capability are removable"
        );
        let (tx, rx) = channel();
        st.register_pending(999_999, "cap-new".into(), tx)
            .expect("space reopens after one is removed");
        receivers.push(rx);
    }

    #[test]
    fn forged_control_reply_cannot_consume_a_pending_mcp_request() {
        let st = test_state();
        let (tx, _rx) = channel();
        st.register_pending(41, "unguessable-request-capability".into(), tx).unwrap();

        assert!(
            st.take_pending(41, Some("attacker-guessed-corr-only")).is_none(),
            "a matching predictable corr with the wrong capability is inert"
        );
        assert_eq!(st.pending.lock().unwrap().len(), 1, "the legitimate waiter remains parked");
        assert!(
            st.take_pending(41, None).is_none(),
            "a legacy corr-only reply cannot consume the waiter"
        );
        assert!(
            st.take_pending(41, Some("unguessable-request-capability")).is_some(),
            "only the exact echoed request capability completes the request"
        );
    }

    #[test]
    fn validate_args_rejects_oversized_string_arguments() {
        let err = validate_args(
            "alpha_registry_fetch",
            &json!({ "artifact_hash": "x".repeat(MAX_HASH_ARG_BYTES + 1) }),
        )
        .unwrap_err();

        assert!(err.contains("artifact_hash"), "names the field: {err}");
        assert!(err.contains("exceeds"), "explains the byte cap: {err}");
        assert!(err.contains(&MAX_HASH_ARG_BYTES.to_string()), "reports the cap: {err}");
    }

    #[test]
    fn validate_args_rejects_fetch_load_chunk_size_above_u32() {
        let err = validate_args(
            "alpha_registry_fetch_load",
            &json!({
                "artifact_hash": "a".repeat(64),
                "chunk_size": u64::from(u32::MAX) + 1,
            }),
        )
        .unwrap_err();

        assert!(err.contains("chunk_size"), "names the field: {err}");
        assert!(err.contains("u32"), "explains the range: {err}");
    }

    #[test]
    fn function_job_tools_require_structured_contract_arguments() {
        let error = validate_args("alpha_job_get", &json!({ "request": "opaque-json" }))
            .expect_err("signed records are objects, not surface-private strings");
        assert!(error.contains("request"));
        assert!(error.contains("object"));

        validate_args(
            "alpha_job_submit",
            &json!({ "request": {}, "resolution": {}, "deployment": {} }),
        )
        .expect("the typed decoder, then omni, performs the nested contract checks");

        validate_args("alpha_function_undeploy", &json!({ "request": {}, "deployment": {} }))
            .expect("undeploy carries two structured signed records");
        let error = validate_args("alpha_function_undeploy", &json!({ "request": {} }))
            .expect_err("the exact deployment receipt is required control evidence");
        assert!(error.contains("deployment"));

        let error = validate_args(
            "alpha_function_deploy",
            &json!({
                "request": {},
                "resolution": {},
                "manifest_path": "m".repeat(MAX_PATH_ARG_BYTES + 1),
                "artifact_path": "/node/artifact.wasm"
            }),
        )
        .expect_err("node-local deployment paths retain the shared path cap");
        assert!(error.contains("manifest_path"));
        assert!(error.contains("exceeds"));
    }

    #[test]
    fn deployment_tool_maps_to_the_fixed_typed_verb() {
        let args = json!({ "query": { "realm": "trusted", "limit": 4 } });
        validate_args("alpha_function_deployments", &args).unwrap();
        let verb = function_job_verb("alpha_function_deployments", &args)
            .expect("known function tool")
            .expect("typed query");
        assert!(matches!(
            verb,
            Verb::FunctionDeployments {
                query: DeploymentQueryV1 {
                    realm: Some(realm),
                    limit: 4,
                    ..
                }
            } if realm == "trusted"
        ));
    }

    #[test]
    fn job_submit_tool_maps_structured_proofs_to_the_shared_async_verb() {
        let home = gawdfn::HomeId::new("home");
        let function = gawdfn::FunctionId {
            manifest_content_address: format!("sha256:{}", "a".repeat(64)),
            entrypoint: "run".into(),
        };
        let selector = gawdfn::FunctionSelectorV1::Id { function: function.clone() };
        let unsigned = |schema: &str, payload: Value| json!({ "schema": schema, "signer": "", "payload": payload, "signature": "" });
        let request = unsigned(
            gawdfn::SCHEMA_JOB_V1,
            serde_json::to_value(gawdfn::JobSubmitV1 {
                home,
                caller_idempotency_key: "mcp-parity".into(),
                function: selector.clone(),
                input: gawdfn::ValueRefV1::Inline { value: json!({}) },
                delivery: gawdfn::DeliveryModeV1::AtMostOnce,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access: gawdfn::JobAccessV1::default(),
                evidence: vec![],
                result_recipients: vec![],
                submitted_at_unix_ms: None,
            })
            .unwrap(),
        );
        let resolution = unsigned(
            gawdfn::SCHEMA_FUNCTION_DEPLOY_V1,
            serde_json::to_value(gawdfn::ResolutionReceiptV1 {
                selector,
                function: function.clone(),
                artifact_hash: format!("sha256:{}", "b".repeat(64)),
                resolved_at_unix_ms: None,
                evidence: vec![],
            })
            .unwrap(),
        );
        let deployment = unsigned(
            gawdfn::SCHEMA_FUNCTION_DEPLOY_V1,
            serde_json::to_value(gawdfn::DeploymentReceiptV1 {
                deployment: gawdfn::DeploymentId::new("deployment"),
                function,
                artifact_hash: format!("sha256:{}", "b".repeat(64)),
                realm: "local".into(),
                node: "node".into(),
                executor: String::new(),
                executor_creature: "1".into(),
                creature: "2".into(),
                evidence: vec![],
                registered_at_unix_ms: None,
            })
            .unwrap(),
        );
        let args = json!({
            "request": request,
            "resolution": resolution,
            "deployment": deployment
        });

        validate_args("alpha_job_submit", &args).unwrap();
        let verb = function_job_verb("alpha_job_submit", &args)
            .expect("job submit is in the exact Function/Job tool set")
            .expect("structured records decode");
        assert!(matches!(verb, Verb::JobSubmit { .. }));
    }

    #[test]
    fn unknown_tool_errors_do_not_echo_unbounded_names() {
        let st = test_state();
        let huge = "tool".repeat(MAX_ERROR_TOKEN_BYTES);

        let (is_error, value) = dispatch(&st, &huge, &json!({}));

        assert!(is_error);
        let err = value["error"].as_str().expect("error string");
        assert!(err.contains("..."), "oversized token is marked truncated: {err:?}");
        assert!(
            err.len() <= "unknown tool: ".len() + MAX_ERROR_TOKEN_BYTES + 3,
            "error is bounded: {} bytes",
            err.len()
        );
    }

    #[test]
    fn unknown_parameter_errors_do_not_echo_unbounded_names() {
        let st = test_state();
        let huge_key = "surprise".repeat(MAX_ERROR_TOKEN_BYTES);
        let args = json!({ huge_key: true });

        let (is_error, value) = dispatch(&st, "alpha_status", &args);

        assert!(is_error);
        let err = value["error"].as_str().expect("error string");
        assert!(err.contains("..."), "oversized token is marked truncated: {err:?}");
        assert!(
            err.len() <= "unknown parameter `` for alpha_status".len() + MAX_ERROR_TOKEN_BYTES + 3,
            "error is bounded: {} bytes",
            err.len()
        );
    }

    #[test]
    fn shutdown_join_helper_does_not_wait_for_blocked_stdio_thread() {
        let (release_tx, release_rx) = std_channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = release_rx.recv();
        });

        let start = Instant::now();
        assert!(
            !join_stdio_thread_if_finished(handle),
            "unfinished stdio thread should be detached, not joined"
        );
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "shutdown helper must not block on an unfinished stdio thread"
        );
        let _ = release_tx.send(());
    }
}
