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
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, Outcome,
};
use omni::{ControlTarget, Verb, VerbResult, CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA};

use serde_json::{json, Value};

const SERVER_NAME: &str = "alpha-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2025-11-25";

/// Generous ceiling for a cold `author` (a real `cargo build`); everything else replies in ms.
const AUTHOR_TIMEOUT: Duration = Duration::from_secs(400);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared between the stdio loop and the creature's `handle` (which delivers control replies).
struct SurfaceState {
    bus: Mutex<Option<Arc<dyn Bus>>>,
    me: Mutex<Option<CreatureId>>,
    corr: AtomicU64,
    pending: Mutex<HashMap<u64, Sender<VerbResult>>>,
    target: ControlTarget,
    stop: AtomicBool,
}

impl SurfaceState {
    fn me(&self) -> Option<CreatureId> {
        *self.me.lock().unwrap()
    }
    fn bus(&self) -> Option<Arc<dyn Bus>> {
        self.bus.lock().unwrap().clone()
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
                if let Some(tx) = self.state.pending.lock().unwrap().remove(&corr) {
                    if let Ok(res) = serde_json::from_slice::<VerbResult>(&env.payload) {
                        let _ = tx.send(res);
                    }
                }
            }
        }
        Outcome::none()
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // Signal the stdio loop to stop after its current line. A blocking `read_line` cannot be
        // interrupted portably, so the thread exits on the next line or on EOF (the host closing
        // stdin) — for an MCP hub the process is usually exiting anyway. Best-effort join.
        self.state.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.stdio_thread.take() {
            let _ = h.join();
        }
    }
}

// ---- the stdio JSON-RPC loop -------------------------------------------------------------------

fn run_stdio(state: Arc<SurfaceState>) {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut line = String::new();
    let mut reader = stdin.lock();
    loop {
        if state.stop.load(Ordering::Relaxed) {
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF — the host closed stdin
            Ok(_) => {}
            Err(e) => {
                eprintln!("surface-mcp: stdin read error: {e}");
                break;
            }
        }
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
            other => error(id, -32601, &format!("Method not found: {other}")),
        };
        write_msg(&mut stdout, &response);
    }
}

fn initialize_result(params: &Value) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or(PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
        "instructions":
            "alpha-mcp drives a running Alpha Sanctum over GAWD's own bus: each tool call is \
             a Verb envelope routed to Role::CONTROL, and the result rides back. The MCP \
             server is itself a headless Sanctum (a control-hub node). DEV posture: the target node's dev policy \
             admits everything and the bus signer is a stub; not a hardened deployment. Mutating tools \
             (alpha_author, alpha_author_critter, alpha_load, alpha_send, alpha_intent, alpha_bind, \
             alpha_unload, alpha_cluster_connect) are gated by the target node's allow-AI switch, which a \
             human grants with `allow-ai on` at that node's REPL; while it is off they return an \
             `ai-not-allowed` error. Read-only tools (alpha_status, alpha_list, alpha_journal, alpha_watch, \
             alpha_cluster) are not blocked by allow-AI. Call alpha_ai_status before mutating so the human \
             watching the node can see your activity and revoke. Prefer alpha_author_critter (Rhai, \
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
    let corr = state.corr.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = channel::<VerbResult>();
    state.pending.lock().unwrap().insert(corr, tx);
    let payload = serde_json::to_vec(&verb).unwrap_or_default();
    let d = Dispatch::to(state.target.address(), payload)
        .with_schema(CONTROL_SCHEMA)
        .with_reply_to(Address::Creature(me))
        .with_corr(corr);
    if let Err(e) = bus.emit(d) {
        state.pending.lock().unwrap().remove(&corr);
        return VerbResult::err(
            json!({ "error": "control-unreachable", "detail": e.to_string() }),
            format!("control plane unreachable: {e}"),
        );
    }
    match rx.recv_timeout(timeout) {
        Ok(res) => res,
        Err(_) => {
            state.pending.lock().unwrap().remove(&corr);
            VerbResult::err(
                json!({ "error": "control-timeout" }),
                "control plane did not reply in time",
            )
        }
    }
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

/// The full tool list returned by `tools/list`. (Same surface as the legacy HTTP-backed proxy, so an
/// MCP host sees no change — only the transport beneath changed, to GAWD's own bus.)
fn tool_list() -> Value {
    json!([
        tool("alpha_status", "Snapshot of the live node: loaded-creature count, bound roles, journal length, and the allow-AI gate + last AI activity. Read-only.", no_args(), true),
        tool("alpha_list", "List the creatures currently loaded on the node (the roster): creature id, name, backend tier (daemon/beast/critter).", no_args(), true),
        tool("alpha_journal", "Recent bus journal entries (the node's short-term memory of routed envelopes). Read-only.", json!({ "type": "object", "properties": { "limit": { "type": "integer", "description": "How many recent entries to return (default 20)." } }, "additionalProperties": false }), true),
        tool("alpha_watch", "A combined glance: current status plus the last 10 journal entries. Read-only.", no_args(), true),
        tool("alpha_author", "Author a NEW daemon-tier (native .so) creature from a natural-language request. Triggers a real cargo build and CAN TAKE MINUTES (the call blocks). Prefer alpha_author_critter. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": { "type": "string", "description": "What the creature should do, in plain language." } }, "required": ["request"], "additionalProperties": false }), false),
        tool("alpha_author_critter", "Author a NEW critter-tier (Rhai script) creature from a natural-language request. No compiler — returns in milliseconds. The preferred authoring path. Gated by allow-AI.", json!({ "type": "object", "properties": { "request": { "type": "string", "description": "What the critter should do, in plain language." } }, "required": ["request"], "additionalProperties": false }), false),
        tool("alpha_load", "Load a creature from a manifest + artifact already on the node's filesystem. Gated by allow-AI.", json!({ "type": "object", "properties": { "manifest_path": { "type": "string" }, "artifact_path": { "type": "string" } }, "required": ["manifest_path", "artifact_path"], "additionalProperties": false }), false),
        tool("alpha_send", "Send a text message to a creature by creature id and read its reply. Add `node` to route to a creature on a peer node over the cluster. Gated by allow-AI.", json!({ "type": "object", "properties": { "id": { "type": "integer" }, "text": { "type": "string" }, "node": { "type": "string", "description": "Optional peer node-id — routes the send across the cluster." } }, "required": ["id", "text"], "additionalProperties": false }), false),
        tool("alpha_intent", "Express an intent on a Role (outcome + text) and read the reply from whatever creature is bound there. Gated by allow-AI.", json!({ "type": "object", "properties": { "outcome": { "type": "string" }, "text": { "type": "string" } }, "required": ["outcome", "text"], "additionalProperties": false }), false),
        tool("alpha_bind", "Bind a loaded creature to a Role so intents addressed to that Role route to it. Gated by allow-AI.", json!({ "type": "object", "properties": { "role": { "type": "string" }, "id": { "type": "integer" } }, "required": ["role", "id"], "additionalProperties": false }), false),
        tool("alpha_unload", "Unload a creature by creature id (runs its orderly teardown). Gated by allow-AI.", json!({ "type": "object", "properties": { "id": { "type": "integer" } }, "required": ["id"], "additionalProperties": false }), false),
        tool("alpha_ai_status", "Announce what you (the AI) are doing on this shared node — surfaced live to the human at the node's REPL/stream so they can watch and revoke. Call it before a mutating action. Not gated.", json!({ "type": "object", "properties": { "working": { "type": "boolean" }, "activity": { "type": "string" }, "message": { "type": "string" } }, "required": ["working"], "additionalProperties": false }), false),
        tool("alpha_cluster", "Read this node's view of the cluster graph: which peer Sanctums it knows and which are connected. Read-only.", no_args(), true),
        tool("alpha_cluster_connect", "Admit + dial a cluster peer (the cluster join); gossip then spreads it across the mesh. Gated by allow-AI.", json!({ "type": "object", "properties": { "node_id": { "type": "string" }, "addr": { "type": "string" }, "pubkey": { "type": "string" } }, "required": ["node_id", "addr", "pubkey"], "additionalProperties": false }), false),
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
        return (true, json!({ "error": format!("unknown tool: {name}") }));
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

// ---- argument validation (mirrors the advertised inputSchema) ----------------------------------

#[derive(Clone, Copy)]
enum ArgType {
    String,
    U64,
    Bool,
}

impl ArgType {
    fn label(self) -> &'static str {
        match self {
            ArgType::String => "string",
            ArgType::U64 => "non-negative integer",
            ArgType::Bool => "boolean",
        }
    }
    fn matches(self, v: &Value) -> bool {
        match self {
            ArgType::String => v.is_string(),
            ArgType::U64 => v.as_u64().is_some(),
            ArgType::Bool => v.is_boolean(),
        }
    }
}

struct ArgSpec {
    name: &'static str,
    ty: ArgType,
    required: bool,
}

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
        "alpha_journal" => &[ArgSpec { name: "limit", ty: ArgType::U64, required: false }],
        "alpha_author" | "alpha_author_critter" => {
            &[ArgSpec { name: "request", ty: ArgType::String, required: true }]
        }
        "alpha_load" => &[
            ArgSpec { name: "manifest_path", ty: ArgType::String, required: true },
            ArgSpec { name: "artifact_path", ty: ArgType::String, required: true },
        ],
        "alpha_send" => &[
            ArgSpec { name: "id", ty: ArgType::U64, required: true },
            ArgSpec { name: "text", ty: ArgType::String, required: true },
            ArgSpec { name: "node", ty: ArgType::String, required: false },
        ],
        "alpha_intent" => &[
            ArgSpec { name: "outcome", ty: ArgType::String, required: true },
            ArgSpec { name: "text", ty: ArgType::String, required: true },
        ],
        "alpha_bind" => &[
            ArgSpec { name: "role", ty: ArgType::String, required: true },
            ArgSpec { name: "id", ty: ArgType::U64, required: true },
        ],
        "alpha_unload" => &[ArgSpec { name: "id", ty: ArgType::U64, required: true }],
        "alpha_cluster_connect" => &[
            ArgSpec { name: "node_id", ty: ArgType::String, required: true },
            ArgSpec { name: "addr", ty: ArgType::String, required: true },
            ArgSpec { name: "pubkey", ty: ArgType::String, required: true },
        ],
        "alpha_ai_status" => &[
            ArgSpec { name: "working", ty: ArgType::Bool, required: true },
            ArgSpec { name: "activity", ty: ArgType::String, required: false },
            ArgSpec { name: "message", ty: ArgType::String, required: false },
        ],
        _ => &[],
    }
}

fn validate_args(name: &str, args: &Value) -> Result<(), String> {
    let Some(obj) = args.as_object() else {
        return Err(format!("arguments for {name} must be a JSON object"));
    };
    let specs = arg_specs(name);
    for key in obj.keys() {
        if !specs.iter().any(|s| s.name == key) {
            return Err(format!("unknown parameter `{key}` for {name}"));
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
