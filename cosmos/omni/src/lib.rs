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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver, Intent, NodeId,
    Role, RouteError, Topic,
};
use anima::Artifact;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

use agent_templated::{AgentTemplated, AuthoringReply, AuthoringRequest};
use build_cargo::{BuildCargo, BuildConfig, BuildOp, BuildReply, Sandbox};
use build_critter::{BuildCritter, BuildCritterOp};
use monitor::Monitor;
use registry_mem::RegistryMem;
use transport_tcp::{TransportCtl, TransportCtlReply, CTL_SCHEMA};

use serde_json::{json, Value};

mod control;
pub use control::{
    ControlCore, ControlTarget, CONTROL_PROGRESS_SCHEMA, CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA,
};

/// The one-line command summary printed by the REPL banner and the `help` verb.
pub const COMMANDS: &str = "commands: author [--critter] <request> | load <manifest> <artifact> | send <[node-id:]id> <text> | intent <outcome> <text> | bind <role> <id> | unload <id> | allow-ai <on|off> | cluster [join <id@host:port#pubkey>] | list | status | journal | watch | help | quit";

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
            *g = AiStatus { working, activity, message };
        }
    }
    fn status_json(&self) -> Value {
        let s = self.status();
        json!({ "working": s.working, "activity": s.activity, "message": s.message })
    }
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
            ctx.ai.set_status(working, activity.clone(), message.clone());
            let human = if working {
                format!("[ai] {activity}: {message}")
            } else {
                "[ai] idle".to_string()
            };
            VerbResult::ok(json!({ "ok": true }), human)
        }
        Verb::Bind { role, id } => {
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
    let m_bytes = match std::fs::read(manifest_path) {
        Ok(b) => b,
        Err(e) => {
            return VerbResult::err(
                json!({ "ok": false, "error": format!("read manifest {manifest_path}: {e}") }),
                format!("load failed: read manifest {manifest_path}: {e}"),
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
    match ctx.kernel.load(m, Artifact::Path(artifact_path.into())) {
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
        Ok(Some(env)) => {
            let reply = String::from_utf8_lossy(&env.payload).to_string();
            VerbResult::ok(json!({ "reply": reply }), format!("reply: {reply}"))
        }
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
            Some(env) => {
                let reply = String::from_utf8_lossy(&env.payload).to_string();
                VerbResult::ok(json!({ "reply": reply }), format!("reply: {reply}"))
            }
            None => VerbResult::ok(json!({ "timeout": true }), "(no reply within 2s)"),
        },
        Err(e) => VerbResult::err(
            json!({ "unrouted": true, "error": e.to_string(), "hint": "bind a placement creature first (e.g. `bind distributor <id>`)" }),
            format!("intent unrouted: {e} — bind a placement creature first (e.g. `bind distributor <id>`)."),
        ),
    }
}

fn verb_author(ctx: &mut VerbCtx, request: &str, progress: &mut dyn FnMut(&str)) -> VerbResult {
    let Some((bus, rx)) = ctx.probe else { return no_probe_err() };
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
        Duration::from_secs(5),
    ) {
        Ok(Some(e)) => e,
        Ok(None) | Err(_) => {
            return author_err(
                "author failed: nothing bound to AUTHORING (running --minimal?)".into(),
            )
        }
    };
    let resp = match serde_json::from_slice::<AuthoringReply>(&env.payload) {
        Ok(AuthoringReply::Authored(r)) => r,
        Ok(AuthoringReply::Failed(e)) => return author_err(format!("authoring failed: {e:?}")),
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
    let (manifest, artifact) = match serde_json::from_slice::<BuildReply>(&env.payload) {
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
    // Nudge the templated agent toward its critter template (its matcher is keyword-based).
    let c1 = ctx.next_corr();
    let payload = match serde_json::to_vec(&AuthoringRequest {
        request: format!("{request} critter"),
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
        Duration::from_secs(5),
    ) {
        Ok(Some(e)) => e,
        Ok(None) | Err(_) => {
            return author_err(
                "author failed: nothing bound to AUTHORING (running --minimal?)".into(),
            )
        }
    };
    let resp = match serde_json::from_slice::<AuthoringReply>(&env.payload) {
        Ok(AuthoringReply::Authored(r)) => r,
        Ok(AuthoringReply::Failed(e)) => return author_err(format!("authoring failed: {e:?}")),
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
    let (manifest, artifact) = match serde_json::from_slice::<BuildReply>(&env.payload) {
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
        Ok(Some(_)) => VerbResult::ok(
            json!({ "ok": true, "joined": node_id, "addr": addr }),
            format!("admitted + dialing `{node_id}` ({addr}); gossip will spread it across the mesh. Run `cluster` to watch it converge."),
        ),
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

/// Self-host the substrate's own organs onto their Roles. Returns the `build-critter` organ's id:
/// `Role::BUILD` is single-binding (held by build-cargo for daemons), so `author --critter`
/// addresses the no-cargo critter builder directly by id.
pub fn boot_organs(kernel: &Kernel) -> Result<CreatureId, String> {
    boot_organs_with_monitor(kernel, true)
}

/// Variant used by non-interactive CLI modes: the monitor creature prints directly to stdout, so it
/// is omitted when stdout must remain machine-readable (`--json --exec` / `--json --script`).
pub fn boot_organs_with_monitor(
    kernel: &Kernel,
    attach_stdout_monitor: bool,
) -> Result<CreatureId, String> {
    let abode = Ed25519KeyMaterial::from_seed([7u8; 32]).map_err(|e| e.to_string())?;
    let author = abode.public_hex().to_string();

    let agent_id = kernel
        .load_instance(boot_manifest("agent-templated"), Box::new(AgentTemplated::new()))
        .map_err(|e| format!("agent: {e}"))?;
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
        let is_workspace = std::fs::read_to_string(dir.join("Cargo.toml"))
            .map(|c| c.lines().any(|l| l.trim() == "[workspace]"))
            .unwrap_or(false);
        if is_workspace {
            return dir.to_path_buf();
        }
    }
    // Fallback (e.g. a packaged single-crate build with no workspace manifest): two parents up,
    // which is `cosmos/omni` → root under the workspace layout.
    manifest_dir.parent().and_then(|p| p.parent()).map(PathBuf::from).unwrap_or(manifest_dir)
}

/// Open a fresh probe endpoint with default capabilities (the unrestricted `calls` gate a control
/// front-end needs to drive any role or creature).
pub fn open_probe(kernel: &Kernel) -> (CreatureId, BusHandle, InboxReceiver) {
    kernel.open_endpoint(Capabilities::default())
}
