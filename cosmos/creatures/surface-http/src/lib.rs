//! surface-http — a **loadable** HTTP-REST + WebSocket control surface.
//!
//! The HTTP server is not *the* control plane wired into the binary; it is one **creature** among
//! siblings. A node loads it only if it wants an HTTP surface, and can unload it to close the port —
//! "don't want the HTTP/WS surface? don't load it" — the same composability the MCP surface enjoys.
//!
//! It follows the `transport-tcp` surface shape: it owns its external boundary (an Axum/tokio
//! runtime + the bound listener) and tears it down cleanly on [`shutdown`](SurfaceHttp), so the port
//! is released and a re-load on the same port succeeds.
//!
//! It holds **no kernel**. Every handler maps its request to a [`Verb`], ships it as a `control_verb`
//! envelope to [`Role::CONTROL`](aether::Role::CONTROL) (local) or a peer node's control plane
//! (remote), and awaits the [`VerbResult`] reply — control is bus traffic. The allow-AI
//! gate and the verb logic live in `ControlCore`/`run_verb`; this surface only maps results to HTTP
//! status codes (`ok` → 200, the allow-AI refusal → 403, other failures → 400).
//!
//! Security posture: off unless loaded; one Bearer key (constant-time
//! compare); the allow-AI gate defaults off; TLS termination is left to a reverse proxy.

use std::collections::HashMap;
use std::future::IntoFuture;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Query, State,
    },
    http::{header, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{broadcast, oneshot};

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Outcome, RealmId,
};
pub use omni::ControlTarget;
use omni::{Verb, VerbResult, CONTROL_PROGRESS_SCHEMA, CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA};

/// Generous ceiling for a cold `author` (a real `cargo build` is tens of seconds to minutes); read
/// and quick-mutation verbs reply in milliseconds, well inside [`READ_TIMEOUT`].
const AUTHOR_TIMEOUT: Duration = Duration::from_secs(400);
/// Bound for every non-author verb's control round-trip. `ControlCore` always replies promptly
/// (reads inline, the worker emits a result), so this only bites if the control plane is gone.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// HTTP JSON request bodies are just another route into `control_verb`; cap them at the same size the
/// control core accepts so the surface cannot buffer unbounded input before the bus guard runs.
const MAX_HTTP_JSON_BODY_BYTES: usize = omni::MAX_CONTROL_VERB_BYTES;
/// Maximum bytes for HTTP text-like payload arguments before `Verb` construction.
const MAX_HTTP_TEXT_ARG_BYTES: usize = omni::MAX_CONTROL_VERB_BYTES;
/// Maximum bytes for an authoring request — the AUTHORING contract's own field cap, so the
/// surface refuses (and documents) exactly what the authoring bindees downstream would refuse.
const MAX_HTTP_AUTHOR_ARG_BYTES: usize = omni::MAX_CONTROL_AUTHOR_REQUEST_BYTES;
/// Maximum bytes for node-local path strings accepted by HTTP tools.
const MAX_HTTP_PATH_ARG_BYTES: usize = 4096;
/// Maximum bytes for artifact hashes accepted by HTTP tools.
const MAX_HTTP_HASH_ARG_BYTES: usize = 128;
/// Maximum bytes for Realm id strings accepted by HTTP tools.
const MAX_HTTP_REALM_ARG_BYTES: usize = 256;
/// Maximum bytes for peer node ids accepted by HTTP tools.
const MAX_HTTP_NODE_ARG_BYTES: usize = 256;
/// Maximum bytes for peer dial addresses accepted by HTTP tools.
const MAX_HTTP_ADDR_ARG_BYTES: usize = 512;
/// Maximum bytes for peer pubkeys accepted by HTTP tools.
const MAX_HTTP_PUBKEY_ARG_BYTES: usize = 128;
/// Maximum bytes for AI status text before the shared control layer sanitizes/truncates it further.
const MAX_HTTP_AI_STATUS_ARG_BYTES: usize = 4096;
/// Maximum raw query bytes accepted on protected HTTP routes before typed query extraction.
const MAX_HTTP_QUERY_BYTES: usize = 1024;
/// Maximum raw query bytes inspected on the unauthenticated WebSocket upgrade path.
const MAX_HTTP_WS_QUERY_BYTES: usize = 1024;
/// Maximum token bytes accepted from `/api/ws?token=...`.
const MAX_HTTP_WS_TOKEN_BYTES: usize = 256;
/// Maximum HTTP requests waiting on a `control_result` at once. The control core already bounds its
/// orchestration worker queue; this bounds the surface-side corr table too, so a burst of clients
/// cannot allocate one pending oneshot per request until timeouts drain.
const MAX_PENDING_CONTROL_REQUESTS: usize = 256;

/// A 64-hex-char API key from the OS CSPRNG. Printed once at boot when the operator supplies none.
pub fn generate_api_key() -> Result<String, String> {
    Ok(sigil::crypto::fresh_seed()?.iter().map(|b| format!("{b:02x}")).collect())
}

/// Shared between the surface's runtime (the HTTP handlers + WS) and its `handle` (the drain thread
/// that receives control replies + sense frames off the bus).
struct SurfaceState {
    /// The creature's bus authority (from `bind`), used by handlers to emit control envelopes.
    bus: Mutex<Option<Arc<dyn Bus>>>,
    /// This surface's own [`CreatureId`] — control replies are addressed back here (`reply_to`).
    me: Mutex<Option<CreatureId>>,
    /// The corr space for this surface's control round-trips. Each request takes the next value;
    /// the reply carries it back and `handle` matches it to the waiting handler.
    corr: AtomicU64,
    /// In-flight control requests: corr → the oneshot that wakes the awaiting HTTP handler.
    pending: Mutex<HashMap<u64, oneshot::Sender<VerbResult>>>,
    /// The live sense stream: `handle` republishes each subscribed sense/progress frame here; every
    /// `/api/ws` connection subscribes.
    stream_tx: broadcast::Sender<String>,
    api_key: String,
    target: ControlTarget,
    /// Fired by `shutdown` to stop the Axum server (drops the listener → frees the port).
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Set by `shutdown` so the sense-reader thread exits its `recv_timeout` loop and joins.
    stop: AtomicBool,
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
        tx: oneshot::Sender<VerbResult>,
    ) -> Result<(), VerbResult> {
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING_CONTROL_REQUESTS {
            return Err(surface_busy(pending.len()));
        }
        pending.insert(corr, tx);
        Ok(())
    }
    fn take_pending(&self, corr: u64) -> Option<oneshot::Sender<VerbResult>> {
        self.pending.lock().unwrap().remove(&corr)
    }
    fn remove_pending(&self, corr: u64) {
        self.pending.lock().unwrap().remove(&corr);
    }
}

/// The HTTP/WS control surface creature.
pub struct SurfaceHttp {
    /// Pre-bound by the loader so a port conflict surfaces synchronously before load; taken in
    /// `bind` and handed to the runtime.
    listener: Option<std::net::TcpListener>,
    /// A **dedicated, drain-less** sense endpoint (opened + subscribed to PROPRIOCEPTION/FITNESS/seer
    /// by the loader) read by a thread in `bind` and republished onto the WS stream. Kept off the
    /// creature's *own* inbox on purpose: that inbox carries control replies, and the sense topics
    /// are high-volume (a node with a monitor publishes fitness continuously) — multiplexing them
    /// would let a fitness burst shed a control reply under backpressure, and being a drain-less
    /// endpoint it never re-publishes fitness (no amplification, unlike a second subscribed creature).
    sense_rx: Option<InboxReceiver>,
    state: Arc<SurfaceState>,
    runtime_thread: Option<JoinHandle<()>>,
    sense_thread: Option<JoinHandle<()>>,
}

impl SurfaceHttp {
    /// Construct over an already-bound listener (the loader binds it so a port conflict is reported
    /// before the creature loads), a Bearer key, a control target, and the sense endpoint receiver
    /// (the loader opens + subscribes it). The listener is set non-blocking for
    /// `tokio::net::TcpListener::from_std`.
    pub fn new(
        listener: std::net::TcpListener,
        api_key: String,
        target: ControlTarget,
        sense_rx: InboxReceiver,
    ) -> std::io::Result<Self> {
        listener.set_nonblocking(true)?;
        let (stream_tx, _rx0) = broadcast::channel::<String>(1024);
        Ok(Self {
            listener: Some(listener),
            sense_rx: Some(sense_rx),
            state: Arc::new(SurfaceState {
                bus: Mutex::new(None),
                me: Mutex::new(None),
                corr: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                stream_tx,
                api_key,
                target,
                shutdown_tx: Mutex::new(None),
                stop: AtomicBool::new(false),
            }),
            runtime_thread: None,
            sense_thread: None,
        })
    }
}

impl Creature for SurfaceHttp {
    fn bind(&mut self, ctx: CreatureCtx) {
        *self.state.bus.lock().unwrap() = Some(ctx.bus);
        *self.state.me.lock().unwrap() = Some(ctx.me);

        // The sense-reader: drain the dedicated sense endpoint and republish onto the WS stream.
        // Drain-less (a bare endpoint, no kernel drain thread), so reading it never re-publishes a
        // fitness event — no storm amplification. Exits on `stop` (set by `shutdown`).
        if let Some(sense_rx) = self.sense_rx.take() {
            let state = self.state.clone();
            let th =
                std::thread::Builder::new().name("surface-http-sense".into()).spawn(move || {
                    while !state.stop.load(Ordering::Relaxed) {
                        match sense_rx.recv_timeout(Duration::from_millis(250)) {
                            Ok(env) => {
                                let frame = if env.header.schema == CONTROL_PROGRESS_SCHEMA {
                                    progress_frame(&env)
                                } else {
                                    sense_frame(&env)
                                };
                                let _ = state.stream_tx.send(frame.to_string());
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
            match th {
                Ok(h) => self.sense_thread = Some(h),
                Err(e) => eprintln!("surface-http: failed to spawn the sense-reader thread: {e}"),
            }
        }

        let Some(std_listener) = self.listener.take() else { return };
        let (sd_tx, sd_rx) = oneshot::channel::<()>();
        *self.state.shutdown_tx.lock().unwrap() = Some(sd_tx);

        let state = self.state.clone();
        let th = std::thread::Builder::new().name("surface-http".into()).spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("surface-http: could not build the tokio runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let listener = match tokio::net::TcpListener::from_std(std_listener) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("surface-http: listener setup failed: {e}");
                        return;
                    }
                };
                // Race the server against the shutdown signal: when `shutdown` fires `sd_tx`, the
                // select returns and the server future is dropped — closing the listener and every
                // open connection (including long-lived WS) at once, so the port is freed promptly.
                // (A drain-style graceful shutdown would hang on an open WS; we choose prompt close.)
                tokio::select! {
                    r = axum::serve(listener, router(state)).into_future() => {
                        if let Err(e) = r { eprintln!("surface-http: server error: {e}"); }
                    }
                    _ = sd_rx => {}
                }
            });
            // `rt` drops here → all runtime threads joined, the listener fd is closed, the port freed.
        });
        match th {
            Ok(h) => self.runtime_thread = Some(h),
            Err(e) => eprintln!("surface-http: failed to spawn the runtime thread: {e}"),
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // The creature's own inbox carries *only* control replies (it is not subscribed to any topic
        // — sense frames go to the dedicated endpoint). A reply wakes the HTTP handler on its corr.
        if env.header.schema == CONTROL_RESULT_SCHEMA {
            if let Some(corr) = env.header.corr {
                if let Some(tx) = self.state.take_pending(corr) {
                    let res = omni::parse_control_result(&env.payload)
                        .unwrap_or_else(omni::control_result_decode_failure);
                    let _ = tx.send(res);
                }
            }
        }
        Outcome::none()
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // Signal both workers to stop: the sense-reader exits its `recv_timeout` loop, and the Axum
        // server's select returns (dropping the listener → frees the port). Then join both so no
        // thread leaks at the kernel's post-shutdown tid snapshot.
        self.state.stop.store(true, Ordering::Relaxed);
        if let Some(tx) = self.state.shutdown_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
        if let Some(th) = self.runtime_thread.take() {
            let _ = th.join();
        }
        if let Some(th) = self.sense_thread.take() {
            let _ = th.join();
        }
    }
}

// ---- the async↔bus bridge ----------------------------------------------------------------------

/// Ship `verb` to the control plane and await its [`VerbResult`]. Allocates a corr, registers a
/// oneshot keyed by it, emits the `control_verb` envelope addressed to the target with `reply_to`
/// pointing back at this surface, and waits (bounded) for `handle` to deliver the reply.
async fn request_control(st: &Arc<SurfaceState>, verb: Verb, timeout: Duration) -> VerbResult {
    let (me, bus) = match (st.me(), st.bus()) {
        (Some(me), Some(bus)) => (me, bus),
        _ => {
            return VerbResult::err(
                json!({ "error": "surface-unbound" }),
                "internal: the control surface is not bound to the bus yet",
            )
        }
    };
    let payload = match omni::control_verb_payload(&verb) {
        Ok(payload) => payload,
        Err(res) => return res,
    };
    let corr = st.corr.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = oneshot::channel::<VerbResult>();
    if let Err(res) = st.register_pending(corr, tx) {
        return res;
    };
    let d = Dispatch::to(st.target.address(), payload)
        .with_schema(CONTROL_SCHEMA)
        .with_reply_to(Address::Creature(me))
        .with_corr(corr);
    if let Err(e) = bus.emit(d) {
        st.remove_pending(corr);
        return VerbResult::err(
            json!({ "error": "control-unreachable", "detail": e.to_string() }),
            format!("control plane unreachable: {e}"),
        );
    }
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(res)) => res,
        _ => {
            st.remove_pending(corr);
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
            "limit": MAX_PENDING_CONTROL_REQUESTS
        }),
        format!(
            "control surface busy: {pending} pending requests (limit {MAX_PENDING_CONTROL_REQUESTS})"
        ),
    )
}

fn into_response(res: VerbResult) -> Response {
    let code = if res.ok {
        StatusCode::OK
    } else if res.is_gate_block() {
        StatusCode::FORBIDDEN
    } else if res.json.get("error").and_then(Value::as_str) == Some("surface-busy") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    (code, Json(res.json)).into_response()
}

#[derive(Debug)]
struct HttpArgError {
    field: &'static str,
    len: usize,
    limit: usize,
}

fn bad_http_argument(err: HttpArgError) -> Response {
    let human =
        format!("parameter `{}` is {} bytes, exceeds {} byte limit", err.field, err.len, err.limit);
    into_response(VerbResult::err(
        json!({
            "error": "bad-http-argument",
            "field": err.field,
            "bytes": err.len,
            "limit": err.limit
        }),
        human,
    ))
}

macro_rules! reject_bad_http_arg {
    ($check:expr) => {
        if let Err(err) = $check {
            return bad_http_argument(err);
        }
    };
}

fn validate_http_arg(field: &'static str, value: &str, limit: usize) -> Result<(), HttpArgError> {
    if value.len() > limit {
        return Err(HttpArgError { field, len: value.len(), limit });
    }
    Ok(())
}

fn validate_http_opt_arg(
    field: &'static str,
    value: Option<&str>,
    limit: usize,
) -> Result<(), HttpArgError> {
    if let Some(value) = value {
        validate_http_arg(field, value, limit)?;
    }
    Ok(())
}

// ---- router / auth ------------------------------------------------------------------------------

fn router(state: Arc<SurfaceState>) -> Router {
    let protected = Router::new()
        .route("/api/status", get(h_status))
        .route("/api/creatures", get(h_creatures))
        .route("/api/journal", get(h_journal))
        .route("/api/author", post(h_author))
        .route("/api/author/critter", post(h_author_critter))
        .route("/api/load", post(h_load))
        // The catalogue verbs. Publish is a POST (mutating, allow-AI-gated by the control core);
        // fetch/list/prove are GET reads (Bearer-guarded, never allow-AI-gated).
        .route("/api/registry/publish", post(h_registry_publish))
        .route("/api/registry/fetch", get(h_registry_fetch))
        .route("/api/registry/list", get(h_registry_list))
        .route("/api/registry/fetch-load", post(h_registry_fetch_load))
        .route("/api/bestiary/prove", get(h_bestiary_prove))
        .route("/api/send", post(h_send))
        .route("/api/intent", post(h_intent))
        .route("/api/bind", post(h_bind))
        .route("/api/unload", post(h_unload))
        .route("/api/ai/status", post(h_ai_status))
        .route("/api/cluster", get(h_cluster))
        .route("/api/cluster/connect", post(h_cluster_connect))
        .layer(DefaultBodyLimit::max(MAX_HTTP_JSON_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key));
    let public = Router::new().route("/api/health", get(h_health)).route("/api/ws", get(h_ws));
    protected.merge(public).with_state(state)
}

/// Constant-time-ish key comparison for the configured key length.
fn constant_time_eq(candidate: &[u8], expected: &[u8]) -> bool {
    let mut acc = candidate.len() ^ expected.len();
    for (i, y) in expected.iter().enumerate() {
        let x = candidate.get(i).copied().unwrap_or(0);
        acc |= usize::from(x ^ y);
    }
    acc == 0
}

async fn require_api_key(
    State(state): State<Arc<SurfaceState>>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !http_query_len_is_valid(request.uri().query()) {
        return Err(StatusCode::URI_TOO_LONG);
    }
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    match token {
        Some(t) if constant_time_eq(t.as_bytes(), state.api_key.as_bytes()) => {
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn http_query_len_is_valid(query: Option<&str>) -> bool {
    match query {
        Some(query) => query.len() <= MAX_HTTP_QUERY_BYTES,
        None => true,
    }
}

// ---- request bodies / query --------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorReq {
    request: String,
}
#[derive(Deserialize)]
struct LoadReq {
    manifest_path: String,
    artifact_path: String,
}
#[derive(Deserialize)]
struct RegistryPublishReq {
    manifest_path: String,
    artifact_path: String,
    #[serde(default)]
    realm: Option<String>,
}
#[derive(Deserialize)]
struct RegistryFetchQ {
    artifact_hash: String,
    #[serde(default)]
    realm: Option<String>,
}
#[derive(Deserialize)]
struct RegistryListQ {
    #[serde(default)]
    realm: Option<String>,
}
#[derive(Deserialize)]
struct RegistryFetchLoadReq {
    artifact_hash: String,
    /// Omit for a local fetch; set with `registry_id` for a cross-node fetch over the cluster.
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    registry_id: Option<u64>,
    #[serde(default)]
    realm: Option<String>,
    #[serde(default)]
    chunk_size: Option<u32>,
}
#[derive(Deserialize)]
struct BestiaryProveQ {
    artifact_hash: String,
    realm: String,
}
#[derive(Deserialize)]
struct SendReq {
    id: u64,
    text: String,
    #[serde(default)]
    node: Option<String>,
}
#[derive(Deserialize)]
struct IntentReq {
    outcome: String,
    text: String,
}
#[derive(Deserialize)]
struct BindReq {
    role: String,
    id: u64,
}
#[derive(Deserialize)]
struct UnloadReq {
    id: u64,
}
#[derive(Deserialize)]
struct AiStatusReq {
    working: bool,
    #[serde(default)]
    activity: String,
    #[serde(default)]
    message: String,
}
#[derive(Deserialize)]
struct JournalQ {
    limit: Option<usize>,
}
#[derive(Deserialize)]
struct ClusterConnectReq {
    node_id: String,
    addr: String,
    pubkey: String,
}

// ---- handlers ----------------------------------------------------------------------------------

async fn h_health() -> impl IntoResponse {
    // This surface fronts an Alpha node (`alpha node`); the health identity names it `alpha`.
    Json(json!({ "ok": true, "name": "alpha", "version": env!("CARGO_PKG_VERSION") }))
}

async fn h_status(State(st): State<Arc<SurfaceState>>) -> Response {
    into_response(request_control(&st, Verb::Status, READ_TIMEOUT).await)
}

async fn h_creatures(State(st): State<Arc<SurfaceState>>) -> Response {
    into_response(request_control(&st, Verb::List, READ_TIMEOUT).await)
}

async fn h_journal(State(st): State<Arc<SurfaceState>>, Query(q): Query<JournalQ>) -> Response {
    into_response(
        request_control(&st, Verb::Journal { limit: q.limit.unwrap_or(20) }, READ_TIMEOUT).await,
    )
}

async fn h_author(State(st): State<Arc<SurfaceState>>, Json(b): Json<AuthorReq>) -> Response {
    reject_bad_http_arg!(validate_http_arg("request", &b.request, MAX_HTTP_AUTHOR_ARG_BYTES));
    into_response(request_control(&st, Verb::Author { request: b.request }, AUTHOR_TIMEOUT).await)
}

async fn h_author_critter(
    State(st): State<Arc<SurfaceState>>,
    Json(b): Json<AuthorReq>,
) -> Response {
    reject_bad_http_arg!(validate_http_arg("request", &b.request, MAX_HTTP_AUTHOR_ARG_BYTES));
    into_response(
        request_control(&st, Verb::AuthorCritter { request: b.request }, AUTHOR_TIMEOUT).await,
    )
}

async fn h_load(State(st): State<Arc<SurfaceState>>, Json(b): Json<LoadReq>) -> Response {
    reject_bad_http_arg!(validate_http_arg(
        "manifest_path",
        &b.manifest_path,
        MAX_HTTP_PATH_ARG_BYTES
    ));
    reject_bad_http_arg!(validate_http_arg(
        "artifact_path",
        &b.artifact_path,
        MAX_HTTP_PATH_ARG_BYTES
    ));
    into_response(
        request_control(
            &st,
            Verb::Load { manifest_path: b.manifest_path, artifact_path: b.artifact_path },
            READ_TIMEOUT,
        )
        .await,
    )
}

/// An optional Realm argument: a present, non-empty string → `Some(RealmId)`; absent or empty → `None`
/// (the local Realm). Mirrors `surface-mcp`'s `oarg_realm` so the two surfaces normalize identically —
/// an explicit `""` must not become `RegistryOp::*InRealm { realm: RealmId("") }` (a distinct, hidden
/// catalogue bucket) on one surface while collapsing to the local Realm on the other.
fn opt_realm(realm: Option<String>) -> Option<RealmId> {
    realm.filter(|s| !s.is_empty()).map(RealmId::new)
}

/// Publish a creature into the catalogue by NODE-LOCAL path (the same operator caveat as `/api/load`:
/// the manifest + artifact must already be on the node's filesystem; this is not a client upload).
async fn h_registry_publish(
    State(st): State<Arc<SurfaceState>>,
    Json(b): Json<RegistryPublishReq>,
) -> Response {
    reject_bad_http_arg!(validate_http_arg(
        "manifest_path",
        &b.manifest_path,
        MAX_HTTP_PATH_ARG_BYTES
    ));
    reject_bad_http_arg!(validate_http_arg(
        "artifact_path",
        &b.artifact_path,
        MAX_HTTP_PATH_ARG_BYTES
    ));
    reject_bad_http_arg!(validate_http_opt_arg(
        "realm",
        b.realm.as_deref(),
        MAX_HTTP_REALM_ARG_BYTES
    ));
    into_response(
        request_control(
            &st,
            Verb::RegistryPublish {
                manifest_path: b.manifest_path,
                artifact_path: b.artifact_path,
                realm: opt_realm(b.realm),
            },
            READ_TIMEOUT,
        )
        .await,
    )
}

async fn h_registry_fetch(
    State(st): State<Arc<SurfaceState>>,
    Query(q): Query<RegistryFetchQ>,
) -> Response {
    reject_bad_http_arg!(validate_http_arg(
        "artifact_hash",
        &q.artifact_hash,
        MAX_HTTP_HASH_ARG_BYTES
    ));
    reject_bad_http_arg!(validate_http_opt_arg(
        "realm",
        q.realm.as_deref(),
        MAX_HTTP_REALM_ARG_BYTES
    ));
    into_response(
        request_control(
            &st,
            Verb::RegistryFetch { artifact_hash: q.artifact_hash, realm: opt_realm(q.realm) },
            READ_TIMEOUT,
        )
        .await,
    )
}

/// Fetch a creature artifact over GX from a (possibly remote) registry, integrity-check it, and load
/// it into this node. Loads code → honors the allow-AI gate; a large transfer can run long, so it uses
/// the same generous budget as `author`.
async fn h_registry_fetch_load(
    State(st): State<Arc<SurfaceState>>,
    Json(b): Json<RegistryFetchLoadReq>,
) -> Response {
    reject_bad_http_arg!(validate_http_arg(
        "artifact_hash",
        &b.artifact_hash,
        MAX_HTTP_HASH_ARG_BYTES
    ));
    reject_bad_http_arg!(validate_http_opt_arg("node", b.node.as_deref(), MAX_HTTP_NODE_ARG_BYTES));
    reject_bad_http_arg!(validate_http_opt_arg(
        "realm",
        b.realm.as_deref(),
        MAX_HTTP_REALM_ARG_BYTES
    ));
    into_response(
        request_control(
            &st,
            Verb::FetchLoad {
                artifact_hash: b.artifact_hash,
                node: b.node,
                registry_id: b.registry_id,
                realm: opt_realm(b.realm),
                chunk_size: b.chunk_size,
            },
            AUTHOR_TIMEOUT,
        )
        .await,
    )
}

async fn h_registry_list(
    State(st): State<Arc<SurfaceState>>,
    Query(q): Query<RegistryListQ>,
) -> Response {
    reject_bad_http_arg!(validate_http_opt_arg(
        "realm",
        q.realm.as_deref(),
        MAX_HTTP_REALM_ARG_BYTES
    ));
    into_response(
        request_control(&st, Verb::RegistryList { realm: opt_realm(q.realm) }, READ_TIMEOUT).await,
    )
}

async fn h_bestiary_prove(
    State(st): State<Arc<SurfaceState>>,
    Query(q): Query<BestiaryProveQ>,
) -> Response {
    reject_bad_http_arg!(validate_http_arg(
        "artifact_hash",
        &q.artifact_hash,
        MAX_HTTP_HASH_ARG_BYTES
    ));
    reject_bad_http_arg!(validate_http_arg("realm", &q.realm, MAX_HTTP_REALM_ARG_BYTES));
    into_response(
        request_control(
            &st,
            Verb::BestiaryProve { artifact_hash: q.artifact_hash, realm: RealmId::new(q.realm) },
            READ_TIMEOUT,
        )
        .await,
    )
}

async fn h_send(State(st): State<Arc<SurfaceState>>, Json(b): Json<SendReq>) -> Response {
    reject_bad_http_arg!(validate_http_arg("text", &b.text, MAX_HTTP_TEXT_ARG_BYTES));
    reject_bad_http_arg!(validate_http_opt_arg("node", b.node.as_deref(), MAX_HTTP_NODE_ARG_BYTES));
    into_response(
        request_control(&st, Verb::Send { id: b.id, text: b.text, node: b.node }, READ_TIMEOUT)
            .await,
    )
}

async fn h_intent(State(st): State<Arc<SurfaceState>>, Json(b): Json<IntentReq>) -> Response {
    reject_bad_http_arg!(validate_http_arg(
        "outcome",
        &b.outcome,
        omni::MAX_CONTROL_ROLE_NAME_BYTES
    ));
    reject_bad_http_arg!(validate_http_arg("text", &b.text, MAX_HTTP_TEXT_ARG_BYTES));
    into_response(
        request_control(&st, Verb::Intent { outcome: b.outcome, text: b.text }, READ_TIMEOUT).await,
    )
}

async fn h_bind(State(st): State<Arc<SurfaceState>>, Json(b): Json<BindReq>) -> Response {
    reject_bad_http_arg!(validate_http_arg("role", &b.role, omni::MAX_CONTROL_ROLE_NAME_BYTES));
    into_response(request_control(&st, Verb::Bind { role: b.role, id: b.id }, READ_TIMEOUT).await)
}

async fn h_unload(State(st): State<Arc<SurfaceState>>, Json(b): Json<UnloadReq>) -> Response {
    into_response(request_control(&st, Verb::Unload { id: b.id }, READ_TIMEOUT).await)
}

/// The AI reports what it's doing (not allow-AI gated — the transparency channel). Surfaced live on
/// the stream and on the operator's stdout tape; then relayed to the control plane as a verb.
async fn h_ai_status(State(st): State<Arc<SurfaceState>>, Json(b): Json<AiStatusReq>) -> Response {
    reject_bad_http_arg!(validate_http_arg("activity", &b.activity, MAX_HTTP_AI_STATUS_ARG_BYTES));
    reject_bad_http_arg!(validate_http_arg("message", &b.message, MAX_HTTP_AI_STATUS_ARG_BYTES));
    let activity = omni::sanitize_ai_status_text(&b.activity);
    let message = omni::sanitize_ai_status_text(&b.message);
    let frame = json!({ "kind": "ai_status", "working": b.working, "activity": activity, "message": message });
    let _ = st.stream_tx.send(frame.to_string());
    if b.working {
        println!("[ai] {activity}: {message}");
    } else {
        println!("[ai] idle");
    }
    into_response(
        request_control(
            &st,
            Verb::AiStatus { working: b.working, activity, message },
            READ_TIMEOUT,
        )
        .await,
    )
}

async fn h_cluster(State(st): State<Arc<SurfaceState>>) -> Response {
    into_response(request_control(&st, Verb::Cluster, READ_TIMEOUT).await)
}

async fn h_cluster_connect(
    State(st): State<Arc<SurfaceState>>,
    Json(b): Json<ClusterConnectReq>,
) -> Response {
    reject_bad_http_arg!(validate_http_arg("node_id", &b.node_id, MAX_HTTP_NODE_ARG_BYTES));
    reject_bad_http_arg!(validate_http_arg("addr", &b.addr, MAX_HTTP_ADDR_ARG_BYTES));
    reject_bad_http_arg!(validate_http_arg("pubkey", &b.pubkey, MAX_HTTP_PUBKEY_ARG_BYTES));
    into_response(
        request_control(
            &st,
            Verb::ClusterJoin { node_id: b.node_id, addr: b.addr, pubkey: b.pubkey },
            READ_TIMEOUT,
        )
        .await,
    )
}

/// The live sense stream. Auth'd via `?token=` (browsers can't set Authorization on a WS upgrade).
async fn h_ws(ws: WebSocketUpgrade, uri: Uri, State(st): State<Arc<SurfaceState>>) -> Response {
    let token = ws_token_from_query(uri.query()).unwrap_or_default();
    if !constant_time_eq(token.as_bytes(), st.api_key.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, st))
}

fn ws_token_from_query(query: Option<&str>) -> Option<&str> {
    let query = query?;
    if query.len() > MAX_HTTP_WS_QUERY_BYTES {
        return None;
    }
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "token" && value.len() <= MAX_HTTP_WS_TOKEN_BYTES {
            return Some(value);
        }
    }
    None
}

async fn handle_socket(mut socket: WebSocket, st: Arc<SurfaceState>) {
    let mut rx = st.stream_tx.subscribe();
    let hello = json!({ "kind": "hello", "name": "alpha", "version": env!("CARGO_PKG_VERSION") });
    if socket.send(Message::Text(hello.to_string())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(s) => { if socket.send(Message::Text(s)).await.is_err() { break; } }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
            inc = socket.recv() => match inc {
                Some(Ok(_)) => {}
                _ => break,
            },
        }
    }
}

fn sense_frame(env: &Envelope) -> Value {
    let preview = omni::payload_preview(&env.payload);
    let mut frame = json!({
        "kind": "sense",
        "from": format!("{:?}", env.header.from),
        "schema": env.header.schema.clone(),
        "seq": env.header.seq,
        "stamp": env.header.stamp,
        "payload": preview.text,
        "payload_bytes": preview.bytes,
    });
    if preview.truncated {
        if let Some(obj) = frame.as_object_mut() {
            obj.insert("payload_truncated".to_string(), Value::Bool(true));
            obj.insert(
                "payload_limit".to_string(),
                Value::Number(serde_json::Number::from(preview.limit as u64)),
            );
        }
    }
    frame
}

fn progress_frame(env: &Envelope) -> Value {
    let progress = if env.payload.len() <= omni::MAX_PRESENTED_PAYLOAD_BYTES {
        serde_json::from_slice::<Value>(&env.payload).ok()
    } else {
        None
    };
    let line = progress
        .as_ref()
        .and_then(|v| v.get("line").and_then(|l| l.as_str()).map(str::to_string))
        .unwrap_or_default();
    let mut frame = json!({ "kind": "progress", "line": line });
    if let Some(corr) =
        progress.as_ref().and_then(|v| v.get("corr")).and_then(Value::as_u64).or(env.header.corr)
    {
        if let Some(obj) = frame.as_object_mut() {
            obj.insert("corr".to_string(), Value::Number(serde_json::Number::from(corr)));
        }
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Envelope, Header};
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use omni::MAX_PRESENTED_PAYLOAD_BYTES;

    fn test_state() -> Arc<SurfaceState> {
        let (stream_tx, _rx0) = broadcast::channel::<String>(1);
        Arc::new(SurfaceState {
            bus: Mutex::new(None),
            me: Mutex::new(None),
            corr: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            stream_tx,
            api_key: "test-key".to_string(),
            target: ControlTarget::Local,
            shutdown_tx: Mutex::new(None),
            stop: AtomicBool::new(false),
        })
    }

    #[test]
    fn opt_realm_normalizes_empty_to_none_matching_mcp() {
        // An absent or explicit-empty realm collapses to the local Realm (None); a real name passes
        // through. This is the cross-surface parity the review flagged (MCP's oarg_realm does the same).
        assert!(opt_realm(None).is_none(), "absent realm → None");
        assert!(
            opt_realm(Some(String::new())).is_none(),
            "explicit empty realm → None (not Some(\"\"))"
        );
        assert_eq!(opt_realm(Some("crew".into())).map(|r| r.0), Some("crew".to_string()));
    }

    #[test]
    fn api_key_compare_accepts_exact_match_only() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"Secret", b"secret"));
        assert!(!constant_time_eq(b"secret-extra", b"secret"));
        assert!(!constant_time_eq(b"sec", b"secret"));
        assert!(!constant_time_eq(b"", b"secret"));
    }

    #[test]
    fn websocket_token_query_scan_is_bounded() {
        assert_eq!(ws_token_from_query(Some("token=abc123")), Some("abc123"));
        assert_eq!(ws_token_from_query(Some("x=1&token=abc123&y=2")), Some("abc123"));
        assert_eq!(ws_token_from_query(None), None);
        assert_eq!(ws_token_from_query(Some(&"x".repeat(MAX_HTTP_WS_QUERY_BYTES + 1))), None);
        assert_eq!(
            ws_token_from_query(Some(&format!(
                "token={}",
                "x".repeat(MAX_HTTP_WS_TOKEN_BYTES + 1)
            ))),
            None
        );
    }

    #[test]
    fn protected_http_query_length_is_bounded() {
        assert!(http_query_len_is_valid(None));
        assert!(http_query_len_is_valid(Some(&"x".repeat(MAX_HTTP_QUERY_BYTES))));
        assert!(!http_query_len_is_valid(Some(&"x".repeat(MAX_HTTP_QUERY_BYTES + 1))));
    }

    #[test]
    fn pending_control_requests_are_bounded() {
        let st = test_state();
        let mut receivers = Vec::new();

        for corr in 0..MAX_PENDING_CONTROL_REQUESTS as u64 {
            let (tx, rx) = oneshot::channel();
            st.register_pending(corr, tx).expect("under cap");
            receivers.push(rx);
        }

        let (tx, _rx) = oneshot::channel();
        let err = st.register_pending(999_999, tx).expect_err("at cap refuses");
        assert_eq!(err.json["error"].as_str(), Some("surface-busy"));
        assert_eq!(err.json["limit"].as_u64(), Some(MAX_PENDING_CONTROL_REQUESTS as u64));
        assert_eq!(
            st.pending.lock().unwrap().len(),
            MAX_PENDING_CONTROL_REQUESTS,
            "refused request is not inserted"
        );

        let removed = st.take_pending(0).expect("existing corr is present");
        drop(removed);
        let (tx, rx) = oneshot::channel();
        st.register_pending(999_999, tx).expect("space reopens after a reply/timeout removes one");
        receivers.push(rx);
    }

    #[tokio::test]
    async fn surface_busy_maps_to_service_unavailable() {
        let response = into_response(surface_busy(MAX_PENDING_CONTROL_REQUESTS));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("surface-busy"));
    }

    #[tokio::test]
    async fn oversized_http_argument_maps_to_bounded_bad_request() {
        let too_long = "x".repeat(MAX_HTTP_HASH_ARG_BYTES + 1);
        let err = validate_http_arg("artifact_hash", &too_long, MAX_HTTP_HASH_ARG_BYTES)
            .expect_err("oversized hash is rejected");
        let response = bad_http_argument(err);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"].as_str(), Some("bad-http-argument"));
        assert_eq!(json["field"].as_str(), Some("artifact_hash"));
        assert_eq!(json["bytes"].as_u64(), Some((MAX_HTTP_HASH_ARG_BYTES + 1) as u64));
        assert_eq!(json["limit"].as_u64(), Some(MAX_HTTP_HASH_ARG_BYTES as u64));
    }

    #[test]
    fn sense_frame_truncates_large_payload_preview() {
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(1)),
                reply_to: None,
                seq: 3,
                causal: vec![],
                stamp: 9,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "fitness".to_string(),
                origin: None,
            },
            payload: vec![b'a'; MAX_PRESENTED_PAYLOAD_BYTES + 1],
        };
        let frame = sense_frame(&env);
        assert_eq!(frame["payload"].as_str().unwrap().len(), MAX_PRESENTED_PAYLOAD_BYTES);
        assert_eq!(frame["payload_bytes"].as_u64(), Some((MAX_PRESENTED_PAYLOAD_BYTES + 1) as u64));
        assert_eq!(frame["payload_truncated"].as_bool(), Some(true));
        assert_eq!(frame["payload_limit"].as_u64(), Some(MAX_PRESENTED_PAYLOAD_BYTES as u64));
    }

    #[test]
    fn progress_frame_drops_oversized_payload_before_json_decode() {
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(1)),
                reply_to: None,
                seq: 3,
                causal: vec![],
                stamp: 9,
                sig: String::new(),
                corr: Some(11),
                commitment: None,
                schema: omni::CONTROL_PROGRESS_SCHEMA.to_string(),
                origin: None,
            },
            payload: vec![b'{'; MAX_PRESENTED_PAYLOAD_BYTES + 1],
        };
        let frame = progress_frame(&env);
        assert_eq!(frame["kind"].as_str(), Some("progress"));
        assert_eq!(frame["line"].as_str(), Some(""));
        assert_eq!(
            frame["corr"].as_u64(),
            Some(11),
            "header corr is still usable when payload decode is skipped"
        );
    }

    #[test]
    fn progress_frame_extracts_line_and_corr_from_bounded_payload() {
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(1)),
                reply_to: None,
                seq: 3,
                causal: vec![],
                stamp: 9,
                sig: String::new(),
                corr: Some(11),
                commitment: None,
                schema: omni::CONTROL_PROGRESS_SCHEMA.to_string(),
                origin: None,
            },
            payload: serde_json::to_vec(&serde_json::json!({ "corr": 11, "line": "compiling" }))
                .unwrap(),
        };
        let frame = progress_frame(&env);
        assert_eq!(frame["kind"].as_str(), Some("progress"));
        assert_eq!(frame["line"].as_str(), Some("compiling"));
        assert_eq!(frame["corr"].as_u64(), Some(11));
    }
}
