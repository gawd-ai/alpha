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
        Query, State,
    },
    http::{header, StatusCode},
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
    Outcome,
};
pub use omni::ControlTarget;
use omni::{Verb, VerbResult, CONTROL_PROGRESS_SCHEMA, CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA};

/// Generous ceiling for a cold `author` (a real `cargo build` is tens of seconds to minutes); read
/// and quick-mutation verbs reply in milliseconds, well inside [`READ_TIMEOUT`].
const AUTHOR_TIMEOUT: Duration = Duration::from_secs(400);
/// Bound for every non-author verb's control round-trip. `ControlCore` always replies promptly
/// (reads inline, the worker emits a result), so this only bites if the control plane is gone.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

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
                                    let line = serde_json::from_slice::<Value>(&env.payload)
                                        .ok()
                                        .and_then(|v| {
                                            v.get("line")
                                                .and_then(|l| l.as_str())
                                                .map(str::to_string)
                                        })
                                        .unwrap_or_default();
                                    json!({ "kind": "progress", "line": line })
                                } else {
                                    json!({
                                        "kind": "sense",
                                        "from": format!("{:?}", env.header.from),
                                        "schema": env.header.schema,
                                        "seq": env.header.seq,
                                        "stamp": env.header.stamp,
                                        "payload": String::from_utf8_lossy(&env.payload),
                                    })
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
    let corr = st.corr.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = oneshot::channel::<VerbResult>();
    st.pending.lock().unwrap().insert(corr, tx);

    let payload = serde_json::to_vec(&verb).unwrap_or_default();
    let d = Dispatch::to(st.target.address(), payload)
        .with_schema(CONTROL_SCHEMA)
        .with_reply_to(Address::Creature(me))
        .with_corr(corr);
    if let Err(e) = bus.emit(d) {
        st.pending.lock().unwrap().remove(&corr);
        return VerbResult::err(
            json!({ "error": "control-unreachable", "detail": e.to_string() }),
            format!("control plane unreachable: {e}"),
        );
    }
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(res)) => res,
        _ => {
            st.pending.lock().unwrap().remove(&corr);
            VerbResult::err(
                json!({ "error": "control-timeout" }),
                "control plane did not reply in time",
            )
        }
    }
}

fn into_response(res: VerbResult) -> Response {
    let code = if res.ok {
        StatusCode::OK
    } else if res.is_gate_block() {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::BAD_REQUEST
    };
    (code, Json(res.json)).into_response()
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
        .route("/api/send", post(h_send))
        .route("/api/intent", post(h_intent))
        .route("/api/bind", post(h_bind))
        .route("/api/unload", post(h_unload))
        .route("/api/ai/status", post(h_ai_status))
        .route("/api/cluster", get(h_cluster))
        .route("/api/cluster/connect", post(h_cluster_connect))
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
    into_response(request_control(&st, Verb::Author { request: b.request }, AUTHOR_TIMEOUT).await)
}

async fn h_author_critter(
    State(st): State<Arc<SurfaceState>>,
    Json(b): Json<AuthorReq>,
) -> Response {
    into_response(
        request_control(&st, Verb::AuthorCritter { request: b.request }, AUTHOR_TIMEOUT).await,
    )
}

async fn h_load(State(st): State<Arc<SurfaceState>>, Json(b): Json<LoadReq>) -> Response {
    into_response(
        request_control(
            &st,
            Verb::Load { manifest_path: b.manifest_path, artifact_path: b.artifact_path },
            READ_TIMEOUT,
        )
        .await,
    )
}

async fn h_send(State(st): State<Arc<SurfaceState>>, Json(b): Json<SendReq>) -> Response {
    into_response(
        request_control(&st, Verb::Send { id: b.id, text: b.text, node: b.node }, READ_TIMEOUT)
            .await,
    )
}

async fn h_intent(State(st): State<Arc<SurfaceState>>, Json(b): Json<IntentReq>) -> Response {
    into_response(
        request_control(&st, Verb::Intent { outcome: b.outcome, text: b.text }, READ_TIMEOUT).await,
    )
}

async fn h_bind(State(st): State<Arc<SurfaceState>>, Json(b): Json<BindReq>) -> Response {
    into_response(request_control(&st, Verb::Bind { role: b.role, id: b.id }, READ_TIMEOUT).await)
}

async fn h_unload(State(st): State<Arc<SurfaceState>>, Json(b): Json<UnloadReq>) -> Response {
    into_response(request_control(&st, Verb::Unload { id: b.id }, READ_TIMEOUT).await)
}

/// The AI reports what it's doing (not allow-AI gated — the transparency channel). Surfaced live on
/// the stream and on the operator's stdout tape; then relayed to the control plane as a verb.
async fn h_ai_status(State(st): State<Arc<SurfaceState>>, Json(b): Json<AiStatusReq>) -> Response {
    let activity = sanitize_status(&b.activity);
    let message = sanitize_status(&b.message);
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

/// Strip control characters from caller-supplied status text and bound its length (safe to write to
/// a terminal; can't flood the operator's tape).
fn sanitize_status(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(512).collect()
}

async fn h_cluster(State(st): State<Arc<SurfaceState>>) -> Response {
    into_response(request_control(&st, Verb::Cluster, READ_TIMEOUT).await)
}

async fn h_cluster_connect(
    State(st): State<Arc<SurfaceState>>,
    Json(b): Json<ClusterConnectReq>,
) -> Response {
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
async fn h_ws(
    ws: WebSocketUpgrade,
    Query(q): Query<HashMap<String, String>>,
    State(st): State<Arc<SurfaceState>>,
) -> Response {
    let token = q.get("token").cloned().unwrap_or_default();
    if !constant_time_eq(token.as_bytes(), st.api_key.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    ws.on_upgrade(move |socket| handle_socket(socket, st))
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

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn api_key_compare_accepts_exact_match_only() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"Secret", b"secret"));
        assert!(!constant_time_eq(b"secret-extra", b"secret"));
        assert!(!constant_time_eq(b"sec", b"secret"));
        assert!(!constant_time_eq(b"", b"secret"));
    }
}
