//! `transport-tcp` — the real authenticated peer link, the swap-in for the `loopback-gateway`.
//!
//! Bound to `Role::TRANSPORT`, so the kernel routes every `Address::Node(_,_)` envelope here.
//! Authenticates each peer with a mutual ed25519 challenge-response handshake against a pre-shared
//! pubkey allowlist — no PKI, no TOFU. After the handshake, envelopes
//! travel as length-prefixed JSON (the same shape the loopback uses, so the wire format is one
//! step's worth of change, not a redesign).
//!
//! ### What this creature delivers
//!
//! - **R4 against reality.** Local-and-remote really *is* the same envelope: the round-trip goes
//!   through the OS network stack, not a `socketpair`. The serialization path the loopback
//!   exercises stays unchanged; the only new code is the auth + the peer table.
//! - **R5 against reality.** The handshake uses real ed25519 (`Ed25519KeyMaterial` /
//!   `Ed25519Verifier`), so an attacker who can't sign with a trusted peer's key can't establish
//!   a session. The transport-level trust gate stays distinct from the *manifest* trust gate
//!   (which the kernel's admission policy enforces): one proves the peer; the other proves the
//!   artifact's authorship + integrity.
//!
//! ### What this creature deliberately does *not* do (named, not pretended)
//!
//! - **No payload encryption.** "Authenticated channel" is the promise; encryption is part of
//!   the capability/sandbox story.
//! - **No cross-node identity preservation at the bus level.** When an envelope arrives from a
//!   peer, the local re-route reseals `from` to the transport creature's own `CreatureId`. The
//!   original sender's identity rides in the preserved `reply_to` (rewritten to
//!   `Address::Node(peer, sender_mid)` so the eventual reply finds its way back). This is the
//!   correct shape — `from`-preservation across hops is cross-node-membership work.
//! - **Discovery: static by default, gossip in cluster mode.** With the bare constructor
//!   the peer table is seeded at construction and grows at runtime *only* via the explicit `Connect`
//!   control op (operator-driven admission). [`TransportTcp::with_gossip`] turns on **member gossip**:
//!   the allowlist (`peers_by_pubkey`) then *also* grows from member sets gossiped by any connected
//!   peer (transitive trust). Membership is **not signed** — a compromised member can gossip a bogus
//!   member; the first admission is gated (the control op) but propagation is not. Signed membership
//!   + a UDP/mDNS discovery beacon are the named next steps.
//! - **No per-connection retry policy beyond "dialer reconnects on drop."** Bounded retry with
//!   backoff arrives when the substrate needs it.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Outcome,
    Topic, KERNEL_ID,
};
use serde::{Deserialize, Serialize};
use sigil::{
    crypto::{hex_decode, hex_encode},
    Ed25519KeyMaterial, Ed25519Verifier, Verifier,
};

/// Domain separator for the handshake signature. Prevents a peer's handshake signature from being
/// reusable in any other ed25519 context the substrate might use (e.g. manifest provenance).
const HANDSHAKE_DOMAIN: &[u8] = b"GAWD-NODE-AUTH-v1:";
const PUBKEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const SIG_BYTES: usize = 64;

/// Per-connection per-side polling cadence — the read/recv timeout that lets a worker thread
/// notice a shutdown request without ever blocking indefinitely. Short enough that an unload
/// returns within human timescales; long enough that the syscall churn is negligible.
const POLL: Duration = Duration::from_millis(200);

/// Per-peer outbound queue depth. Backpressure here is "we're not draining the peer fast enough"
/// — bounded queue + `try_send` shedding keeps memory bounded under a sender flood (R9).
const PEER_QUEUE_DEPTH: usize = 1024;

/// Per-frame cap. See the reader for rationale.
const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;

/// Cap on members grafted from a single gossip frame (R9). Far above any real cluster's
/// membership — a bound on dialer threads one message can spawn, not a topology limit.
const MAX_GOSSIP_MEMBERS: usize = 1024;
/// Default cap on the accumulated dynamic member table. One slot is reserved for `self` in gossip
/// frames, so a full default member table still fits under `MAX_GOSSIP_MEMBERS`. `0` in
/// [`TransportTcp::with_max_members`] is the explicit unbounded lab/demo opt-out.
pub const DEFAULT_MAX_MEMBERS: usize = MAX_GOSSIP_MEMBERS - 1;

/// Poison-tolerant `Mutex` acquisition (R9). Every worker thread in this creature runs OUTSIDE the
/// kernel drain's `catch_unwind`, so a panic while one holds a `TransportState` lock would poison it
/// and wedge every other peer thread on the next acquire. Recovering the guard is sound — each lock
/// guards a plain map / Vec / Option with no half-broken invariant. (Mirrors `sanctum::mlock`.)
#[inline]
fn mlock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// One known peer.
#[derive(Clone, Debug)]
pub struct PeerConfig {
    /// The peer's NodeId (the substrate-level identity, distinct from any ed25519 key).
    pub node_id: NodeId,
    /// The peer's hex-encoded ed25519 public key — what we authenticate against in the handshake.
    pub pubkey_hex: String,
    /// `Some("host:port")` to dial this peer actively; `None` to wait for them to dial us.
    /// Both sides usually configure dial (both nodes are alive at boot); the substrate
    /// idempotently uses whichever connection establishes first.
    pub dial_addr: Option<String>,
}

/// Construction config — what an operator wires up before `load_instance`.
pub struct TransportConfig {
    pub self_key: Ed25519KeyMaterial,
    pub self_node: NodeId,
    /// `host:port` for the listener (e.g. `127.0.0.1:9001`).
    pub listen_addr: String,
    /// Initial peers / seeds. Peers with a `dial_addr` seed the dynamic member set (the bootstrap
    /// addresses a joining node is handed); peers without are passive entries in the allowlist.
    pub peers: Vec<PeerConfig>,
}

/// Cross-node membership signal — published on the local proprioception topic when a peer link
/// comes up or goes down. The first step of the cross-node membership story; a future bridge can
/// forward subscribers' interest across.
#[derive(Serialize, Deserialize, Debug)]
pub struct PeerEvent {
    pub peer: String,  // NodeId
    pub event: String, // "peer_connected" | "peer_disconnected" | "peer_auth_failed"
}

// ---- cluster membership types -------------------------------------------------------------------

/// A known cluster member (internal): how to reach + authenticate a peer.
#[derive(Clone, Debug)]
struct MemberInfo {
    pubkey_hex: String,
    addr: String,
}

/// One member as gossiped on the wire.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct GossipMember {
    node_id: String,
    pubkey_hex: String,
    addr: String,
}

/// One wire frame on a peer connection: a routed envelope or a membership-gossip push. Gossip rides
/// the same authenticated socket, so membership needs no cross-node module addressing.
#[derive(Serialize, Deserialize)]
#[serde(tag = "f", rename_all = "snake_case")]
enum WireFrame {
    Env(Box<Envelope>),
    Gossip { members: Vec<GossipMember> },
}
impl WireFrame {
    fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    fn parse(bytes: &[u8]) -> Option<Self> {
        let frame: Self = serde_json::from_slice(bytes).ok()?;
        // Reject (don't silently truncate) a gossip frame that exceeds the member cap, so
        // MAX_GOSSIP_MEMBERS is a hard ceiling on everything downstream — member grafting AND dialer
        // spawns — not merely on the graft loop. The transient decode is still bounded by the global
        // per-frame byte cap; an over-cap frame from a (necessarily authenticated) peer is dropped
        // whole and signalled, rather than partially applied. A well-behaved peer never sends more.
        if let WireFrame::Gossip { members } = &frame {
            if members.len() > MAX_GOSSIP_MEMBERS {
                eprintln!(
                    "transport-tcp: rejecting gossip frame with {} members (cap {MAX_GOSSIP_MEMBERS})",
                    members.len()
                );
                return None;
            }
        }
        Some(frame)
    }
}

/// Schema of the cluster control op an operator/front-end sends to admit a peer or read the graph.
pub const CTL_SCHEMA: &str = "transport.ctl";

/// Cluster control op (schema [`CTL_SCHEMA`]). Recognized in `handle()` by schema, address-agnostic.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TransportCtl {
    /// Admit + dial a peer — the operator/AI-gated cluster join. Idempotent.
    Connect { node_id: String, pubkey_hex: String, addr: String },
    /// Ask this node for its view of the cluster graph.
    Members,
}
impl TransportCtl {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// Reply to a [`TransportCtl`] op.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum TransportCtlReply {
    Connecting { node_id: String },
    Rejected { reason: String },
    Members { self_node: String, members: Vec<MemberView> },
}
impl TransportCtlReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// One node in the cluster graph, as reported by [`TransportCtl::Members`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberView {
    pub node_id: String,
    pub addr: String,
    pub connected: bool,
}

/// The transport creature.
pub struct TransportTcp {
    cfg: TransportConfig,
    state: Arc<TransportState>,
}

struct TransportState {
    self_key: Ed25519KeyMaterial,
    self_pubkey_hex: String,
    self_node: NodeId,
    listen_addr: String,
    /// Pubkey-hex → NodeId allowlist consulted during the inbound handshake. Mutable: the
    /// `Connect` control op + gossip admit peers at runtime. The handshake still authenticates
    /// strictly against whatever is in here at that instant.
    peers_by_pubkey: Mutex<HashMap<String, NodeId>>,
    /// Known cluster members: NodeId → (pubkey, dial addr). Seeded from config, grown by gossip / the
    /// `Connect` control op. Source for gossip payloads + the `Members` graph query.
    members: Mutex<HashMap<NodeId, MemberInfo>>,
    /// Maximum accumulated members retained at once. Existing members can be updated at capacity;
    /// new members are refused. `0` means unbounded.
    max_members: AtomicUsize,
    /// NodeIds we already spawned a persistent dialer for — prevents duplicate dialer threads when a
    /// peer is learned more than once (config + gossip + re-introduction).
    dialing: Mutex<HashSet<NodeId>>,
    /// Cluster mode: gossip membership + auto-dial learned members. Off by default; flipped on by
    /// [`TransportTcp::with_gossip`], so the classic static transport (every existing cross-node use)
    /// is byte-for-byte unchanged.
    gossip: AtomicBool,
    /// The dial address advertised to peers in gossip (defaults to listen_addr).
    advertise_addr: Mutex<String>,
    /// NodeId → outbound queue. `handle(Node(peer, _))` pushes here; the per-peer writer thread
    /// drains. Wrapped in Mutex because connect/disconnect rewrites it.
    writers: Mutex<HashMap<NodeId, SyncSender<Vec<u8>>>>,
    /// Open sockets, by peer NodeId — kept so shutdown can call `Shutdown::Both` on each to
    /// unblock any reader that's mid-`read`. Multiple connections per peer may exist briefly during
    /// re-dial; the Vec covers that race.
    sockets: Mutex<HashMap<NodeId, Vec<TcpStream>>>,
    bus: Mutex<Option<Arc<dyn Bus>>>,
    me: Mutex<Option<CreatureId>>,
    stop: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl TransportTcp {
    pub fn new(cfg: TransportConfig) -> Self {
        let self_pubkey_hex = cfg.self_key.public_hex().to_string();
        let self_node = cfg.self_node.clone();
        let listen_addr = cfg.listen_addr.clone();
        let peers_by_pubkey: HashMap<String, NodeId> =
            cfg.peers.iter().map(|p| (p.pubkey_hex.clone(), p.node_id.clone())).collect();
        // Seed the member set from configured peers that advertise a dial address (the seeds): a node
        // can dial + gossip those even before it has learned anyone else.
        let members: HashMap<NodeId, MemberInfo> = cfg
            .peers
            .iter()
            .filter_map(|p| {
                p.dial_addr.clone().map(|addr| {
                    (p.node_id.clone(), MemberInfo { pubkey_hex: p.pubkey_hex.clone(), addr })
                })
            })
            .collect();
        let state = Arc::new(TransportState {
            self_key: cfg.self_key.clone(),
            self_pubkey_hex,
            self_node,
            advertise_addr: Mutex::new(listen_addr.clone()),
            listen_addr,
            peers_by_pubkey: Mutex::new(peers_by_pubkey),
            members: Mutex::new(members),
            max_members: AtomicUsize::new(DEFAULT_MAX_MEMBERS),
            dialing: Mutex::new(HashSet::new()),
            gossip: AtomicBool::new(false),
            writers: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            bus: Mutex::new(None),
            me: Mutex::new(None),
            stop: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        });
        TransportTcp { cfg, state }
    }

    /// Enable **cluster mode**: gossip this node's member view to peers on connect and
    /// auto-dial any member it learns, so a many-to-many mesh self-completes from one seed.
    /// `advertise_addr` is the address peers should dial to reach this node (defaults to the listen
    /// address). Without this call the transport is the classic static peer link.
    pub fn with_gossip(self, advertise_addr: Option<String>) -> Self {
        self.state.gossip.store(true, Ordering::Relaxed);
        if let Some(a) = advertise_addr {
            *mlock(&self.state.advertise_addr) = a;
        }
        self
    }

    /// Cap the accumulated dynamic member table. `0` disables the cap. At capacity a new member from
    /// `transport.ctl` or gossip is refused; already-known members can still be updated.
    pub fn with_max_members(self, max_members: usize) -> Self {
        self.state.max_members.store(max_members, Ordering::Relaxed);
        self
    }
}

impl Creature for TransportTcp {
    fn bind(&mut self, ctx: CreatureCtx) {
        *mlock(&self.state.bus) = Some(ctx.bus);
        *mlock(&self.state.me) = Some(ctx.me);

        // Spawn the listener. Binding the socket inside `bind` (not at construction time) lets
        // construction be infallible and lets the operator decide who owns the port — if the bind
        // fails, the transport publishes nothing and `handle` becomes a quiet no-op (proprio shows
        // no `peer_connected`); operators see the symptom without the kernel crashing.
        match TcpListener::bind(&self.state.listen_addr) {
            Ok(listener) => {
                let state = self.state.clone();
                match Builder::new()
                    .name(format!("transport-listener-{}", self.state.self_node.0))
                    .spawn(move || listener_loop(state, listener))
                {
                    Ok(h) => mlock(&self.state.threads).push(h),
                    Err(e) => {
                        eprintln!(
                            "transport-tcp: failed to spawn listener thread for {}: {e}",
                            self.state.listen_addr
                        );
                        publish_peer_event(
                            &self.state,
                            &NodeId(format!("listen://{}", self.state.listen_addr)),
                            "listener_spawn_failed",
                        );
                    }
                }
            }
            Err(e) => {
                // Bind failure makes the node deaf to ALL inbound peers — a node-level fault. The
                // proprio event below only reaches a subscriber that exists and isn't shedding; also
                // log directly so a headless `alpha node` surfaces it.
                eprintln!(
                    "transport-tcp: failed to bind listener {}: {e} — node is deaf to inbound peers",
                    self.state.listen_addr
                );
                publish_peer_event(
                    &self.state,
                    &NodeId(format!("listen://{}", self.state.listen_addr)),
                    &format!("listener_bind_failed:{e}"),
                );
            }
        }

        // Dial each known peer that advertises a dial address.
        for peer in self.cfg.peers.iter().cloned() {
            spawn_dialer(&self.state, peer);
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Cluster control ops are schema-keyed and address-agnostic (admit/dial a peer, or report the
        // graph) — handle them before the Node-routing path.
        if env.header.schema == CTL_SCHEMA {
            return handle_ctl(&self.state, &env);
        }
        // We only handle Node-addressed envelopes (the router only delivers those here anyway).
        let Address::Node(peer_node, _target_mid) = &env.header.to else {
            return Outcome::none();
        };
        let peer_node = peer_node.clone();
        // Frame the envelope (WireFrame::Env) so membership-gossip frames can share the channel.
        // Look up the writer for that peer; if no connection yet, drop. We could buffer, but
        // buffering without bounds is the seed's R9 footgun; bounded buffering belongs to a
        // higher-level "queue at the source until peer is up" policy a creature can choose to
        // implement on top. The transport itself is honest about delivering only what it can
        // deliver right now.
        let bytes = WireFrame::Env(Box::new(env)).to_bytes();
        // Resolve + try_send under the writers guard, then DROP it before any publish (publish takes
        // state.bus — holding two state locks across a publish widens the poison/deadlock window).
        let disposition = {
            let writers = mlock(&self.state.writers);
            match writers.get(&peer_node) {
                Some(tx) => tx.try_send(bytes).err().map(|e| match e {
                    TrySendError::Full(_) => "peer_send_dropped:backpressure",
                    TrySendError::Disconnected(_) => "peer_send_dropped:no_link",
                }),
                None => Some("peer_send_dropped:no_link"),
            }
        };
        // Keep best-effort delivery (no buffering — bounded buffering is a higher-level policy a
        // creature can layer on; R9), but make a drop *discoverable*: an outbound cross-node frame
        // silently vanishing was invisible end-to-end (the bus already returned Ok to the sender).
        if let Some(event) = disposition {
            publish_peer_event(&self.state, &peer_node, event);
        }
        Outcome::none()
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // The kernel-driven discipline: signal stop, unblock blocking syscalls, join all threads so
        // the tid guard sees no leaked threads at the post-shutdown snapshot. `_deadline` is
        // best-effort here: run-phase workers exit within ~POLL of `stop`, but a thread caught
        // mid-handshake exits within its own ~5s read/write timeout — we favor a clean join (no leaked
        // tids) over a hard deadline, since a stray handshake exactly at shutdown is rare and bounded.
        self.state.stop.store(true, Ordering::Relaxed);

        // Unblock the listener's `accept` by connecting to it once. Best-effort; if it fails the
        // listener will eventually still notice via `set_nonblocking` fallback (we don't set that
        // by default — the connect-self trick is enough).
        let _ = TcpStream::connect(&self.state.listen_addr);

        // Slam every open peer socket so any reader/writer mid-syscall returns.
        {
            let mut socks = mlock(&self.state.sockets);
            for (_, streams) in socks.drain() {
                for s in streams {
                    let _ = s.shutdown(Shutdown::Both);
                }
            }
        }

        // Disconnect every per-peer outbound queue so writer threads exit their `recv_timeout`.
        mlock(&self.state.writers).clear();

        // Join all spawned threads. Each respects `state.stop` + the timeouts above, so they exit
        // within ~POLL of the signal. In cluster mode a dialer mid-handshake (or the listener
        // accepting the connect-self) can install reader/writer/handshake threads *after* a drain — but
        // a worker only pushes children before it returns, so joining a batch guarantees its children
        // are already in `threads` for the next pass. Drain+join until a pass comes back empty (stop is
        // set, so the spawn chain is finite and this converges in a few passes); the cap is only a
        // non-termination backstop, NOT a normal exit. The drain releases the lock before each join —
        // the exiting workers don't touch `threads`, so there's no join-vs-deregister deadlock.
        let mut passes = 0;
        loop {
            let batch: Vec<JoinHandle<()>> = mlock(&self.state.threads).drain(..).collect();
            if batch.is_empty() {
                break;
            }
            for h in batch {
                let _ = h.join();
            }
            passes += 1;
            if passes >= 1024 {
                eprintln!(
                    "transport-tcp: shutdown thread-drain did not converge after {passes} passes"
                );
                break;
            }
        }
    }
}

// ---- listener / dialer ----

fn listener_loop(state: Arc<TransportState>, listener: TcpListener) {
    // Non-blocking accept so we can poll `state.stop` between iterations without needing a
    // wake-up trick. The cost is a tiny per-loop `sleep`; the win is no race with shutdown.
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !state.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let state_h = state.clone();
                let h = match Builder::new()
                    .name("transport-handshake-server".into())
                    .spawn(move || server_handshake_and_run(state_h, stream))
                {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("transport-tcp: failed to spawn inbound handshake thread: {e}");
                        continue;
                    }
                };
                // Track the handshake thread alongside the connection workers — shutdown joins all.
                // Reap finished handles first so this Vec doesn't grow unbounded under connection
                // churn / a hostile scanner: without reaping, each accepted connection leaves a
                // dead handle here for the node's whole life (and makes shutdown's join
                // O(connections-ever)). `is_finished` + dropping a done handle is non-blocking. (T4)
                let mut threads = mlock(&state.threads);
                threads.retain(|h| !h.is_finished());
                threads.push(h);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL);
            }
            Err(_) => break,
        }
    }
}

fn dialer_loop(state: Arc<TransportState>, peer: PeerConfig) {
    // Release this peer's `dialing` reservation (taken in `spawn_dialer`) on EVERY exit path — clean
    // shutdown, bad address, or any future early return — via Drop. The `dialing` set then stays a
    // truthful "a dialer currently exists for this peer" invariant: a peer whose dialer has exited can
    // always be re-introduced and re-dialed later. Clearing it only on the error paths would couple
    // correctness to process shutdown being the one clean exit — a fragility this avoids.
    struct DialingGuard {
        state: Arc<TransportState>,
        node_id: NodeId,
    }
    impl Drop for DialingGuard {
        fn drop(&mut self) {
            mlock(&self.state.dialing).remove(&self.node_id);
        }
    }
    let _dialing = DialingGuard { state: state.clone(), node_id: peer.node_id.clone() };

    let Some(addr) = peer.dial_addr.clone() else {
        return;
    };
    // Parse the dial address ONCE. Re-parsing it every loop was wasteful; worse, an unparseable
    // address silently `return`ed and ended ALL reconnects to this peer with zero signal — a
    // fail-fast config error vanishing. Surface it and stop this dialer cleanly. (T9)
    let sockaddr: std::net::SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "transport-tcp: peer {} has an invalid dial address {addr:?}: {e}; not dialing it",
                peer.node_id.0
            );
            publish_peer_event(&state, &peer.node_id, "peer_dial_addr_invalid");
            // The `dialing` reservation is freed by `_dialing`'s Drop on this return, so a later
            // Connect/gossip carrying a corrected address can spawn a fresh dialer for this peer.
            return;
        }
    };
    // Retry while the substrate is up. Backoff bounded between 100ms and 1s — generous enough to
    // not hammer a stranger; tight enough that the first `connect` after a peer boots succeeds
    // quickly. A real production policy is operator-injected.
    //
    // **Single-connection discipline.** Once a connection is established (writer is in the
    // `writers` map), the dialer idles until the reader removes that writer on disconnect — then
    // it dials again. Without this gate the dialer would loop on `connect_timeout → install
    // → return → connect_timeout` immediately, each new connection's `install_connection` would
    // replace the existing writer (dropping the SyncSender), the old writer thread would see
    // `Disconnected` and `shutdown(Shutdown::Both)` the stream, the peer would see EOF and tear
    // its side down — a "connection thrashing" loop that never delivers a frame.
    let mut backoff = Duration::from_millis(100);
    while !state.stop.load(Ordering::Relaxed) {
        // Already connected? Just idle and re-check — the reader removes our entry on disconnect.
        if mlock(&state.writers).contains_key(&peer.node_id) {
            std::thread::sleep(POLL);
            backoff = Duration::from_millis(100);
            continue;
        }
        match TcpStream::connect_timeout(&sockaddr, POLL) {
            Ok(stream) => {
                client_handshake_and_run(state.clone(), stream, &peer);
                backoff = Duration::from_millis(100);
            }
            Err(_) => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(1));
            }
        }
    }
}

// ---- handshake ----

fn server_handshake_and_run(state: Arc<TransportState>, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let server_pubkey_bytes = match hex_decode(&state.self_pubkey_hex) {
        Some(b) if b.len() == PUBKEY_BYTES => b,
        _ => return,
    };
    let Some(server_nonce) = fresh_nonce() else {
        // OS RNG unavailable — abort rather than handshake with a weak nonce. The peer is not yet
        // identified at this step, so there is no specific peer event to publish.
        return;
    };

    // Step 1: server sends pubkey + nonce.
    if stream.write_all(&server_pubkey_bytes).is_err() || stream.write_all(&server_nonce).is_err() {
        return;
    }
    // Step 2: read client pubkey + nonce.
    let mut client_pubkey = [0u8; PUBKEY_BYTES];
    let mut client_nonce = [0u8; NONCE_BYTES];
    if stream.read_exact(&mut client_pubkey).is_err()
        || stream.read_exact(&mut client_nonce).is_err()
    {
        return;
    }
    let client_pubkey_hex = hex_encode(&client_pubkey);
    let Some(client_node) = mlock(&state.peers_by_pubkey).get(&client_pubkey_hex).cloned() else {
        publish_peer_event(
            &state,
            &NodeId(client_pubkey_hex.clone()),
            "peer_auth_failed:unknown_pubkey",
        );
        return;
    };

    // Step 3: server signs transcript binding (client_nonce, client_pk, server_pk).
    let server_sig = state.self_key.sign(&handshake_transcript(
        &client_nonce,
        &client_pubkey,
        &server_pubkey_bytes,
    ));
    let server_sig_bytes = match hex_decode(&server_sig) {
        Some(b) if b.len() == SIG_BYTES => b,
        _ => return,
    };
    if stream.write_all(&server_sig_bytes).is_err() {
        return;
    }
    // Step 4: read client sig, verify.
    let mut client_sig = [0u8; SIG_BYTES];
    if stream.read_exact(&mut client_sig).is_err() {
        return;
    }
    let v = Ed25519Verifier;
    let expected = handshake_transcript(&server_nonce, &server_pubkey_bytes, &client_pubkey);
    if !v.verify(&client_pubkey_hex, &expected, &hex_encode(&client_sig)) {
        publish_peer_event(&state, &client_node, "peer_auth_failed:bad_sig");
        return;
    }

    // Authenticated. Hand the stream off to the per-peer reader/writer pair.
    install_connection(state, stream, client_node);
}

fn client_handshake_and_run(state: Arc<TransportState>, mut stream: TcpStream, peer: &PeerConfig) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let client_pubkey_bytes = match hex_decode(&state.self_pubkey_hex) {
        Some(b) if b.len() == PUBKEY_BYTES => b,
        _ => return,
    };
    let Some(client_nonce) = fresh_nonce() else {
        // OS RNG unavailable — abort rather than handshake with a weak nonce. We know the peer here.
        publish_peer_event(&state, &peer.node_id, "peer_auth_failed:rng");
        return;
    };

    // Step 1: read server pubkey + nonce.
    let mut server_pubkey = [0u8; PUBKEY_BYTES];
    let mut server_nonce = [0u8; NONCE_BYTES];
    if stream.read_exact(&mut server_pubkey).is_err()
        || stream.read_exact(&mut server_nonce).is_err()
    {
        return;
    }
    let server_pubkey_hex = hex_encode(&server_pubkey);
    // Verify the server's claimed pubkey is the one we expected to dial.
    if server_pubkey_hex != peer.pubkey_hex {
        publish_peer_event(&state, &peer.node_id, "peer_auth_failed:wrong_server_pubkey");
        return;
    }

    // Step 2: write client pubkey + nonce.
    if stream.write_all(&client_pubkey_bytes).is_err() || stream.write_all(&client_nonce).is_err() {
        return;
    }
    // Step 3: read server sig, verify.
    let mut server_sig = [0u8; SIG_BYTES];
    if stream.read_exact(&mut server_sig).is_err() {
        return;
    }
    let v = Ed25519Verifier;
    let expected = handshake_transcript(&client_nonce, &client_pubkey_bytes, &server_pubkey);
    if !v.verify(&server_pubkey_hex, &expected, &hex_encode(&server_sig)) {
        publish_peer_event(&state, &peer.node_id, "peer_auth_failed:bad_server_sig");
        return;
    }
    // Step 4: write client sig.
    let client_sig = state.self_key.sign(&handshake_transcript(
        &server_nonce,
        &server_pubkey,
        &client_pubkey_bytes,
    ));
    let client_sig_bytes = match hex_decode(&client_sig) {
        Some(b) if b.len() == SIG_BYTES => b,
        _ => return,
    };
    if stream.write_all(&client_sig_bytes).is_err() {
        return;
    }

    // Authenticated.
    install_connection(state, stream, peer.node_id.clone());
}

/// Construct the canonical bytes both sides sign over. Direction bound by which pubkey comes
/// "first" (the side that owns the nonce). Domain-separated so the signature is never reusable in
/// another ed25519 context the substrate uses.
fn handshake_transcript(nonce: &[u8], owner_pk: &[u8], peer_pk: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(HANDSHAKE_DOMAIN.len() + nonce.len() + 64);
    t.extend_from_slice(HANDSHAKE_DOMAIN);
    t.extend_from_slice(nonce);
    t.extend_from_slice(owner_pk);
    t.extend_from_slice(peer_pk);
    t
}

fn fresh_nonce() -> Option<[u8; NONCE_BYTES]> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut n = [0u8; NONCE_BYTES];
    // Fail CLOSED on OS-RNG failure. A zero nonce would defeat the sole replay-freshness element
    // bound into the ed25519 challenge-response transcript; the handshake fns abort the connection
    // on `None` exactly as they already do on a hex/IO failure — never proceed with a known-weak
    // nonce. (RNG failure is effectively never on a supported platform.)
    rng.fill(&mut n).ok()?;
    Some(n)
}

// ---- per-peer reader + writer ----

fn install_connection(state: Arc<TransportState>, stream: TcpStream, peer: NodeId) {
    // Reset stream timeouts for the run phase — short reads/writes are how we wake on shutdown.
    let _ = stream.set_read_timeout(Some(POLL));
    let _ = stream.set_write_timeout(Some(POLL));

    let (tx, rx) = sync_channel::<Vec<u8>>(PEER_QUEUE_DEPTH);

    // **Double-connect race fix.** When both nodes mutually dial each other at boot, both
    // handshakes can succeed before either side has installed a writer. Without the
    // check-and-insert-under-one-lock discipline below, the second call to `install_connection`
    // would silently overwrite the first writer; the first writer's `SyncSender` would drop, the
    // first writer thread would exit on `Disconnected`, `Shutdown::Both` the socket, the peer
    // would see EOF and tear down — a connection thrash that never delivers a frame.
    //
    // First successful handshake-and-install **wins**; redundant arrivals close their socket
    // politely and return. The window between the two sides' lock acquisitions is microseconds;
    // the worst that happens during it is one wasted handshake — and even then, both sides
    // converge on having exactly one working connection (which may be different physical
    // connections on each side under a strict race, but each side has a working channel, which
    // is all the substrate needs).
    let rx = {
        let mut writers = mlock(&state.writers);
        if writers.contains_key(&peer) {
            drop(writers);
            let _ = stream.shutdown(Shutdown::Both);
            publish_peer_event(&state, &peer, "peer_redundant_connection_closed");
            return;
        }
        writers.insert(peer.clone(), tx);
        rx
    };

    // From here the writer SENDER is in the `writers` map. EVERY early exit below must roll it back
    // (and any pushed socket handle) — otherwise `handle` would feed a peer with no reader/writer
    // behind it: a silent half-wired connection that drops every frame. `try_clone` (EMFILE/ENFILE)
    // and `spawn` (EAGAIN at the thread limit) are the resource-edge conditions that can fail here;
    // none may panic a free-standing, non-`catch_unwind` thread (R9).

    // We need three handles to the same TCP connection: one for the reader thread, one for the
    // writer thread (keeps `stream` by move), and one in `state.sockets` so `shutdown` can slam the
    // connection closed on the way out.
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("transport-tcp: try_clone (reader) for {} failed: {e}; rolling back", peer.0);
            mlock(&state.writers).remove(&peer);
            return;
        }
    };
    let shutdown_handle = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "transport-tcp: try_clone (shutdown) for {} failed: {e}; rolling back",
                peer.0
            );
            mlock(&state.writers).remove(&peer);
            return;
        }
    };
    mlock(&state.sockets).entry(peer.clone()).or_default().push(shutdown_handle);

    publish_peer_event(&state, &peer, "peer_connected");

    // Cluster mode: sync our member view to the newcomer so membership propagates over the mesh.
    if state.gossip.load(Ordering::Relaxed) {
        gossip_to_peer(&state, &peer);
    }

    // Reader: pull envelopes off the wire and route them locally.
    let state_r = state.clone();
    let peer_r = peer.clone();
    let h_r = match Builder::new()
        .name(format!("transport-reader-{}", peer.0))
        .spawn(move || reader_loop(state_r, reader_stream, peer_r))
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "transport-tcp: spawn reader for {} failed: {e}; rolling back connection",
                peer.0
            );
            mlock(&state.writers).remove(&peer);
            mlock(&state.sockets).remove(&peer);
            return;
        }
    };
    // Track the reader BEFORE spawning the writer, so a writer-spawn failure can still join it at
    // shutdown rather than orphaning it. Reap finished handles to bound the Vec under churn (T4).
    {
        let mut threads = mlock(&state.threads);
        threads.retain(|h| !h.is_finished());
        threads.push(h_r);
    }

    // Writer: pull from the per-peer queue and put on the wire.
    let state_w = state.clone();
    let peer_w = peer.clone();
    match Builder::new()
        .name(format!("transport-writer-{}", peer.0))
        .spawn(move || writer_loop(state_w, stream, rx, peer_w))
    {
        Ok(h) => mlock(&state.threads).push(h),
        Err(e) => {
            // The reader is already running. Drop the writer entry and slam the retained socket so
            // the reader's next read hits EOF and it exits cleanly (it removes the socket handle and
            // publishes `peer_disconnected` on the way out). The dialer reconnects. (E1)
            eprintln!(
                "transport-tcp: spawn writer for {} failed: {e}; tearing the connection down",
                peer.0
            );
            mlock(&state.writers).remove(&peer);
            for s in mlock(&state.sockets).get(&peer).into_iter().flatten() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

fn reader_loop(state: Arc<TransportState>, mut stream: TcpStream, peer: NodeId) {
    loop {
        if state.stop.load(Ordering::Relaxed) {
            break;
        }
        // Length prefix (4-byte LE u32).
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
        let n = u32::from_le_bytes(len_buf) as usize;
        if n == 0 || n > MAX_FRAME_BYTES {
            // Cap absurd frame sizes (R9: hostile peer doesn't get to OOM us). 128 MB is roomy
            // for the ship-an-artifact case (an echo-daemon debug `.so` is ~16 MB, the
            // envelope JSON with hex-encoded payload is ~33 MB) and bounded enough to refuse a
            // billion-byte-prefix attack. A future policy makes this operator-injectable.
            break;
        }
        let mut payload = vec![0u8; n];
        if read_exact_with_stop(&state, &mut stream, &mut payload).is_err() {
            break;
        }
        match WireFrame::parse(&payload) {
            Some(WireFrame::Env(env)) => deliver_locally(&state, *env, &peer),
            Some(WireFrame::Gossip { members }) => {
                // Membership only matters in cluster mode; a static node ignores stray gossip.
                if state.gossip.load(Ordering::Relaxed) {
                    ingest_gossip(&state, members);
                }
            }
            // Drop malformed frames quietly (R9 — no panic on hostile bytes).
            None => continue,
        }
    }
    publish_peer_event(&state, &peer, "peer_disconnected");
    // Remove this peer's writer so `handle` stops trying to feed a dead connection — AND its
    // retained shutdown-handle socket(s). Dropping the socket clone closes the dup fd; without this,
    // every reconnect of a flapping peer leaked one fd that lived until full transport shutdown,
    // eventually exhausting the descriptor table (EMFILE). Sound because the single-active-connection
    // discipline keeps ≤1 live connection per peer (the redundant-arrival path returns before
    // pushing a handle). (T4)
    mlock(&state.writers).remove(&peer);
    mlock(&state.sockets).remove(&peer);
}

/// Like `read_exact`, but co-operates with shutdown: any `WouldBlock`/`TimedOut` re-checks `stop`
/// instead of returning an error, so the reader doesn't fail spuriously under our own POLL.
fn read_exact_with_stop(
    state: &TransportState,
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> std::io::Result<()> {
    let mut got = 0;
    while got < buf.len() {
        if state.stop.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("stop"));
        }
        match stream.read(&mut buf[got..]) {
            Ok(0) => {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(n) => got += n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn writer_loop(
    state: Arc<TransportState>,
    mut stream: TcpStream,
    rx: Receiver<Vec<u8>>,
    peer: NodeId,
) {
    loop {
        if state.stop.load(Ordering::Relaxed) {
            break;
        }
        let bytes = match rx.recv_timeout(POLL) {
            Ok(b) => b,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let len = (bytes.len() as u32).to_le_bytes();
        if write_all_with_stop(&state, &mut stream, &len).is_err()
            || write_all_with_stop(&state, &mut stream, &bytes).is_err()
        {
            break;
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    // Reader on the other side will see EOF and exit; we don't double-publish disconnected here.
    let _ = peer; // silence unused if all branches above already used it for naming
}

/// `write_all` that co-operates with the per-call `POLL` timeout: a partial write hitting the
/// kernel send-buffer wall returns `WouldBlock`/`TimedOut`; we loop and try again instead of
/// failing the whole frame. Without this, a 22 MB envelope on localhost stalls after the first
/// ~1 MB (TCP send buffer full), the next `write` times out, `write_all` errors, and the writer
/// thread tears the connection down — the exact failure mode a bare `stream.write_all`
/// hits under a stalled peer.
fn write_all_with_stop(
    state: &TransportState,
    stream: &mut TcpStream,
    buf: &[u8],
) -> std::io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        if state.stop.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("stop"));
        }
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write 0")),
            Ok(n) => written += n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Re-address an envelope that arrived from `peer` and route it onto the local bus. The local
/// recipient sees `from = transport_creature_id` (the local bus re-seals it), but the `reply_to`
/// is rewritten to `Address::Node(peer, original_sender_mid)` so the eventual reply goes back
/// across the wire through us, and from there to the original requester on the peer node. `corr`,
/// `schema`, and `commitment` ride through unchanged — `corr`/`schema` are what fire-and-correlate
/// needs to match a reply to its request across the boundary, and `commitment` is the
/// commit-and-reveal slot a receiving Realm may have to verify; dropping it here
/// would silently defeat any cross-node commit-and-reveal (a fair Distribute pick, a consensus
/// tie-break), which is exactly why the realm-gateway/omega-federator preserve it on rewrite.
fn deliver_locally(state: &TransportState, env: Envelope, peer: &NodeId) {
    let target_mid = match &env.header.to {
        Address::Node(node, mid) if *node == state.self_node => *mid,
        Address::Node(node, _mid) => {
            eprintln!(
                "transport-tcp: dropped an inbound frame from peer {} addressed to node {}, \
                 but this transport is node {}",
                peer.0, node.0, state.self_node.0
            );
            return;
        }
        // The router should never deliver a non-Node envelope here; if it does we drop it
        // (re-routing locally would be undefined intent) but make the contract violation visible.
        other => {
            eprintln!(
                "transport-tcp: dropped an inbound non-Node envelope addressed {other:?} from peer {}",
                peer.0
            );
            return;
        }
    };

    // Kernel control is local-only. The reserved `KERNEL_ID` inbox drives `KernelControl`
    // (Unload / ExtendBudget); a remote peer must never reach it. Admitted peers are trusted to
    // route *data* across the mesh, not to drive a peer node's kernel — so refuse it here, at the
    // wire boundary, which is the one place the off-node origin is still known (the bus reseals
    // `from` to this transport creature before the control listener ever sees the envelope).
    if target_mid == KERNEL_ID {
        eprintln!(
            "transport-tcp: refused an inbound frame from peer {} addressed to the reserved \
             local KERNEL_ID — kernel control is local-only",
            peer.0
        );
        return;
    }

    // Capture the small correlation fields before `env` is moved into the dispatch builder, so a
    // dropped inbound frame can name itself in the log below.
    let corr = env.header.corr;

    // Rewrite `reply_to`: a `Creature(mid)` from the peer means "mid on the peer node" from our POV.
    let reply_to = env.header.reply_to.clone().map(|rt| match rt {
        Address::Creature(mid) => Address::Node(peer.clone(), mid),
        other => other,
    });

    let mut dispatch =
        Dispatch::to(Address::Creature(target_mid), env.payload).with_schema(env.header.schema);
    if let Some(rt) = reply_to {
        dispatch = dispatch.with_reply_to(rt);
    }
    if let Some(corr) = corr {
        dispatch = dispatch.with_corr(corr);
    }
    if let Some(commit) = env.header.commitment {
        dispatch = dispatch.with_commitment(commit);
    }

    // Clone the `Arc<dyn Bus>` out and DROP the guard before emitting — `emit` re-enters the router
    // (table read + journal mutex + try_send), so holding `state.bus` across it would serialize
    // every peer reader thread on one mutex and widen the poison/deadlock window (T6).
    let bus = mlock(&state.bus).as_ref().cloned();
    if let Some(bus) = bus {
        if let Err(e) = bus.emit(dispatch) {
            // The frame already crossed the wire and authenticated; a local-route failure after
            // that was invisible. Make it discoverable (best-effort delivery is unchanged).
            eprintln!(
                "transport-tcp: inbound frame from peer {} to creature {target_mid:?} \
                 (corr={corr:?}) dropped on local route: {e}",
                peer.0
            );
        }
    }
}

fn publish_peer_event(state: &TransportState, peer: &NodeId, event: &str) {
    let ev = PeerEvent { peer: peer.0.clone(), event: event.to_string() };
    let payload = aether::wire::to_bytes(&ev);
    // Clone the Arc out and drop the guard before `emit` (T6 — never hold `state.bus` across the
    // recursive route()).
    let bus = mlock(&state.bus).as_ref().cloned();
    let Some(bus) = bus else { return };
    let _ = bus.emit(
        Dispatch::to(Address::Topic(Topic::new(Topic::PROPRIOCEPTION)), payload)
            .with_schema("peer_event"),
    );
}

// ---- cluster membership (gossip + control) ------------------------------------------------------

/// Spawn one persistent dialer for a peer (idempotent — the `dialing` set prevents duplicates).
/// Skips peers with no dial address and never dials self.
fn spawn_dialer(state: &Arc<TransportState>, peer: PeerConfig) {
    if peer.dial_addr.is_none() || peer.node_id == state.self_node {
        return;
    }
    if !mlock(&state.dialing).insert(peer.node_id.clone()) {
        return; // a dialer already exists for this peer
    }
    let st = state.clone();
    let peer_id = peer.node_id.clone();
    match Builder::new()
        .name(format!("transport-dialer-{}", peer_id.0))
        .spawn(move || dialer_loop(st, peer))
    {
        Ok(h) => mlock(&state.threads).push(h),
        Err(e) => {
            eprintln!("transport-tcp: failed to spawn dialer thread for {}: {e}", peer_id.0);
            mlock(&state.dialing).remove(&peer_id);
            publish_peer_event(state, &peer_id, "peer_dialer_spawn_failed");
        }
    }
}

/// Admit a peer into the allowlist + member set. Reports whether the graph changed, was already
/// current, or the new member was refused. Never admits self.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmitMemberResult {
    Changed,
    Unchanged,
    Refused,
}

fn admit_member(
    state: &Arc<TransportState>,
    node_id: &NodeId,
    pubkey_hex: &str,
    addr: &str,
) -> AdmitMemberResult {
    if *node_id == state.self_node {
        return AdmitMemberResult::Refused;
    }
    let result = {
        let max_members = state.max_members.load(Ordering::Relaxed);
        let mut members = mlock(&state.members);
        match members.get(node_id) {
            Some(existing) if existing.pubkey_hex == pubkey_hex && existing.addr == addr => {
                AdmitMemberResult::Unchanged
            }
            _ => {
                if !members.contains_key(node_id)
                    && max_members != 0
                    && members.len() >= max_members
                {
                    eprintln!(
                        "transport-tcp: member table at capacity ({max_members}); refusing new member {}",
                        node_id.0
                    );
                    return AdmitMemberResult::Refused;
                }
                members.insert(
                    node_id.clone(),
                    MemberInfo { pubkey_hex: pubkey_hex.to_string(), addr: addr.to_string() },
                );
                AdmitMemberResult::Changed
            }
        }
    };
    // Keep the handshake allowlist current (idempotent) so this peer can connect either direction.
    if result != AdmitMemberResult::Refused {
        mlock(&state.peers_by_pubkey).insert(pubkey_hex.to_string(), node_id.clone());
    }
    // A newly-learned member is a graph change — surface it on the same sense stream peer_connected
    // rides, so a subscriber can observe admissions (operator-initiated and gossip-grafted alike).
    if result == AdmitMemberResult::Changed {
        publish_peer_event(state, node_id, "peer_admitted");
    }
    result
}

/// Snapshot self + known members as gossip entries.
fn member_gossip(state: &Arc<TransportState>) -> Vec<GossipMember> {
    let mut out = vec![GossipMember {
        node_id: state.self_node.0.clone(),
        pubkey_hex: state.self_pubkey_hex.clone(),
        addr: mlock(&state.advertise_addr).clone(),
    }];
    for (id, info) in mlock(&state.members).iter() {
        out.push(GossipMember {
            node_id: id.0.clone(),
            pubkey_hex: info.pubkey_hex.clone(),
            addr: info.addr.clone(),
        });
    }
    out
}

/// Push a gossip frame (full member view) onto one peer's outbound queue.
fn gossip_to_peer(state: &Arc<TransportState>, peer: &NodeId) {
    let frame = WireFrame::Gossip { members: member_gossip(state) }.to_bytes();
    if let Some(tx) = mlock(&state.writers).get(peer) {
        let _ = tx.try_send(frame);
    }
}

/// Push a gossip frame to every connected peer (used when membership changes, so it propagates).
fn gossip_broadcast(state: &Arc<TransportState>) {
    let frame = WireFrame::Gossip { members: member_gossip(state) }.to_bytes();
    for tx in mlock(&state.writers).values() {
        let _ = tx.try_send(frame.clone());
    }
}

/// Ingest a peer's gossip: admit + dial any unknown member; if anything new, re-broadcast so the
/// new member floods to the rest of the mesh (terminates: a node only re-broadcasts on genuinely
/// new members, and the member set is finite).
fn ingest_gossip(state: &Arc<TransportState>, members: Vec<GossipMember>) {
    let mut any_new = false;
    // Bound how many members one gossip frame can graft, so a hostile/buggy peer can't make us spawn
    // an unbounded number of dialer threads from a single message (R9). Far above any real cluster.
    for m in members.into_iter().take(MAX_GOSSIP_MEMBERS) {
        let node_id = NodeId(m.node_id);
        if node_id == state.self_node {
            continue;
        }
        if admit_member(state, &node_id, &m.pubkey_hex, &m.addr) == AdmitMemberResult::Changed {
            any_new = true;
            spawn_dialer(
                state,
                PeerConfig { node_id, pubkey_hex: m.pubkey_hex, dial_addr: Some(m.addr) },
            );
        }
    }
    if any_new {
        gossip_broadcast(state);
    }
}

/// Handle a `transport.ctl` control op: admit/dial a peer (`Connect`) or report the graph
/// (`Members`). Replies to the op's `reply_to`.
fn handle_ctl(state: &Arc<TransportState>, env: &Envelope) -> Outcome {
    let Some(op) = TransportCtl::parse(&env.payload) else {
        return Outcome::none();
    };
    match op {
        TransportCtl::Connect { node_id, pubkey_hex, addr } => {
            let node_id = NodeId(node_id);
            let admitted = admit_member(state, &node_id, &pubkey_hex, &addr);
            if admitted == AdmitMemberResult::Refused {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        TransportCtlReply::Rejected {
                            reason: "transport member table at capacity or self-admission refused"
                                .into(),
                        }
                        .to_bytes(),
                    )
                    .with_schema(CTL_SCHEMA),
                );
            }
            spawn_dialer(
                state,
                PeerConfig { node_id: node_id.clone(), pubkey_hex, dial_addr: Some(addr) },
            );
            if admitted == AdmitMemberResult::Changed {
                gossip_broadcast(state);
            }
            Outcome::send(
                Dispatch::reply_to_env(
                    env,
                    TransportCtlReply::Connecting { node_id: node_id.0 }.to_bytes(),
                )
                .with_schema(CTL_SCHEMA),
            )
        }
        TransportCtl::Members => {
            let connected: HashSet<NodeId> = mlock(&state.writers).keys().cloned().collect();
            let mut members: Vec<MemberView> = mlock(&state.members)
                .iter()
                .map(|(id, info)| MemberView {
                    node_id: id.0.clone(),
                    addr: info.addr.clone(),
                    connected: connected.contains(id),
                })
                .collect();
            members.sort_by(|a, b| a.node_id.cmp(&b.node_id));
            Outcome::send(
                Dispatch::reply_to_env(
                    env,
                    TransportCtlReply::Members { self_node: state.self_node.0.clone(), members }
                        .to_bytes(),
                )
                .with_schema(CTL_SCHEMA),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_transcript_is_domain_separated_and_order_sensitive() {
        let n = [1u8; NONCE_BYTES];
        let a = [2u8; PUBKEY_BYTES];
        let b = [3u8; PUBKEY_BYTES];
        let t_ab = handshake_transcript(&n, &a, &b);
        let t_ba = handshake_transcript(&n, &b, &a);
        assert_ne!(t_ab, t_ba, "(owner_pk, peer_pk) order matters — direction binding");
        assert!(t_ab.starts_with(HANDSHAKE_DOMAIN), "domain prefix present");
    }

    #[test]
    fn fresh_nonce_returns_distinct_values() {
        // Probabilistic; two 32-byte RNG draws colliding is ~2^-256.
        assert_ne!(fresh_nonce(), fresh_nonce());
    }

    /// **Double-connect race regression.** When both nodes dial each other at boot, the
    /// substrate must converge on exactly one working writer per peer — not flap between two
    /// connections that keep tearing each other down.
    ///
    /// We simulate the race directly at the install layer: two `install_connection` calls
    /// for the same peer on the same state, with two distinct sockets that DON'T actually need
    /// peers (they connect to a short-lived listener so `try_clone` works). After both calls
    /// return, exactly one writer must be in the map, exactly one socket in the sockets list.
    #[test]
    fn install_connection_is_idempotent_under_concurrent_arrival() {
        use std::net::TcpListener;

        // Throwaway listener so we can produce real connected `TcpStream`s for the test.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let s1 = TcpStream::connect(addr).unwrap();
        let (s1_server, _) = listener.accept().unwrap();

        let s2 = TcpStream::connect(addr).unwrap();
        let (s2_server, _) = listener.accept().unwrap();

        // Keep the server-side handles alive for the duration of the test so the client-side
        // streams stay routable (otherwise the kernel would close them immediately).
        let _keep_alive = (s1_server, s2_server);

        let (k1, _) = Ed25519KeyMaterial::generate().unwrap();
        let state = Arc::new(TransportState {
            self_key: k1.clone(),
            self_pubkey_hex: k1.public_hex().to_string(),
            self_node: NodeId("test-self".into()),
            listen_addr: "unused".into(),
            advertise_addr: Mutex::new("unused".into()),
            gossip: AtomicBool::new(false),
            peers_by_pubkey: Mutex::new(HashMap::new()),
            members: Mutex::new(HashMap::new()),
            max_members: AtomicUsize::new(DEFAULT_MAX_MEMBERS),
            dialing: Mutex::new(HashSet::new()),
            writers: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            bus: Mutex::new(None),
            me: Mutex::new(None),
            stop: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        });

        let peer = NodeId("peer".into());

        // Both calls happen, simulating the race.
        install_connection(state.clone(), s1, peer.clone());
        install_connection(state.clone(), s2, peer.clone());

        // Exactly one writer survived — the FIRST call won; the second saw the entry already
        // present and bowed out.
        assert_eq!(state.writers.lock().unwrap().len(), 1, "exactly one writer per peer");
        assert_eq!(
            state.sockets.lock().unwrap().get(&peer).map(|v| v.len()).unwrap_or(0),
            1,
            "exactly one shutdown handle per peer (no zombie socket from the loser)"
        );

        // Cleanup the spawned reader/writer threads so the test exits. Mirror the production
        // `shutdown()` lock discipline: signal stop, slam every socket, clear the writers — then
        // RELEASE those locks *before* joining. The reader thread's exit path (see `reader_loop`)
        // acquires `state.sockets` and `state.writers` to deregister itself; holding either across
        // the join would deadlock (the reader can't finish, so the join never returns). The drains
        // are scoped so the guards drop at the end of each block, exactly as production does.
        state.stop.store(true, Ordering::Relaxed);
        {
            let mut socks = state.sockets.lock().unwrap();
            for (_, ss) in socks.drain() {
                for s in ss {
                    let _ = s.shutdown(Shutdown::Both);
                }
            }
        }
        state.writers.lock().unwrap().clear();
        // Take the handles out under the lock, then release it before joining.
        let handles: Vec<_> = state.threads.lock().unwrap().drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }

    // ---- cluster membership unit coverage ----

    #[test]
    fn default_member_cap_leaves_room_for_self_in_gossip_frame() {
        assert_eq!(DEFAULT_MAX_MEMBERS + 1, MAX_GOSSIP_MEMBERS);
    }

    /// A bound-free transport state (no listener/threads) for testing the pure membership logic.
    fn test_state(self_id: &str) -> Arc<TransportState> {
        let (k, _) = Ed25519KeyMaterial::generate().unwrap();
        let cfg = TransportConfig {
            self_key: k,
            self_node: NodeId(self_id.into()),
            listen_addr: "127.0.0.1:0".into(),
            peers: vec![],
        };
        TransportTcp::new(cfg).state.clone()
    }

    #[derive(Default)]
    struct RecordingBus {
        sent: std::sync::Mutex<Vec<Dispatch>>,
    }

    impl Bus for RecordingBus {
        fn emit(&self, d: Dispatch) -> Result<(), aether::BusError> {
            mlock(&self.sent).push(d);
            Ok(())
        }

        fn whoami(&self) -> CreatureId {
            CreatureId(999)
        }
    }

    fn attach_recording_bus(state: &Arc<TransportState>) -> Arc<RecordingBus> {
        let bus = Arc::new(RecordingBus::default());
        let bus_for_state: Arc<dyn Bus> = bus.clone();
        *mlock(&state.bus) = Some(bus_for_state);
        bus
    }

    fn inbound_env(to: Address) -> Envelope {
        Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(42)),
                to,
                reply_to: Some(Address::Creature(CreatureId(7))),
                seq: 0,
                causal: Vec::new(),
                stamp: 0,
                sig: "sig".into(),
                corr: Some(55),
                commitment: Some("commitment".into()),
                schema: "test.schema".into(),
            },
            payload: b"payload".to_vec(),
        }
    }

    #[test]
    fn inbound_frame_must_be_addressed_to_this_node_before_local_delivery() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());

        deliver_locally(
            &state,
            inbound_env(Address::Node(NodeId("someone-else".into()), CreatureId(3))),
            &peer,
        );
        assert!(
            mlock(&bus.sent).is_empty(),
            "wrong-node frames must be refused at the wire boundary"
        );

        deliver_locally(&state, inbound_env(Address::Node(NodeId("me".into()), KERNEL_ID)), &peer);
        assert!(
            mlock(&bus.sent).is_empty(),
            "remote peers must not be able to address the local kernel control inbox"
        );

        deliver_locally(
            &state,
            inbound_env(Address::Node(NodeId("me".into()), CreatureId(3))),
            &peer,
        );
        let sent = mlock(&bus.sent).clone();
        assert_eq!(sent.len(), 1, "a self-node frame still routes locally");
        assert_eq!(sent[0].to, Address::Creature(CreatureId(3)));
        assert_eq!(sent[0].reply_to, Some(Address::Node(peer, CreatureId(7))));
        assert_eq!(sent[0].corr, Some(55));
        assert_eq!(sent[0].schema, "test.schema");
        assert_eq!(sent[0].commitment.as_deref(), Some("commitment"));
        assert_eq!(sent[0].payload, b"payload");
    }

    #[test]
    fn admit_member_is_idempotent_and_never_admits_self() {
        let state = test_state("me");
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), "pk_a", "127.0.0.1:1"),
            AdmitMemberResult::Changed,
            "first admit is a graph change"
        );
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), "pk_a", "127.0.0.1:1"),
            AdmitMemberResult::Unchanged,
            "re-admit with identical data is unchanged"
        );
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), "pk_a", "127.0.0.1:2"),
            AdmitMemberResult::Changed,
            "a changed dial addr is a graph change"
        );
        assert_eq!(
            admit_member(&state, &NodeId("me".into()), "pk_me", "127.0.0.1:9"),
            AdmitMemberResult::Refused,
            "self is never admitted"
        );
        assert_eq!(
            mlock(&state.peers_by_pubkey).get("pk_a"),
            Some(&NodeId("a".into())),
            "admitting a peer updates the handshake allowlist"
        );
        assert!(
            !mlock(&state.members).contains_key(&NodeId("me".into())),
            "self stays out of members"
        );
    }

    #[test]
    fn admit_member_refuses_new_members_at_capacity_but_updates_existing() {
        let state = test_state("me");
        state.max_members.store(1, Ordering::Relaxed);

        assert_eq!(
            admit_member(&state, &NodeId("a".into()), "pk_a", "127.0.0.1:1"),
            AdmitMemberResult::Changed
        );
        assert_eq!(
            admit_member(&state, &NodeId("b".into()), "pk_b", "127.0.0.1:2"),
            AdmitMemberResult::Refused,
            "new member refused at capacity"
        );
        assert!(!mlock(&state.members).contains_key(&NodeId("b".into())));
        assert!(
            !mlock(&state.peers_by_pubkey).contains_key("pk_b"),
            "refused member must not enter the handshake allowlist"
        );

        assert_eq!(
            admit_member(&state, &NodeId("a".into()), "pk_a", "127.0.0.1:3"),
            AdmitMemberResult::Changed,
            "existing member updates at capacity"
        );
        assert_eq!(
            mlock(&state.members).get(&NodeId("a".into())).map(|m| m.addr.clone()),
            Some("127.0.0.1:3".into())
        );

        state.max_members.store(0, Ordering::Relaxed);
        assert_eq!(
            admit_member(&state, &NodeId("b".into()), "pk_b", "127.0.0.1:2"),
            AdmitMemberResult::Changed,
            "0 is the explicit unbounded opt-out"
        );
    }

    #[test]
    fn control_connect_replies_rejected_when_member_table_is_at_capacity() {
        let state = test_state("me");
        state.max_members.store(1, Ordering::Relaxed);
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), "pk_a", "127.0.0.1:1"),
            AdmitMemberResult::Changed
        );
        let env = Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(42)),
                to: Address::Creature(CreatureId(1)),
                reply_to: Some(Address::Creature(CreatureId(42))),
                seq: 0,
                causal: Vec::new(),
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: CTL_SCHEMA.into(),
            },
            payload: TransportCtl::Connect {
                node_id: "b".into(),
                pubkey_hex: "pk_b".into(),
                addr: "127.0.0.1:2".into(),
            }
            .to_bytes(),
        };

        let out = handle_ctl(&state, &env);
        assert_eq!(out.dispatches.len(), 1);
        match TransportCtlReply::parse(&out.dispatches[0].payload) {
            Some(TransportCtlReply::Rejected { reason }) => {
                assert!(reason.contains("capacity"), "reason: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(!mlock(&state.members).contains_key(&NodeId("b".into())));
        assert!(!mlock(&state.peers_by_pubkey).contains_key("pk_b"));
    }

    #[test]
    fn ingest_gossip_admits_unknown_members_and_skips_self() {
        let state = test_state("me");
        ingest_gossip(
            &state,
            vec![
                GossipMember {
                    node_id: "a".into(),
                    pubkey_hex: "pk_a".into(),
                    addr: "127.0.0.1:1".into(),
                },
                GossipMember {
                    node_id: "me".into(),
                    pubkey_hex: "pk_me".into(),
                    addr: "127.0.0.1:2".into(),
                },
            ],
        );
        assert!(mlock(&state.members).contains_key(&NodeId("a".into())), "learned `a` from gossip");
        assert!(!mlock(&state.members).contains_key(&NodeId("me".into())), "did not learn self");
        assert_eq!(mlock(&state.peers_by_pubkey).get("pk_a"), Some(&NodeId("a".into())));
        // ingest spawned a dialer for `a`; tear it down so the test process exits cleanly.
        state.stop.store(true, Ordering::Relaxed);
        let handles: Vec<_> = mlock(&state.threads).drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }

    #[test]
    fn control_and_wire_frames_round_trip() {
        let c = TransportCtl::Connect {
            node_id: "n".into(),
            pubkey_hex: "pk".into(),
            addr: "127.0.0.1:9".into(),
        };
        assert!(matches!(TransportCtl::parse(&c.to_bytes()), Some(TransportCtl::Connect { .. })));
        assert!(matches!(
            TransportCtl::parse(&TransportCtl::Members.to_bytes()),
            Some(TransportCtl::Members)
        ));

        let r = TransportCtlReply::Members {
            self_node: "s".into(),
            members: vec![MemberView { node_id: "a".into(), addr: "x".into(), connected: true }],
        };
        match TransportCtlReply::parse(&r.to_bytes()) {
            Some(TransportCtlReply::Members { members, .. }) => assert_eq!(members.len(), 1),
            other => panic!("expected Members reply, got {other:?}"),
        }

        let g = WireFrame::Gossip {
            members: vec![GossipMember {
                node_id: "a".into(),
                pubkey_hex: "pk".into(),
                addr: "x".into(),
            }],
        };
        assert!(matches!(WireFrame::parse(&g.to_bytes()), Some(WireFrame::Gossip { .. })));
    }
}
