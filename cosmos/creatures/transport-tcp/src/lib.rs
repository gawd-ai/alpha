//! `transport-tcp` — the real authenticated peer link, the swap-in for the `loopback-gateway`.
//!
//! Bound to `Role::TRANSPORT`, so the kernel routes every `Address::Node(_,_)` and
//! `Address::NodeRole(_,_)` envelope here. A numeric Node target is delivered exactly as named;
//! NodeRole is resolved only on ingress by an attesting transport and only when the receiving host
//! explicitly exposed that role.
//! Authenticates each peer with a mutual ed25519 challenge-response handshake against a pre-shared
//! pubkey allowlist — no PKI, no TOFU. After the handshake, envelopes and gossip travel as
//! length-prefixed JSON (the same shape the loopback uses, so the wire format is one step's worth of
//! change, not a redesign). Bulk artifact chunks use the shared GX/gawdxfer binary frame on that
//! same authenticated length-prefixed stream.
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
//! - **No unbounded inbound handshakes.** By default at most
//!   [`DEFAULT_MAX_INBOUND_HANDSHAKES`] accepted sockets may be authenticating at once per transport
//!   instance; [`TransportTcp::with_max_inbound_handshakes`] may lower or otherwise finitely tune the
//!   ceiling, and excess sockets are closed immediately.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Origin,
    OriginEvent, OriginVerdict, Outcome, Role, Topic, KERNEL_ID, ORIGIN_EVENT_SCHEMA,
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

/// Aggregate per-transport cap on accepted sockets that have not completed authentication. Each
/// handshake also retains its five-second per-socket read/write timeout; the cap bounds the threads
/// and descriptors a slow unauthenticated client can occupy concurrently.
pub const DEFAULT_MAX_INBOUND_HANDSHAKES: usize = 64;

/// Per-peer outbound queue depth. Backpressure here is "we're not draining the peer fast enough"
/// — bounded queue + `try_send` shedding keeps memory bounded under a sender flood (R9).
const PEER_QUEUE_DEPTH: usize = 1024;

/// Per-frame cap. See the reader for rationale.
const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;
/// Magic prefix for raw GX/gawdxfer chunk frames on the authenticated peer stream.
///
/// The outer TCP record is still transport-tcp's length prefix. Inside that record, JSON frames
/// begin with a JSON object and GX frames begin with this marker followed by
/// `gawdxfer::encode_binary_frame`. This keeps bulk chunks out of envelope JSON without inventing a
/// transport-specific artifact protocol.
const GX_FRAME_PREFIX: &[u8; 4] = b"GX1\0";

/// Cap on members grafted from a single gossip frame (R9). Far above any real cluster's
/// membership — a bound on dialer threads one message can spawn, not a topology limit.
const MAX_GOSSIP_MEMBERS: usize = 1024;
/// Maximum active raw-GX route bindings retained per peer. A binding is `transfer_id -> local
/// creature target`, installed only by authenticated peers and removed on disconnect or, for
/// transfer-plan generated chunks, after the declared final chunk.
const MAX_GX_ROUTES_PER_PEER: usize = 4096;
/// Default cap on the accumulated dynamic member table. One slot is reserved for `self` in gossip
/// frames, so a full default member table still fits under `MAX_GOSSIP_MEMBERS`. `0` in
/// [`TransportTcp::with_max_members`] is the explicit unbounded lab/demo opt-out.
pub const DEFAULT_MAX_MEMBERS: usize = MAX_GOSSIP_MEMBERS - 1;
/// Maximum byte length for a cluster member's node id. Cluster node ids are operator-visible
/// routing tokens, not payload storage; cap them before they enter the member table or sense stream.
pub const MAX_MEMBER_NODE_ID_BYTES: usize = 256;
/// Maximum byte length for a cluster member's dial address. The current dialer accepts IP socket
/// addresses (`127.0.0.1:9001`, `[::1]:9001`), so this cap is intentionally roomy.
pub const MAX_MEMBER_ADDR_BYTES: usize = 512;

/// Poison-tolerant `Mutex` acquisition (R9). Every worker thread in this creature runs OUTSIDE the
/// kernel drain's `catch_unwind`, so a panic while one holds a `TransportState` lock would poison it
/// and wedge every other peer thread on the next acquire. Recovering the guard is sound — each lock
/// guards a plain map / Vec / Option with no half-broken invariant. (Mirrors `sanctum::mlock`.)
#[inline]
fn mlock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Shared aggregate accounting for inbound sockets that have not authenticated yet.
struct InboundHandshakeSlots {
    active: Arc<AtomicUsize>,
    limit: AtomicUsize,
}

impl InboundHandshakeSlots {
    fn new(limit: usize) -> Self {
        Self { active: Arc::new(AtomicUsize::new(0)), limit: AtomicUsize::new(limit) }
    }

    fn try_acquire(&self) -> Option<InboundHandshakeSlot> {
        let mut active = self.active.load(Ordering::Relaxed);
        loop {
            // Reload the configured limit on every CAS retry. Lowering the limit while handshakes
            // are active never evicts an existing worker, but it immediately refuses new sockets
            // until the active count falls below the new finite ceiling. A limit of zero is an
            // explicit fail-closed posture: refuse every inbound handshake.
            if active >= self.limit.load(Ordering::Acquire) {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(InboundHandshakeSlot { active: self.active.clone() }),
                Err(observed) => active = observed,
            }
        }
    }
}

/// Releases one unauthenticated-handshake reservation on every exit path, including unwinding.
struct InboundHandshakeSlot {
    active: Arc<AtomicUsize>,
}

impl Drop for InboundHandshakeSlot {
    fn drop(&mut self) {
        let previous = self.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "inbound handshake slot underflow");
    }
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

/// One JSON wire frame on a peer connection: a routed envelope, a membership-gossip push, or a raw
/// GX route binding. Gossip rides the same authenticated socket, so membership needs no cross-node
/// module addressing. Raw GX chunk frames are parsed by [`parse_wire_payload`] before JSON decode.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "f", rename_all = "snake_case")]
enum WireFrame {
    Env(Box<Envelope>),
    Gossip { members: Vec<GossipMember> },
    GxBind(GxRouteBind),
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
        match &frame {
            WireFrame::Gossip { members } if members.len() > MAX_GOSSIP_MEMBERS => {
                eprintln!(
                "transport-tcp: rejecting gossip frame with {} members (cap {MAX_GOSSIP_MEMBERS})",
                members.len()
            );
                return None;
            }
            WireFrame::GxBind(bind) if bind.shape_error().is_some() => return None,
            _ => {}
        }
        Some(frame)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct GxRouteBind {
    transfer_id: String,
    target: CreatureId,
    schema: String,
    corr: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_chunks: Option<u32>,
}

impl GxRouteBind {
    fn shape_error(&self) -> Option<String> {
        let req = gawdxfer::ChunkRequest::new(self.transfer_id.clone(), 0);
        if let Some(error) = req.shape_error() {
            return Some(error);
        }
        if self.target == KERNEL_ID {
            return Some("GX chunks may not target the reserved local KERNEL_ID".to_string());
        }
        if self.schema != GX_CHUNK_SCHEMA {
            return Some(format!("GX bind schema must be `{GX_CHUNK_SCHEMA}`"));
        }
        if self.total_chunks == Some(0) {
            return Some("GX bind total_chunks must be greater than zero".to_string());
        }
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GxRoute {
    target: CreatureId,
    schema: String,
    corr: Option<u64>,
    total_chunks: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PeerFrame {
    frames: Vec<Vec<u8>>,
}

#[derive(Debug)]
enum ParsedWireFrame<'a> {
    Env(Box<Envelope>),
    Gossip { members: Vec<GossipMember> },
    GxBind(GxRouteBind),
    GxChunk(gawdxfer::ChunkFrameHeader, &'a [u8]),
}

fn parse_wire_payload(bytes: &[u8]) -> Option<ParsedWireFrame<'_>> {
    if let Some((header, payload)) = decode_gx_wire_frame(bytes) {
        return Some(ParsedWireFrame::GxChunk(header, payload));
    }
    match WireFrame::parse(bytes)? {
        WireFrame::Env(env) => Some(ParsedWireFrame::Env(env)),
        WireFrame::Gossip { members } => Some(ParsedWireFrame::Gossip { members }),
        WireFrame::GxBind(bind) => Some(ParsedWireFrame::GxBind(bind)),
    }
}

fn decode_gx_wire_frame(bytes: &[u8]) -> Option<(gawdxfer::ChunkFrameHeader, &[u8])> {
    let body = bytes.strip_prefix(GX_FRAME_PREFIX)?;
    let (header, payload) =
        gawdxfer::decode_binary_frame::<gawdxfer::ChunkFrameHeader>(body).ok()?;
    if header.shape_error().is_some() {
        return None;
    }
    Some((header, payload))
}

#[cfg(test)]
fn encode_gx_wire_frame(
    header: &gawdxfer::ChunkFrameHeader,
    payload: &[u8],
) -> Result<Vec<u8>, gawdxfer::FrameError> {
    let body = gawdxfer::encode_binary_frame(header, payload)?;
    prefix_gx_wire_frame(&body)
}

fn prefix_gx_wire_frame(body: &[u8]) -> Result<Vec<u8>, gawdxfer::FrameError> {
    let capacity = prefixed_gx_wire_frame_len(body.len())?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(GX_FRAME_PREFIX);
    frame.extend_from_slice(body);
    Ok(frame)
}

fn prefixed_gx_wire_frame_len(body_len: usize) -> Result<usize, gawdxfer::FrameError> {
    let capacity =
        GX_FRAME_PREFIX.len().checked_add(body_len).ok_or(gawdxfer::FrameError::FrameTooLarge)?;
    if capacity > MAX_FRAME_BYTES {
        return Err(gawdxfer::FrameError::FrameTooLarge);
    }
    Ok(capacity)
}

/// Schema of the cluster control op an operator/front-end sends to admit a peer or read the graph.
pub const CTL_SCHEMA: &str = "transport.ctl";
/// Schema for a raw GX/gawdxfer chunk body addressed to `Address::Node(peer, _)`.
///
/// The local envelope payload is `gawdxfer::encode_binary_frame(...)` bytes. The transport prefixes
/// those bytes with the private `GX_FRAME_PREFIX` tag and sends them over the authenticated peer
/// stream without wrapping the chunk in JSON.
pub const GX_CHUNK_SCHEMA: &str = gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA;
/// Maximum bytes accepted for one `transport.ctl` request before JSON decode. Control ops are small
/// (`Members` or a single bounded `Connect` member); keep this far below the data-plane frame cap.
pub const MAX_TRANSPORT_CTL_BYTES: usize = 64 * 1024;
/// Maximum bytes accepted for one `transport.ctl` reply before JSON decode. The default member-table
/// cap fits under this; larger/unbounded lab meshes should page or narrow their control view.
pub const MAX_TRANSPORT_CTL_REPLY_BYTES: usize = 1024 * 1024;

/// Cluster control op (schema [`CTL_SCHEMA`]). Recognized in `handle()` by schema, address-agnostic.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TransportCtl {
    /// Admit + dial a peer — the operator/AI-gated cluster join. Idempotent.
    Connect { node_id: String, pubkey_hex: String, addr: String },
    /// Ask this node for its view of the cluster graph.
    Members,
    /// Drop a peer: remove it from the allowlist + member set and tear down its link, so it can
    /// neither send nor re-handshake until a fresh [`Connect`](TransportCtl::Connect). The reversible
    /// inverse of `Connect` — the lever an injected defense policy pulls when a peer misbehaves
    /// (e.g. `policy-origin` on repeated forged-origin verdicts). Idempotent.
    Forget { node_id: String },
}
impl TransportCtl {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TRANSPORT_CTL_BYTES {
            return None;
        }
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
    Forgotten { node_id: String },
}
impl TransportCtlReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_TRANSPORT_CTL_REPLY_BYTES {
            return None;
        }
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
    /// NodeId → outbound queue. `handle(Node(peer, _)|NodeRole(peer, _))` pushes here; the per-peer
    /// writer thread drains. Wrapped in Mutex because connect/disconnect rewrites it.
    writers: Mutex<HashMap<NodeId, SyncSender<PeerFrame>>>,
    /// `(peer, transfer_id)` → local route for raw GX chunks received outside JSON envelopes.
    gx_routes: Mutex<HashMap<(NodeId, String), GxRoute>>,
    /// Replay-guard high-water marks: `(origin node, original sender creature)` → highest `seq` seen
    /// this link session. A cross-node frame whose `seq` does not advance is dropped. Reset for a
    /// peer when a fresh handshake installs (a new session legitimately restarts the sender's `seq`).
    origin_seq: Mutex<HashMap<(NodeId, CreatureId), u64>>,
    /// Open sockets, by peer NodeId — kept so shutdown can call `Shutdown::Both` on each to
    /// unblock any reader that's mid-`read`. Multiple connections per peer may exist briefly during
    /// re-dial; the Vec covers that race.
    sockets: Mutex<HashMap<NodeId, Vec<TcpStream>>>,
    bus: Mutex<Option<Arc<dyn Bus>>>,
    me: Mutex<Option<CreatureId>>,
    stop: AtomicBool,
    inbound_handshakes: InboundHandshakeSlots,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl TransportTcp {
    pub fn new(cfg: TransportConfig) -> Self {
        let self_pubkey_hex = cfg.self_key.public_hex().to_string();
        let self_node = cfg.self_node.clone();
        let listen_addr = cfg.listen_addr.clone();
        let mut peers_by_pubkey: HashMap<String, NodeId> = HashMap::new();
        let mut members: HashMap<NodeId, MemberInfo> = HashMap::new();
        let mut peers = Vec::new();
        // Seed the allowlist and member set from configured peers. Peers with a dial address seed
        // the dynamic member set (the bootstrap addresses a joining node is handed); passive peers
        // still enter the allowlist. The stored `cfg.peers` below is the same sanitized view, so
        // `bind()` never spawns dialers from malformed or non-canonical config.
        for p in &cfg.peers {
            let Some(pubkey_hex) = canonical_peer_pubkey(&p.pubkey_hex) else {
                eprintln!("transport-tcp: ignoring configured peer with malformed ed25519 pubkey");
                continue;
            };
            if let Some(reason) = validate_cluster_node_id(&p.node_id) {
                eprintln!("transport-tcp: ignoring configured peer with {reason}");
                continue;
            }
            peers_by_pubkey.insert(pubkey_hex.clone(), p.node_id.clone());
            let mut sanitized_peer = PeerConfig {
                node_id: p.node_id.clone(),
                pubkey_hex: pubkey_hex.clone(),
                dial_addr: None,
            };
            if let Some(addr) = p.dial_addr.as_deref() {
                if let Some(reason) = validate_member_addr(addr) {
                    eprintln!(
                        "transport-tcp: peer {} stays allowlisted, but its configured dial address is ignored ({reason})",
                        p.node_id.0
                    );
                } else {
                    members.insert(
                        p.node_id.clone(),
                        MemberInfo { pubkey_hex, addr: addr.to_string() },
                    );
                    sanitized_peer.dial_addr = Some(addr.to_string());
                }
            }
            peers.push(sanitized_peer);
        }
        let state = Arc::new(TransportState {
            self_key: cfg.self_key.clone(),
            self_pubkey_hex,
            self_node: self_node.clone(),
            advertise_addr: Mutex::new(listen_addr.clone()),
            listen_addr: listen_addr.clone(),
            peers_by_pubkey: Mutex::new(peers_by_pubkey),
            members: Mutex::new(members),
            max_members: AtomicUsize::new(DEFAULT_MAX_MEMBERS),
            dialing: Mutex::new(HashSet::new()),
            gossip: AtomicBool::new(false),
            writers: Mutex::new(HashMap::new()),
            gx_routes: Mutex::new(HashMap::new()),
            origin_seq: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            bus: Mutex::new(None),
            me: Mutex::new(None),
            stop: AtomicBool::new(false),
            inbound_handshakes: InboundHandshakeSlots::new(DEFAULT_MAX_INBOUND_HANDSHAKES),
            threads: Mutex::new(Vec::new()),
        });
        let cfg = TransportConfig { self_key: cfg.self_key, self_node, listen_addr, peers };
        TransportTcp { cfg, state }
    }

    /// Enable **cluster mode**: gossip this node's member view to peers on connect and
    /// auto-dial any member it learns, so a many-to-many mesh self-completes from one seed.
    /// `advertise_addr` is the address peers should dial to reach this node (defaults to the listen
    /// address). Without this call the transport is the classic static peer link.
    pub fn with_gossip(self, advertise_addr: Option<String>) -> Self {
        self.state.gossip.store(true, Ordering::Relaxed);
        if let Some(a) = advertise_addr {
            if let Some(reason) = validate_member_addr(&a) {
                eprintln!("transport-tcp: ignoring gossip advertise address ({reason})");
            } else {
                *mlock(&self.state.advertise_addr) = a;
            }
        }
        // The default advertise address is the (unvalidated, bind-resolvable) listen address, so a
        // rejected override falls back to a value peers may equally refuse — say what will really
        // be gossiped instead of implying the fallback is fine. Receiving peers shape-check every
        // gossiped member, so an invalid self entry simply never propagates.
        let effective = mlock(&self.state.advertise_addr).clone();
        if let Some(reason) = validate_member_addr(&effective) {
            eprintln!(
                "transport-tcp: gossiping advertise address `{effective}` that peers will refuse \
                 ({reason}); set an IP socket address (e.g. 192.0.2.1:9001)"
            );
        }
        self
    }

    /// Cap the accumulated dynamic member table. `0` disables the cap. At capacity a new member from
    /// `transport.ctl` or gossip is refused; already-known members can still be updated.
    pub fn with_max_members(self, max_members: usize) -> Self {
        self.state.max_members.store(max_members, Ordering::Relaxed);
        self
    }

    /// Set the aggregate number of inbound sockets allowed to authenticate concurrently.
    ///
    /// The default is [`DEFAULT_MAX_INBOUND_HANDSHAKES`]. Unlike the member-table cap, this resource
    /// boundary has no unbounded mode: `0` deliberately refuses every inbound handshake, which is a
    /// useful listener-disabled posture while preserving outbound dialing.
    pub fn with_max_inbound_handshakes(self, max_inbound_handshakes: usize) -> Self {
        self.state.inbound_handshakes.limit.store(max_inbound_handshakes, Ordering::Release);
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
        if env.header.schema == GX_CHUNK_SCHEMA {
            return handle_gx_chunk_outbound(&self.state, &env);
        }
        // We only handle node-scoped envelopes (the router only delivers those here anyway). Keep a
        // NodeRole unresolved on egress; only the destination host knows its current exposed binding.
        let peer_node = match &env.header.to {
            Address::Node(peer_node, _) | Address::NodeRole(peer_node, _) => peer_node.clone(),
            _ => return Outcome::none(),
        };
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
                Some(tx) => queue_peer_frame(tx, bytes, MAX_FRAME_BYTES).err(),
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
        mlock(&self.state.gx_routes).clear();

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

fn queue_peer_frame(
    tx: &SyncSender<PeerFrame>,
    frame: Vec<u8>,
    max_frame_bytes: usize,
) -> Result<(), &'static str> {
    queue_peer_frames(tx, vec![frame], max_frame_bytes)
}

fn queue_peer_frames(
    tx: &SyncSender<PeerFrame>,
    frames: Vec<Vec<u8>>,
    max_frame_bytes: usize,
) -> Result<(), &'static str> {
    if frames.is_empty() {
        return Err("peer_send_dropped:empty_frame");
    }
    for frame in &frames {
        // An empty frame is `wire::to_bytes`'s release-mode degrade for an unserializable value —
        // never a real wire message. Name it distinctly so the shed event tells the truth.
        if frame.is_empty() {
            return Err("peer_send_dropped:empty_frame");
        }
        if frame.len() > max_frame_bytes {
            return Err("peer_send_dropped:frame_too_large");
        }
    }
    tx.try_send(PeerFrame { frames }).map_err(|e| match e {
        TrySendError::Full(_) => "peer_send_dropped:backpressure",
        TrySendError::Disconnected(_) => "peer_send_dropped:no_link",
    })
}

fn handle_gx_chunk_outbound(state: &Arc<TransportState>, env: &Envelope) -> Outcome {
    let Address::Node(peer_node, target_mid) = &env.header.to else {
        return Outcome::none();
    };
    if *target_mid == KERNEL_ID {
        publish_peer_event(state, peer_node, "peer_send_dropped:gx_kernel_target");
        return Outcome::none();
    }

    let disposition =
        match gawdxfer::decode_binary_frame::<gawdxfer::ChunkFrameHeader>(&env.payload) {
            Ok((header, _payload)) if header.shape_error().is_none() => {
                let bind = WireFrame::GxBind(GxRouteBind {
                    transfer_id: header.transfer_id,
                    target: *target_mid,
                    schema: GX_CHUNK_SCHEMA.to_string(),
                    corr: env.header.corr,
                    total_chunks: header.total_chunks,
                })
                .to_bytes();
                match prefix_gx_wire_frame(&env.payload) {
                    Ok(frame) => {
                        let writers = mlock(&state.writers);
                        match writers.get(peer_node) {
                            Some(tx) => {
                                queue_peer_frames(tx, vec![bind, frame], MAX_FRAME_BYTES).err()
                            }
                            None => Some("peer_send_dropped:no_link"),
                        }
                    }
                    Err(_) => Some("peer_send_dropped:frame_too_large"),
                }
            }
            _ => Some("peer_send_dropped:malformed_gx_chunk"),
        };
    if let Some(event) = disposition {
        publish_peer_event(state, peer_node, event);
    }
    Outcome::none()
}

fn install_gx_route(state: &TransportState, peer: &NodeId, bind: GxRouteBind) {
    if let Some(reason) = bind.shape_error() {
        eprintln!("transport-tcp: rejected GX route bind from peer {}: {reason}", peer.0);
        publish_peer_event(state, peer, "gx_route_bind_dropped:malformed");
        return;
    }
    let incoming = GxRoute {
        target: bind.target,
        schema: bind.schema,
        corr: bind.corr,
        total_chunks: bind.total_chunks,
    };
    let mut event = None;
    {
        let mut routes = mlock(&state.gx_routes);
        let key = (peer.clone(), bind.transfer_id.clone());
        if let Some(existing) = routes.get(&key) {
            if existing != &incoming {
                event = Some("gx_route_bind_dropped:conflict");
            }
        } else {
            let peer_routes = routes.keys().filter(|(route_peer, _)| route_peer == peer).count();
            if peer_routes >= MAX_GX_ROUTES_PER_PEER {
                event = Some("gx_route_bind_dropped:capacity");
            } else {
                routes.insert(key, incoming);
            }
        }
    }
    if let Some(event) = event {
        publish_peer_event(state, peer, event);
    }
}

fn deliver_gx_chunk_locally(
    state: &TransportState,
    peer: &NodeId,
    header: gawdxfer::ChunkFrameHeader,
    payload: &[u8],
) {
    let route_key = (peer.clone(), header.transfer_id.clone());
    let route = mlock(&state.gx_routes).get(&route_key).cloned();
    let Some(route) = route else {
        publish_peer_event(state, peer, "gx_chunk_dropped:no_route");
        return;
    };
    if let Some(expected) = route.total_chunks {
        match header.total_chunks {
            Some(actual) if actual == expected => {}
            _ => {
                mlock(&state.gx_routes).remove(&route_key);
                publish_peer_event(state, peer, "gx_chunk_dropped:route_mismatch");
                return;
            }
        }
    }
    let retire_route = route
        .total_chunks
        .is_some_and(|total_chunks| header.chunk_index == total_chunks.saturating_sub(1));
    let actual_hash = gawdxfer::hash_bytes(payload);
    if actual_hash != header.chunk_hash {
        publish_peer_event(state, peer, "gx_chunk_dropped:hash_mismatch");
        if retire_route {
            mlock(&state.gx_routes).remove(&route_key);
        }
        return;
    }
    let body = match gawdxfer::encode_binary_frame(&header, payload) {
        Ok(body) => body,
        Err(_) => {
            publish_peer_event(state, peer, "gx_chunk_dropped:frame_encode_failed");
            if retire_route {
                mlock(&state.gx_routes).remove(&route_key);
            }
            return;
        }
    };
    let mut dispatch =
        Dispatch::to(Address::Creature(route.target), body).with_schema(route.schema);
    if let Some(corr) = route.corr {
        dispatch = dispatch.with_corr(corr);
    }

    let bus = mlock(&state.bus).as_ref().cloned();
    if let Some(bus) = bus {
        if let Err(e) = bus.emit(dispatch) {
            eprintln!(
                "transport-tcp: inbound GX chunk from peer {} for transfer {} dropped on local route: {e}",
                peer.0, header.transfer_id
            );
        }
    }
    if retire_route {
        mlock(&state.gx_routes).remove(&route_key);
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
                let Some(handshake_slot) = state.inbound_handshakes.try_acquire() else {
                    // The peer is unauthenticated, so there is no trustworthy identity to name in
                    // an event. Refuse synchronously: do not queue a socket or spawn a thread that
                    // would let a slow scanner grow resource use beyond the aggregate cap.
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                };
                configure_stream_for_transport(&stream);
                let state_h = state.clone();
                let h = match Builder::new()
                    .name("transport-handshake-server".into())
                    .spawn(move || server_handshake_and_run(state_h, stream, handshake_slot))
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
                configure_stream_for_transport(&stream);
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

fn server_handshake_and_run(
    state: Arc<TransportState>,
    mut stream: TcpStream,
    handshake_slot: InboundHandshakeSlot,
) {
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

    // Authenticated. Hand the stream off to the per-peer reader/writer pair, carrying the pubkey the
    // client just proved possession of so inbound frames are verified under the *connection's* key.
    // It no longer consumes an unauthenticated-handshake slot while connection workers are installed.
    drop(handshake_slot);
    install_connection(state, stream, client_node, client_pubkey_hex);
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

    // Authenticated. `server_pubkey_hex` was checked equal to the configured `peer.pubkey_hex`, so
    // it is the key the server proved possession of — carry it for inbound origin verification.
    install_connection(state, stream, peer.node_id.clone(), server_pubkey_hex);
}

fn configure_stream_for_transport(stream: &TcpStream) {
    // The wire carries many small control/bind frames interleaved with bulk GX chunks. Waiting for
    // Nagle/delayed-ACK coalescing turns a 12 MiB local transfer into many poll-sized stalls.
    let _ = stream.set_nodelay(true);
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

fn install_connection(
    state: Arc<TransportState>,
    stream: TcpStream,
    peer: NodeId,
    peer_pubkey: String,
) {
    configure_stream_for_transport(&stream);
    // Reset stream timeouts for the run phase — short reads/writes are how we wake on shutdown.
    let _ = stream.set_read_timeout(Some(POLL));
    let _ = stream.set_write_timeout(Some(POLL));

    let (tx, rx) = sync_channel::<PeerFrame>(PEER_QUEUE_DEPTH);

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

    // A fresh handshake is a new link session: the sender's per-`BusHandle` `seq` restarts from 0,
    // so clear any stale replay watermarks for this peer before the reader starts admitting frames.
    reset_origin_watermarks(&state, &peer);

    publish_peer_event(&state, &peer, "peer_connected");

    // Cluster mode: sync our member view to the newcomer so membership propagates over the mesh.
    if state.gossip.load(Ordering::Relaxed) {
        gossip_to_peer(&state, &peer);
    }

    // Reader: pull envelopes off the wire and route them locally.
    let state_r = state.clone();
    let peer_r = peer.clone();
    let peer_pubkey_r = peer_pubkey.clone();
    let h_r = match Builder::new()
        .name(format!("transport-reader-{}", peer.0))
        .spawn(move || reader_loop(state_r, reader_stream, peer_r, peer_pubkey_r))
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

fn reader_loop(
    state: Arc<TransportState>,
    mut stream: TcpStream,
    peer: NodeId,
    peer_pubkey: String,
) {
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
            // Cap absurd frame sizes (R9: hostile peer doesn't get to OOM us). 128 MiB is roomy
            // for the ship-an-artifact case (an echo-daemon debug `.so` is ~16 MB, the
            // envelope JSON with hex-encoded payload is ~33 MB) and bounded enough to refuse a
            // billion-byte-prefix attack. A future policy makes this operator-injectable.
            break;
        }
        let mut payload = vec![0u8; n];
        if read_exact_with_stop(&state, &mut stream, &mut payload).is_err() {
            break;
        }
        match parse_wire_payload(&payload) {
            Some(ParsedWireFrame::Env(env)) => deliver_locally(&state, *env, &peer, &peer_pubkey),
            Some(ParsedWireFrame::Gossip { members }) => {
                // Membership only matters in cluster mode; a static node ignores stray gossip.
                if state.gossip.load(Ordering::Relaxed) {
                    ingest_gossip(&state, members);
                }
            }
            Some(ParsedWireFrame::GxBind(bind)) => install_gx_route(&state, &peer, bind),
            // GX chunks only route after an authenticated peer has installed a bounded route binding
            // for the transfer id. This preserves the raw lane without letting arbitrary chunks choose
            // their own local destination.
            Some(ParsedWireFrame::GxChunk(header, payload)) => {
                deliver_gx_chunk_locally(&state, &peer, header, payload);
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
    mlock(&state.gx_routes).retain(|(route_peer, _), _| route_peer != &peer);
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
    rx: Receiver<PeerFrame>,
    peer: NodeId,
) {
    'writer: loop {
        if state.stop.load(Ordering::Relaxed) {
            break;
        }
        let batch = match rx.recv_timeout(POLL) {
            Ok(b) => b,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        for bytes in batch.frames {
            let len = (bytes.len() as u32).to_le_bytes();
            if write_all_with_stop(&state, &mut stream, &len).is_err()
                || write_all_with_stop(&state, &mut stream, &bytes).is_err()
            {
                break 'writer;
            }
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
fn deliver_locally(state: &TransportState, env: Envelope, peer: &NodeId, peer_pubkey: &str) {
    enum InboundTarget {
        Creature(CreatureId),
        RemoteRole(Role),
    }

    let target = match &env.header.to {
        Address::Node(node, mid) if *node == state.self_node => InboundTarget::Creature(*mid),
        Address::Node(node, _mid) => {
            eprintln!(
                "transport-tcp: dropped an inbound frame from peer {} addressed to node {}, \
                 but this transport is node {}",
                peer.0, node.0, state.self_node.0
            );
            return;
        }
        Address::NodeRole(node, role) if *node == state.self_node => {
            InboundTarget::RemoteRole(role.clone())
        }
        Address::NodeRole(node, _role) => {
            eprintln!(
                "transport-tcp: dropped an inbound remote-role frame from peer {} addressed to \
                 node {}, but this transport is node {}",
                peer.0, node.0, state.self_node.0
            );
            return;
        }
        // The router should never deliver another address grain here; if it does we drop it
        // (re-routing locally would be undefined intent) but make the contract violation visible.
        other => {
            eprintln!(
                "transport-tcp: dropped an inbound non-node-scoped envelope addressed {other:?} \
                 from peer {}",
                peer.0
            );
            return;
        }
    };

    // Clone the `Arc<dyn Bus>` out and DROP the guard before resolving/emitting — either operation
    // re-enters host routing state, so holding `state.bus` across it would serialize every peer.
    let bus = mlock(&state.bus).as_ref().cloned();
    let Some(bus) = bus else { return };

    let target_mid = match target {
        InboundTarget::Creature(mid) => mid,
        InboundTarget::RemoteRole(role) => {
            // Remote capability resolution is inseparable from authenticated immediate-peer
            // attribution. An ordinarily loaded transport may continue numeric relay for backwards
            // compatibility, but it cannot resolve a host role or silently shed origin evidence.
            if !bus.may_attest() {
                eprintln!(
                    "transport-tcp: refused remote role `{}` from peer {} because this transport \
                     lacks the boot attestation grant",
                    role.0, peer.0
                );
                publish_peer_event(state, peer, "remote_role_non_attesting_dropped");
                return;
            }
            let Some(mid) = bus.remote_role_target(&role) else {
                eprintln!(
                    "transport-tcp: refused unexposed or unbound remote role `{}` from peer {}",
                    role.0, peer.0
                );
                publish_peer_event(state, peer, "remote_role_unexposed_dropped");
                return;
            };
            mid
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

    // Capture what we need from the header *before* the payload moves into the dispatch builder:
    // the correlation fields, the sender's per-link `seq` (replay guard) and original `from`
    // creature, and — crucially — the signature over the *un-rewritten* bytes (the exact bytes the
    // sender signed), which is verifiable here under the peer's handshake-authenticated key.
    let corr = env.header.corr;
    let seq = env.header.seq;
    let sender_creature = match &env.header.from {
        Address::Creature(c) => *c,
        other => {
            eprintln!(
                "transport-tcp: dropped an inbound frame from peer {} with non-creature \
                 original sender {other:?}",
                peer.0
            );
            publish_peer_event(state, peer, "frame_bad_from_dropped");
            return;
        }
    };
    // Verify against the connection-authenticated pubkey, NOT a mutable member-table lookup — so a
    // later gossip pubkey change can never retroactively flip a live link's verdict.
    let sig_ok = !peer_pubkey.is_empty()
        && Ed25519Verifier.verify(peer_pubkey, &env.signing_payload(), &env.header.sig);

    // Rewrite `reply_to`: a `Creature(mid)` from the peer means "mid on the peer node" from our POV.
    // Recurses through `Realm`/`Omega` wrappers so a cross-Realm `reply_to` is rewritten at any depth
    // (ADR-0039), not just a bare `Creature`.
    let reply_to = env.header.reply_to.clone().map(|rt| rewrite_inbound_target(rt, peer));
    let commitment = env.header.commitment.clone();
    let schema = env.header.schema.clone();

    let mut dispatch = Dispatch::to(Address::Creature(target_mid), env.payload).with_schema(schema);
    if let Some(rt) = reply_to {
        dispatch = dispatch.with_reply_to(rt);
    }
    if let Some(corr) = corr {
        dispatch = dispatch.with_corr(corr);
    }
    if let Some(commit) = commitment {
        dispatch = dispatch.with_commitment(commit);
    }

    // A transport loaded *without* the boot-only attestation grant relays numeric Node traffic as
    // before — no origin, no verdict. NodeRole was already refused above: resolving a capability
    // without authenticated immediate-peer attribution would silently weaken its contract.
    if !bus.may_attest() {
        if let Err(e) = bus.emit(dispatch) {
            eprintln!(
                "transport-tcp: inbound frame from peer {} to creature {target_mid:?} \
                 (corr={corr:?}) dropped on local route: {e}",
                peer.0
            );
        }
        return;
    }

    // Replay guard (wire-integrity, like the KERNEL_ID refusal): a frame whose `seq` does not
    // advance the per-(node, sender) high-water mark is dropped. Reset on reconnect handles the
    // legitimate `seq` restart of a fresh link session.
    if is_replayed_seq(state, peer, sender_creature, seq) {
        publish_peer_event(state, peer, "frame_replay_dropped");
        return;
    }

    // Non-enforcing origin verdict: stamp the *authenticated* peer (never the frame's own claim) and
    // publish the judgement for an injected policy to act on. `Unresolved` should be unreachable on
    // an authenticated link — its appearance signals a member/connection desync.
    let verdict = if peer_pubkey.is_empty() {
        OriginVerdict::Unresolved
    } else if sig_ok {
        OriginVerdict::Verified
    } else {
        OriginVerdict::BadSig
    };
    publish_origin_verdict(state, peer, target_mid, corr, verdict);

    if let Err(e) = bus.emit_attested(dispatch, Origin::node(peer.clone())) {
        eprintln!(
            "transport-tcp: inbound frame from peer {} to creature {target_mid:?} \
             (corr={corr:?}) dropped on local route: {e}",
            peer.0
        );
    }
}

/// Rewrite an inbound address's *sender-local* grain to *our* point of view: a peer's `Creature(mid)`
/// is `Node(peer, mid)` from here. Recurses through `Realm` / `Omega` wrappers so a nested target
/// (e.g. a cross-Realm `reply_to`) is rewritten at any depth while the federation wrapper is preserved
/// (ADR-0039). Recursion terminates because depth is bounded by the kernel's address-depth cap (the
/// frame was already accepted, so it is within that bound). Any other address kind is left unchanged.
fn rewrite_inbound_target(addr: Address, peer: &NodeId) -> Address {
    match addr {
        Address::Creature(mid) => Address::Node(peer.clone(), mid),
        Address::Realm { realm, target } => {
            Address::Realm { realm, target: Box::new(rewrite_inbound_target(*target, peer)) }
        }
        Address::Omega { realm, target } => {
            Address::Omega { realm, target: Box::new(rewrite_inbound_target(*target, peer)) }
        }
        other => other,
    }
}

/// Replay-guard check: returns `true` (drop) when `seq` does not advance the high-water mark for
/// `(peer, sender)`, else records it and returns `false`. Monotone per sender within a link session.
///
/// **Scope (ADR-0040): this guard is session-scoped, not cross-session.** It prevents replay *within*
/// an authenticated link session; a fresh handshake wipes the marks for that peer
/// ([`reset_origin_watermarks`]) so a legitimately restarted `seq` stream isn't mistaken for a replay.
/// The consequence is deliberate and specified: a peer that crashes and reconnects *can* re-present a
/// frame from a previous session with a `seq` the cleared map no longer remembers. The bus does **not**
/// promise exactly-once delivery across reconnects — components that need it dedup at the application
/// layer on `corr` (the SEER/dialogue reduction theorem already keys on `corr`). Adding durable
/// per-peer watermarks / generation tokens is the future option if a concrete need arises; it is out of
/// scope here because it trades a memory-only transport for durable state and a stale-mark failure mode.
fn is_replayed_seq(state: &TransportState, peer: &NodeId, sender: CreatureId, seq: u64) -> bool {
    let mut wm = mlock(&state.origin_seq);
    let key = (peer.clone(), sender);
    match wm.get(&key) {
        Some(&last) if seq <= last => true,
        _ => {
            wm.insert(key, seq);
            false
        }
    }
}

/// Drop a peer's replay watermarks — called when a fresh handshake installs, so the new session's
/// restarted `seq` stream is not mistaken for a replay of the previous one.
fn reset_origin_watermarks(state: &TransportState, peer: &NodeId) {
    mlock(&state.origin_seq).retain(|(node, _), _| node != peer);
}

/// Publish a non-enforcing [`OriginEvent`] on `PROPRIOCEPTION` (mirrors [`publish_peer_event`]).
fn publish_origin_verdict(
    state: &TransportState,
    origin_node: &NodeId,
    target: CreatureId,
    corr: Option<u64>,
    verdict: OriginVerdict,
) {
    let ev = OriginEvent { origin_node: origin_node.clone(), target, corr, verdict };
    let payload = aether::wire::to_bytes(&ev);
    let bus = mlock(&state.bus).as_ref().cloned();
    let Some(bus) = bus else { return };
    let _ = bus.emit(
        Dispatch::to(Address::Topic(Topic::new(Topic::PROPRIOCEPTION)), payload)
            .with_schema(ORIGIN_EVENT_SCHEMA),
    );
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

fn validate_cluster_node_id(node_id: &NodeId) -> Option<&'static str> {
    let s = node_id.0.as_str();
    if s.is_empty() {
        return Some("empty node id");
    }
    if s.len() > MAX_MEMBER_NODE_ID_BYTES {
        return Some("node id exceeds transport member byte cap");
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return Some("node id contains characters outside [A-Za-z0-9._-]");
    }
    None
}

fn canonical_peer_pubkey(pubkey_hex: &str) -> Option<String> {
    let bytes = hex_decode(pubkey_hex)?;
    if bytes.len() != PUBKEY_BYTES {
        return None;
    }
    Some(hex_encode(&bytes))
}

fn validate_member_addr(addr: &str) -> Option<&'static str> {
    if addr.is_empty() {
        return Some("empty dial address");
    }
    if addr.len() > MAX_MEMBER_ADDR_BYTES {
        return Some("dial address exceeds transport member byte cap");
    }
    if addr.bytes().any(|b| b.is_ascii_control()) {
        return Some("dial address contains control characters");
    }
    if addr.parse::<std::net::SocketAddr>().is_err() {
        return Some("dial address is not an IP socket address");
    }
    None
}

fn validate_member_shape(
    node_id: &NodeId,
    pubkey_hex: &str,
    addr: &str,
) -> Result<String, &'static str> {
    if let Some(reason) = validate_cluster_node_id(node_id) {
        return Err(reason);
    }
    let pubkey_hex = canonical_peer_pubkey(pubkey_hex).ok_or("malformed ed25519 pubkey")?;
    if let Some(reason) = validate_member_addr(addr) {
        return Err(reason);
    }
    Ok(pubkey_hex)
}

fn admit_member(
    state: &Arc<TransportState>,
    node_id: &NodeId,
    pubkey_hex: &str,
    addr: &str,
) -> AdmitMemberResult {
    let pubkey_hex = match validate_member_shape(node_id, pubkey_hex, addr) {
        Ok(pk) => pk,
        Err(reason) => {
            eprintln!("transport-tcp: refusing malformed cluster member ({reason})");
            return AdmitMemberResult::Refused;
        }
    };
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
                    MemberInfo { pubkey_hex: pubkey_hex.clone(), addr: addr.to_string() },
                );
                AdmitMemberResult::Changed
            }
        }
    };
    // Keep the handshake allowlist current (idempotent) so this peer can connect either direction.
    if result != AdmitMemberResult::Refused {
        mlock(&state.peers_by_pubkey).insert(pubkey_hex, node_id.clone());
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
        let _ = queue_peer_frame(tx, frame, MAX_FRAME_BYTES);
    }
}

/// Push a gossip frame to every connected peer (used when membership changes, so it propagates).
fn gossip_broadcast(state: &Arc<TransportState>) {
    let frame = WireFrame::Gossip { members: member_gossip(state) }.to_bytes();
    for tx in mlock(&state.writers).values() {
        let _ = queue_peer_frame(tx, frame.clone(), MAX_FRAME_BYTES);
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
        let admitted = admit_member(state, &node_id, &m.pubkey_hex, &m.addr);
        if admitted == AdmitMemberResult::Changed {
            let pubkey_hex = canonical_peer_pubkey(&m.pubkey_hex).unwrap_or(m.pubkey_hex);
            any_new = true;
            spawn_dialer(state, PeerConfig { node_id, pubkey_hex, dial_addr: Some(m.addr) });
        }
    }
    if any_new {
        gossip_broadcast(state);
    }
}

/// Handle a `transport.ctl` control op: admit/dial a peer (`Connect`) or report the graph
/// (`Members`). Replies to the op's `reply_to`.
fn handle_ctl(state: &Arc<TransportState>, env: &Envelope) -> Outcome {
    if env.payload.len() > MAX_TRANSPORT_CTL_BYTES {
        return Outcome::send(
            Dispatch::reply_to_env(
                env,
                TransportCtlReply::Rejected {
                    reason: format!(
                        "transport control payload exceeds {MAX_TRANSPORT_CTL_BYTES} byte cap"
                    ),
                }
                .to_bytes(),
            )
            .with_schema(CTL_SCHEMA),
        );
    }
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
                            reason: "transport member refused: capacity, self-admission, or malformed member shape"
                                .into(),
                        }
                        .to_bytes(),
                    )
                    .with_schema(CTL_SCHEMA),
                );
            }
            spawn_dialer(
                state,
                PeerConfig {
                    node_id: node_id.clone(),
                    pubkey_hex: canonical_peer_pubkey(&pubkey_hex).unwrap_or(pubkey_hex),
                    dial_addr: Some(addr),
                },
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
        TransportCtl::Forget { node_id } => {
            let node = NodeId(node_id);
            forget_member(state, &node);
            gossip_broadcast(state);
            Outcome::send(
                Dispatch::reply_to_env(
                    env,
                    TransportCtlReply::Forgotten { node_id: node.0 }.to_bytes(),
                )
                .with_schema(CTL_SCHEMA),
            )
        }
    }
}

/// Drop a peer: remove it from the allowlist + member set, stop dialing it, clear its replay
/// watermarks, and tear down its live link. Reversible — a later `Connect` re-admits it. Never
/// touches `self`. The inverse of [`admit_member`].
fn forget_member(state: &Arc<TransportState>, node: &NodeId) {
    if *node == state.self_node {
        return;
    }
    // Allowlist is keyed by pubkey → node; drop every pubkey mapping to this node so it can't
    // re-handshake until explicitly re-admitted.
    mlock(&state.peers_by_pubkey).retain(|_, n| n != node);
    mlock(&state.members).remove(node);
    mlock(&state.dialing).remove(node);
    reset_origin_watermarks(state, node);
    // Drop the outbound queue and slam any open socket so the reader/writer pair exits and the peer
    // sees EOF. (The reader publishes `peer_disconnected` on its way out.)
    mlock(&state.writers).remove(node);
    for s in mlock(&state.sockets).remove(node).into_iter().flatten() {
        let _ = s.shutdown(Shutdown::Both);
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

    #[test]
    fn inbound_handshake_slots_enforce_the_aggregate_cap_and_reopen_on_drop() {
        let slots = InboundHandshakeSlots::new(2);
        let first = slots.try_acquire().expect("first slot");
        let second = slots.try_acquire().expect("second slot");

        assert!(slots.try_acquire().is_none(), "the aggregate cap refuses a third handshake");
        assert_eq!(slots.active.load(Ordering::Relaxed), 2);

        drop(first);
        let replacement = slots.try_acquire().expect("dropping a guard reopens its slot");
        assert_eq!(slots.active.load(Ordering::Relaxed), 2);

        drop((second, replacement));
        assert_eq!(slots.active.load(Ordering::Relaxed), 0);

        slots.limit.store(0, Ordering::Release);
        assert!(slots.try_acquire().is_none(), "zero is an explicit refuse-all ceiling");
    }

    #[test]
    fn inbound_handshake_slot_is_released_when_the_worker_panics() {
        let slots = InboundHandshakeSlots::new(1);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = slots.try_acquire().expect("slot before panic");
            panic!("handshake worker specimen");
        }));

        assert!(panic.is_err());
        assert_eq!(slots.active.load(Ordering::Relaxed), 0);
        assert!(slots.try_acquire().is_some(), "unwinding releases capacity for the next peer");
    }

    #[test]
    fn rewrite_inbound_target_recurses_through_realm_and_omega() {
        use aether::RealmId;
        let peer = NodeId("peer-1".to_string());
        let mid = CreatureId(7);

        // Bare Creature → Node(peer, mid).
        assert_eq!(
            rewrite_inbound_target(Address::Creature(mid), &peer),
            Address::Node(peer.clone(), mid)
        );

        // Realm{ r, Creature(mid) } → Realm{ r, Node(peer, mid) } — wrapper preserved, inner rewritten.
        let realm = RealmId::new("other");
        let nested =
            Address::Realm { realm: realm.clone(), target: Box::new(Address::Creature(mid)) };
        match rewrite_inbound_target(nested, &peer) {
            Address::Realm { realm: r, target } => {
                assert_eq!(r, realm);
                assert_eq!(*target, Address::Node(peer.clone(), mid));
            }
            other => panic!("expected Realm wrapper preserved, got {other:?}"),
        }

        // Omega{ r, Creature(mid) } likewise.
        let omega =
            Address::Omega { realm: realm.clone(), target: Box::new(Address::Creature(mid)) };
        match rewrite_inbound_target(omega, &peer) {
            Address::Omega { realm: r, target } => {
                assert_eq!(r, realm);
                assert_eq!(*target, Address::Node(peer.clone(), mid));
            }
            other => panic!("expected Omega wrapper preserved, got {other:?}"),
        }

        // A non-creature inner (already Node) is left as-is — only sender-local grain is rewritten.
        let already = Address::Node(NodeId("elsewhere".to_string()), mid);
        assert_eq!(rewrite_inbound_target(already.clone(), &peer), already);
    }

    #[test]
    fn stream_configuration_enables_tcp_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        configure_stream_for_transport(&client);
        configure_stream_for_transport(&server);

        assert!(client.nodelay().unwrap(), "client stream has TCP_NODELAY enabled");
        assert!(server.nodelay().unwrap(), "server stream has TCP_NODELAY enabled");
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
            gx_routes: Mutex::new(HashMap::new()),
            origin_seq: Mutex::new(HashMap::new()),
            sockets: Mutex::new(HashMap::new()),
            bus: Mutex::new(None),
            me: Mutex::new(None),
            stop: AtomicBool::new(false),
            inbound_handshakes: InboundHandshakeSlots::new(DEFAULT_MAX_INBOUND_HANDSHAKES),
            threads: Mutex::new(Vec::new()),
        });

        let peer = NodeId("peer".into());

        // Both calls happen, simulating the race.
        install_connection(state.clone(), s1, peer.clone(), test_pubkey_hex());
        install_connection(state.clone(), s2, peer.clone(), test_pubkey_hex());

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

    #[test]
    fn peer_frame_enqueue_refuses_oversized_frames_before_queueing() {
        let (tx, rx) = sync_channel::<PeerFrame>(1);

        assert_eq!(
            queue_peer_frame(&tx, vec![1, 2, 3], 2).unwrap_err(),
            "peer_send_dropped:frame_too_large"
        );
        assert!(
            rx.try_recv().is_err(),
            "oversized frames must not be retained in the outbound queue"
        );
        assert_eq!(
            queue_peer_frame(&tx, Vec::new(), 2).unwrap_err(),
            "peer_send_dropped:empty_frame"
        );
        assert!(rx.try_recv().is_err(), "empty frames must not be retained in the outbound queue");

        queue_peer_frame(&tx, vec![1, 2], 2).unwrap();
        assert_eq!(rx.try_recv().unwrap().frames, vec![vec![1, 2]]);
    }

    #[test]
    fn peer_frame_enqueue_preserves_backpressure_and_disconnect_events() {
        let (tx, rx) = sync_channel::<PeerFrame>(1);
        queue_peer_frame(&tx, vec![1], MAX_FRAME_BYTES).unwrap();
        assert_eq!(
            queue_peer_frame(&tx, vec![2], MAX_FRAME_BYTES).unwrap_err(),
            "peer_send_dropped:backpressure"
        );
        drop(rx);
        assert_eq!(
            queue_peer_frame(&tx, vec![3], MAX_FRAME_BYTES).unwrap_err(),
            "peer_send_dropped:no_link"
        );
    }

    #[test]
    fn peer_frame_batch_enqueue_is_atomic_under_backpressure() {
        let (tx, rx) = sync_channel::<PeerFrame>(1);
        queue_peer_frame(&tx, vec![9], MAX_FRAME_BYTES).unwrap();

        assert_eq!(
            queue_peer_frames(&tx, vec![vec![1], vec![2]], MAX_FRAME_BYTES).unwrap_err(),
            "peer_send_dropped:backpressure"
        );

        assert_eq!(
            rx.try_recv().unwrap().frames,
            vec![vec![9]],
            "failed batch must not leave a partial bind frame in the queue"
        );
        assert!(rx.try_recv().is_err(), "failed batch must not enqueue any trailing frame either");
    }

    #[test]
    fn outbound_node_role_is_framed_for_its_named_peer_without_source_resolution() {
        let (key, _) = Ed25519KeyMaterial::generate().unwrap();
        let mut transport = TransportTcp::new(TransportConfig {
            self_key: key,
            self_node: NodeId("me".into()),
            listen_addr: "127.0.0.1:0".into(),
            peers: vec![],
        });
        let peer = NodeId("peer".into());
        let role = Role::new("executor");
        let (tx, rx) = sync_channel::<PeerFrame>(1);
        mlock(&transport.state.writers).insert(peer.clone(), tx);
        let target = Address::NodeRole(peer, role);

        let outcome = transport.handle(inbound_env(target.clone()));

        assert!(outcome.dispatches.is_empty());
        let queued = rx.try_recv().expect("NodeRole frame queued for the peer");
        assert_eq!(queued.frames.len(), 1);
        let Some(WireFrame::Env(envelope)) = WireFrame::parse(&queued.frames[0]) else {
            panic!("queued frame was not an envelope")
        };
        assert_eq!(envelope.header.to, target, "egress preserves the unresolved remote role");
    }

    fn gx_chunk_env(peer: &str, payload: Vec<u8>) -> Envelope {
        Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(42)),
                to: Address::Node(NodeId(peer.into()), CreatureId(77)),
                reply_to: Some(Address::Creature(CreatureId(42))),
                seq: 0,
                causal: Vec::new(),
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: GX_CHUNK_SCHEMA.into(),
                origin: None,
            },
            payload,
        }
    }

    #[test]
    fn gx_chunk_schema_queues_prefixed_raw_frame_to_peer() {
        let state = test_state("me");
        let peer = NodeId("peer".into());
        let (tx, rx) = sync_channel::<PeerFrame>(2);
        mlock(&state.writers).insert(peer.clone(), tx);

        let header =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 3, gawdxfer::hash_bytes(b"chunk"))
                .with_total_chunks(4);
        let body = gawdxfer::encode_binary_frame(&header, b"chunk").expect("encode gx body");
        let out = handle_gx_chunk_outbound(&state, &gx_chunk_env(&peer.0, body.clone()));

        assert!(out.dispatches.is_empty(), "raw GX send is transport-local");
        let queued = rx.try_recv().expect("queued gx bind+chunk batch");
        assert_eq!(queued.frames.len(), 2, "GX bind and chunk queue atomically");
        let bind = &queued.frames[0];
        match WireFrame::parse(bind) {
            Some(WireFrame::GxBind(bind)) => {
                assert_eq!(bind.transfer_id, "xfer-1");
                assert_eq!(bind.target, CreatureId(77));
                assert_eq!(bind.schema, GX_CHUNK_SCHEMA);
                assert_eq!(bind.corr, Some(7));
                assert_eq!(bind.total_chunks, Some(4));
            }
            other => panic!("expected GX route bind before raw chunk, got {other:?}"),
        }
        let queued = &queued.frames[1];
        assert!(queued.starts_with(GX_FRAME_PREFIX));
        assert_eq!(&queued[GX_FRAME_PREFIX.len()..], body.as_slice());
        match decode_gx_wire_frame(queued) {
            Some((decoded, payload)) => {
                assert_eq!(decoded, header);
                assert_eq!(payload, b"chunk");
            }
            other => panic!("expected decoded queued GX chunk, got {other:?}"),
        }
    }

    #[test]
    fn malformed_gx_chunk_payload_is_not_queued_to_peer() {
        let state = test_state("me");
        let peer = NodeId("peer".into());
        let (tx, rx) = sync_channel::<PeerFrame>(1);
        mlock(&state.writers).insert(peer.clone(), tx);

        let out = handle_gx_chunk_outbound(&state, &gx_chunk_env(&peer.0, b"not gx".to_vec()));

        assert!(out.dispatches.is_empty());
        assert!(rx.try_recv().is_err(), "malformed GX payload must not reach the peer queue");
    }

    #[test]
    fn malformed_gx_chunk_header_shape_is_not_queued_to_peer() {
        let state = test_state("me");
        let peer = NodeId("peer".into());
        let (tx, rx) = sync_channel::<PeerFrame>(1);
        mlock(&state.writers).insert(peer.clone(), tx);

        let bad_header = gawdxfer::ChunkFrameHeader::new(
            "xfer-1".into(),
            3,
            gawdxfer::hash_bytes(b"chunk").to_uppercase(),
        );
        let body = gawdxfer::encode_binary_frame(&bad_header, b"chunk").expect("encode gx body");
        let wire = prefix_gx_wire_frame(&body).expect("prefix gx body");
        assert!(
            decode_gx_wire_frame(&wire).is_none(),
            "raw GX parser rejects malformed header shape"
        );

        let out = handle_gx_chunk_outbound(&state, &gx_chunk_env(&peer.0, body));

        assert!(out.dispatches.is_empty());
        assert!(rx.try_recv().is_err(), "malformed GX header must not reach the peer queue");
    }

    #[test]
    fn gx_prefix_refuses_over_cap_frame_before_allocating_copy() {
        let max_body = MAX_FRAME_BYTES - GX_FRAME_PREFIX.len();
        assert_eq!(
            prefixed_gx_wire_frame_len(max_body).expect("exact cap is allowed"),
            MAX_FRAME_BYTES
        );
        assert_eq!(
            prefixed_gx_wire_frame_len(max_body + 1),
            Err(gawdxfer::FrameError::FrameTooLarge)
        );
        assert_eq!(
            prefixed_gx_wire_frame_len(usize::MAX),
            Err(gawdxfer::FrameError::FrameTooLarge)
        );
    }

    #[test]
    fn inbound_gx_chunk_requires_route_bind_before_local_delivery() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());
        let header =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 3, gawdxfer::hash_bytes(b"chunk"));

        deliver_gx_chunk_locally(&state, &peer, header.clone(), b"chunk");
        assert!(
            !mlock(&bus.sent).iter().any(|d| d.to == Address::Creature(CreatureId(77))),
            "unbound raw GX chunks must not choose a local target"
        );
        mlock(&bus.sent).clear();

        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(77),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(7),
                total_chunks: None,
            },
        );
        deliver_gx_chunk_locally(&state, &peer, header.clone(), b"chunk");

        let sent = mlock(&bus.sent).clone();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, Address::Creature(CreatureId(77)));
        assert_eq!(sent[0].schema, GX_CHUNK_SCHEMA);
        assert_eq!(sent[0].corr, Some(7));
        let (decoded, payload): (gawdxfer::ChunkFrameHeader, &[u8]) =
            gawdxfer::decode_binary_frame(&sent[0].payload).expect("local gx chunk payload");
        assert_eq!(decoded, header);
        assert_eq!(payload, b"chunk");
    }

    #[test]
    fn inbound_gx_route_retires_after_declared_final_chunk() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());

        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(77),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(7),
                total_chunks: Some(4),
            },
        );
        assert_eq!(mlock(&state.gx_routes).len(), 1);

        let not_final =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 2, gawdxfer::hash_bytes(b"chunk"))
                .with_total_chunks(4);
        deliver_gx_chunk_locally(&state, &peer, not_final, b"chunk");
        assert_eq!(mlock(&state.gx_routes).len(), 1, "route stays until final chunk");

        let final_chunk =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 3, gawdxfer::hash_bytes(b"chunk"))
                .with_total_chunks(4);
        deliver_gx_chunk_locally(&state, &peer, final_chunk, b"chunk");

        assert!(mlock(&state.gx_routes).is_empty(), "route retires after final chunk");
        assert_eq!(
            mlock(&bus.sent).len(),
            2,
            "both chunks were delivered before the route was retired"
        );
    }

    #[test]
    fn inbound_gx_route_drops_chunk_with_mismatched_declared_count() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());

        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(77),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(7),
                total_chunks: Some(4),
            },
        );

        let mismatched =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 0, gawdxfer::hash_bytes(b"chunk"))
                .with_total_chunks(5);
        deliver_gx_chunk_locally(&state, &peer, mismatched, b"chunk");

        assert!(
            !mlock(&bus.sent).iter().any(|d| d.to == Address::Creature(CreatureId(77))),
            "mismatched route/chunk count must not deliver to the target creature"
        );
        assert!(
            mlock(&state.gx_routes).is_empty(),
            "mismatched route state is discarded before accepting more chunks"
        );
    }

    #[test]
    fn inbound_gx_route_drops_chunk_missing_declared_count_on_counted_route() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());

        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(77),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(7),
                total_chunks: Some(4),
            },
        );

        let missing_count =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 0, gawdxfer::hash_bytes(b"chunk"));
        deliver_gx_chunk_locally(&state, &peer, missing_count, b"chunk");

        assert!(
            !mlock(&bus.sent).iter().any(|d| d.to == Address::Creature(CreatureId(77))),
            "counted routes require chunks to echo the declared count"
        );
        assert!(
            mlock(&state.gx_routes).is_empty(),
            "missing count on a counted route discards the route before accepting more chunks"
        );
    }

    #[test]
    fn inbound_gx_route_drops_chunk_with_payload_hash_mismatch() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());

        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(77),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(7),
                total_chunks: Some(1),
            },
        );

        let forged =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 0, gawdxfer::hash_bytes(b"declared"))
                .with_total_chunks(1);
        deliver_gx_chunk_locally(&state, &peer, forged, b"actual");

        assert!(
            !mlock(&bus.sent).iter().any(|d| d.to == Address::Creature(CreatureId(77))),
            "chunk whose payload does not match its header hash must not reach the local target"
        );
        assert!(
            mlock(&state.gx_routes).is_empty(),
            "a bad declared-final chunk retires the counted route instead of pinning it"
        );
    }

    #[test]
    fn inbound_gx_route_rejects_conflicting_rebind_for_active_transfer() {
        let state = test_state("me");
        let bus = attach_recording_bus(&state);
        let peer = NodeId("peer".into());

        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(77),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(7),
                total_chunks: Some(4),
            },
        );
        install_gx_route(
            &state,
            &peer,
            GxRouteBind {
                transfer_id: "xfer-1".into(),
                target: CreatureId(88),
                schema: GX_CHUNK_SCHEMA.into(),
                corr: Some(9),
                total_chunks: Some(4),
            },
        );
        mlock(&bus.sent).clear();

        let header =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 0, gawdxfer::hash_bytes(b"chunk"))
                .with_total_chunks(4);
        deliver_gx_chunk_locally(&state, &peer, header, b"chunk");

        let sent = mlock(&bus.sent).clone();
        assert!(
            sent.iter().any(|d| d.to == Address::Creature(CreatureId(77))),
            "original active route remains authoritative"
        );
        assert!(
            !sent.iter().any(|d| d.to == Address::Creature(CreatureId(88))),
            "conflicting rebind must not hijack the transfer target"
        );
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

    fn test_pubkey_hex() -> String {
        let (k, _) = Ed25519KeyMaterial::generate().unwrap();
        k.public_hex().to_string()
    }

    #[test]
    fn gossip_advertise_addr_is_shape_checked() {
        let (bad_key, _) = Ed25519KeyMaterial::generate().unwrap();
        let bad_cfg = TransportConfig {
            self_key: bad_key,
            self_node: NodeId("bad".into()),
            listen_addr: "127.0.0.1:0".into(),
            peers: vec![],
        };
        let bad = TransportTcp::new(bad_cfg).with_gossip(Some("localhost:9001".into()));
        assert!(
            bad.state.gossip.load(Ordering::Relaxed),
            "invalid advertise override must not disable gossip mode"
        );
        assert_eq!(
            mlock(&bad.state.advertise_addr).as_str(),
            "127.0.0.1:0",
            "invalid advertise override falls back to the listener address"
        );
        assert_eq!(member_gossip(&bad.state)[0].addr, "127.0.0.1:0");

        let (good_key, _) = Ed25519KeyMaterial::generate().unwrap();
        let good_cfg = TransportConfig {
            self_key: good_key,
            self_node: NodeId("good".into()),
            listen_addr: "127.0.0.1:0".into(),
            peers: vec![],
        };
        let good = TransportTcp::new(good_cfg).with_gossip(Some("[::1]:9001".into()));
        assert_eq!(mlock(&good.state.advertise_addr).as_str(), "[::1]:9001");
        assert_eq!(member_gossip(&good.state)[0].addr, "[::1]:9001");
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
                origin: None,
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
            "",
        );
        assert!(
            mlock(&bus.sent).is_empty(),
            "wrong-node frames must be refused at the wire boundary"
        );

        deliver_locally(
            &state,
            inbound_env(Address::NodeRole(NodeId("someone-else".into()), Role::new("executor"))),
            &peer,
            "",
        );
        assert!(
            mlock(&bus.sent).is_empty(),
            "wrong-node remote-role frames must be refused at the wire boundary"
        );

        deliver_locally(
            &state,
            inbound_env(Address::Node(NodeId("me".into()), KERNEL_ID)),
            &peer,
            "",
        );
        assert!(
            mlock(&bus.sent).is_empty(),
            "remote peers must not be able to address the local kernel control inbox"
        );

        deliver_locally(
            &state,
            inbound_env(Address::Node(NodeId("me".into()), CreatureId(3))),
            &peer,
            "",
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

    /// A test bus that holds the boot attestation grant: it records the attested deliveries (with the
    /// stamped origin) separately from the diagnostic events emitted on PROPRIOCEPTION.
    #[derive(Default)]
    struct AttestingBus {
        attested: std::sync::Mutex<Vec<(Dispatch, Origin)>>,
        events: std::sync::Mutex<Vec<Dispatch>>,
        remote_roles: std::sync::Mutex<HashMap<Role, CreatureId>>,
    }

    impl Bus for AttestingBus {
        fn emit(&self, d: Dispatch) -> Result<(), aether::BusError> {
            mlock(&self.events).push(d);
            Ok(())
        }
        fn whoami(&self) -> CreatureId {
            CreatureId(999)
        }
        fn emit_attested(&self, d: Dispatch, origin: Origin) -> Result<(), aether::BusError> {
            mlock(&self.attested).push((d, origin));
            Ok(())
        }
        fn may_attest(&self) -> bool {
            true
        }
        fn remote_role_target(&self, role: &Role) -> Option<CreatureId> {
            mlock(&self.remote_roles).get(role).copied()
        }
    }

    fn attach_attesting_bus(state: &Arc<TransportState>) -> Arc<AttestingBus> {
        let bus = Arc::new(AttestingBus::default());
        let bus_for_state: Arc<dyn Bus> = bus.clone();
        *mlock(&state.bus) = Some(bus_for_state);
        bus
    }

    /// The latest origin verdict the transport published on PROPRIOCEPTION, if any.
    fn last_verdict(bus: &AttestingBus) -> Option<OriginVerdict> {
        mlock(&bus.events).iter().rev().find_map(|d| {
            (d.schema == ORIGIN_EVENT_SCHEMA)
                .then(|| serde_json::from_slice::<OriginEvent>(&d.payload).ok())
                .flatten()
                .map(|e| e.verdict)
        })
    }

    fn saw_peer_event(bus: &AttestingBus, expected: &str) -> bool {
        mlock(&bus.events).iter().any(|d| {
            d.schema == "peer_event"
                && serde_json::from_slice::<PeerEvent>(&d.payload)
                    .ok()
                    .is_some_and(|ev| ev.event == expected)
        })
    }

    #[test]
    fn inbound_node_role_requires_attestation_and_explicit_exposure_then_tracks_rebind() {
        let peer = NodeId("node-A".into());
        let role = Role::new("executor");
        let target = Address::NodeRole(NodeId("me".into()), role.clone());

        let ordinary_state = test_state("me");
        let ordinary = attach_recording_bus(&ordinary_state);
        deliver_locally(&ordinary_state, inbound_env(target.clone()), &peer, "");
        assert!(
            !mlock(&ordinary.sent)
                .iter()
                .any(|dispatch| matches!(dispatch.to, Address::Creature(_))),
            "an ordinary transport never resolves a remote role"
        );
        assert!(mlock(&ordinary.sent).iter().any(|dispatch| {
            dispatch.schema == "peer_event"
                && serde_json::from_slice::<PeerEvent>(&dispatch.payload)
                    .ok()
                    .is_some_and(|event| event.event == "remote_role_non_attesting_dropped")
        }));

        let state = test_state("me");
        let bus = attach_attesting_bus(&state);
        deliver_locally(&state, inbound_env(target.clone()), &peer, "");
        assert!(mlock(&bus.attested).is_empty(), "unexposed role is not delivered");
        assert!(saw_peer_event(&bus, "remote_role_unexposed_dropped"));

        mlock(&bus.remote_roles).insert(role.clone(), KERNEL_ID);
        deliver_locally(&state, inbound_env(target.clone()), &peer, "");
        assert!(mlock(&bus.attested).is_empty(), "role exposure cannot bypass KERNEL_ID refusal");

        mlock(&bus.remote_roles).insert(role.clone(), CreatureId(33));
        let bad_pubkey = test_pubkey_hex();
        deliver_locally(&state, inbound_env(target.clone()), &peer, &bad_pubkey);
        {
            let attested = mlock(&bus.attested);
            assert_eq!(attested.len(), 1);
            assert_eq!(attested[0].0.to, Address::Creature(CreatureId(33)));
            assert_eq!(attested[0].1, Origin::node(peer.clone()));
        }
        assert_eq!(
            last_verdict(&bus),
            Some(OriginVerdict::BadSig),
            "remote-role delivery preserves the existing non-enforcing verdict posture"
        );

        mlock(&bus.remote_roles).insert(role, CreatureId(44));
        let mut rebound = inbound_env(target);
        rebound.header.seq = 1;
        deliver_locally(&state, rebound, &peer, &bad_pubkey);
        let attested = mlock(&bus.attested);
        assert_eq!(attested.len(), 2);
        assert_eq!(
            attested[1].0.to,
            Address::Creature(CreatureId(44)),
            "each frame resolves the host's current exposed binding"
        );
    }

    /// An inbound frame to `CreatureId(3)` on this node, signed by `key`, optionally carrying a
    /// (forged) self-claimed `origin` in its header.
    fn signed_inbound_env(key: &Ed25519KeyMaterial, seq: u64, claimed: Option<&str>) -> Envelope {
        let mut env = Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(42)),
                to: Address::Node(NodeId("me".into()), CreatureId(3)),
                reply_to: Some(Address::Creature(CreatureId(7))),
                seq,
                causal: Vec::new(),
                stamp: 0,
                sig: String::new(),
                corr: Some(55),
                commitment: None,
                schema: "test.schema".into(),
                origin: claimed.map(|n| Origin::node(NodeId(n.into()))),
            },
            payload: b"payload".to_vec(),
        };
        env.header.sig = key.sign(&env.signing_payload());
        env
    }

    #[test]
    fn attested_delivery_stamps_the_authenticated_peer_and_verifies_the_signature() {
        let state = test_state("me");
        let bus = attach_attesting_bus(&state);
        let (key, _) = Ed25519KeyMaterial::generate().unwrap();
        let peer = NodeId("node-A".into());

        // The frame even *claims* to be from a different node ("evil"); the transport must ignore the
        // claim and stamp the peer the handshake authenticated.
        let env = signed_inbound_env(&key, 1, Some("evil"));
        deliver_locally(&state, env, &peer, key.public_hex());

        let attested = mlock(&bus.attested).clone();
        assert_eq!(attested.len(), 1, "the frame was delivered via the attested path");
        assert_eq!(
            attested[0].1,
            Origin::node(peer.clone()),
            "origin is the authenticated peer, never the frame's self-claim"
        );
        assert_eq!(attested[0].0.to, Address::Creature(CreatureId(3)));
        assert_eq!(last_verdict(&bus), Some(OriginVerdict::Verified));
    }

    #[test]
    fn attested_delivery_flags_a_bad_signature_but_still_delivers() {
        // A frame whose signature does not verify under the authenticated peer's key earns `BadSig`.
        // The verdict is non-enforcing — the frame is still delivered; acting on it is policy.
        let state = test_state("me");
        let bus = attach_attesting_bus(&state);
        let peer = NodeId("node-A".into());
        // inbound_env carries the literal sig "sig"; pass a syntactically valid but wrong pubkey.
        let pubkey = test_pubkey_hex();
        deliver_locally(
            &state,
            inbound_env(Address::Node(NodeId("me".into()), CreatureId(3))),
            &peer,
            &pubkey,
        );
        assert_eq!(mlock(&bus.attested).len(), 1, "delivered despite the bad signature");
        assert_eq!(last_verdict(&bus), Some(OriginVerdict::BadSig));
    }

    #[test]
    fn attested_delivery_reports_unresolved_when_no_peer_key_is_available() {
        // Defensive: an authenticated link always carries a pubkey, so an empty one signals a
        // member/connection desync. It must never silently pass as `Verified`.
        let state = test_state("me");
        let bus = attach_attesting_bus(&state);
        let peer = NodeId("node-A".into());
        deliver_locally(
            &state,
            inbound_env(Address::Node(NodeId("me".into()), CreatureId(3))),
            &peer,
            "",
        );
        assert_eq!(last_verdict(&bus), Some(OriginVerdict::Unresolved));
    }

    #[test]
    fn inbound_frame_with_non_creature_sender_is_dropped_before_origin_attestation() {
        // A legitimate cross-node envelope was sealed by the peer's bus, so its original `from`
        // must be a creature id. Refuse hand-crafted wire frames with another sender shape before
        // they can bypass the per-(peer, creature) replay watermark.
        let state = test_state("me");
        let bus = attach_attesting_bus(&state);
        let (key, _) = Ed25519KeyMaterial::generate().unwrap();
        let peer = NodeId("node-A".into());
        let mut env = signed_inbound_env(&key, 1, None);
        env.header.from = Address::Role(aether::Role::new("forged"));
        env.header.sig = key.sign(&env.signing_payload());

        deliver_locally(&state, env, &peer, key.public_hex());

        assert!(mlock(&bus.attested).is_empty(), "malformed original sender is not delivered");
        assert_eq!(last_verdict(&bus), None, "no origin verdict is published for a dropped shape");
        assert!(saw_peer_event(&bus, "frame_bad_from_dropped"));
    }

    #[test]
    fn the_replay_guard_drops_a_non_advancing_seq_and_resets_on_reconnect() {
        let state = test_state("me");
        let bus = attach_attesting_bus(&state);
        let (key, _) = Ed25519KeyMaterial::generate().unwrap();
        let peer = NodeId("node-A".into());

        // Intra-session (ADR-0040): seq 1 admitted, a replay of seq 1 dropped, seq 2 admitted again.
        deliver_locally(&state, signed_inbound_env(&key, 1, None), &peer, key.public_hex());
        deliver_locally(&state, signed_inbound_env(&key, 1, None), &peer, key.public_hex());
        deliver_locally(&state, signed_inbound_env(&key, 2, None), &peer, key.public_hex());
        assert_eq!(mlock(&bus.attested).len(), 2, "the replayed seq-1 frame was dropped");

        // A fresh handshake resets the watermark, so the new session's seq-1 is admitted again.
        reset_origin_watermarks(&state, &peer);
        deliver_locally(&state, signed_inbound_env(&key, 1, None), &peer, key.public_hex());
        assert_eq!(mlock(&bus.attested).len(), 3, "post-reconnect seq-1 is not a replay");

        // ADR-0040 — the guard is SESSION-scoped, not cross-session. After a reconnect the cleared map
        // no longer remembers the previous session's frames, so re-presenting an *old-session* frame
        // (here the previous session's seq-2) is ACCEPTED, not dropped. This is the specified,
        // accepted contract: exactly-once across reconnects is an application-layer property keyed on
        // `corr`, never a transport guarantee. This assertion pins the boundary as known, not a bug.
        deliver_locally(&state, signed_inbound_env(&key, 2, None), &peer, key.public_hex());
        assert_eq!(
            mlock(&bus.attested).len(),
            4,
            "a frame from a previous session is accepted after reconnect (session-scoped guard)"
        );
    }

    #[test]
    fn forget_member_clears_the_allowlist_and_is_reversible() {
        let state = test_state("me");
        let pk = test_pubkey_hex();
        let node = NodeId("peer".into());
        assert_eq!(admit_member(&state, &node, &pk, "127.0.0.1:9000"), AdmitMemberResult::Changed);
        let canon = canonical_peer_pubkey(&pk).unwrap();
        assert_eq!(mlock(&state.peers_by_pubkey).get(&canon), Some(&node));
        assert!(mlock(&state.members).contains_key(&node));

        forget_member(&state, &node);
        assert!(
            !mlock(&state.peers_by_pubkey).contains_key(&canon),
            "a forgotten peer is off the handshake allowlist"
        );
        assert!(!mlock(&state.members).contains_key(&node), "and out of the member set");

        // Forgetting self is a no-op, and a later Connect re-admits the peer (reversible).
        forget_member(&state, &state.self_node.clone());
        assert_eq!(
            admit_member(&state, &node, &pk, "127.0.0.1:9000"),
            AdmitMemberResult::Changed,
            "Connect re-admits a forgotten peer"
        );
    }

    #[test]
    fn admit_member_is_idempotent_and_never_admits_self() {
        let state = test_state("me");
        let pk_a = test_pubkey_hex();
        let pk_me = test_pubkey_hex();
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), &pk_a, "127.0.0.1:1"),
            AdmitMemberResult::Changed,
            "first admit is a graph change"
        );
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), &pk_a, "127.0.0.1:1"),
            AdmitMemberResult::Unchanged,
            "re-admit with identical data is unchanged"
        );
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), &pk_a, "127.0.0.1:2"),
            AdmitMemberResult::Changed,
            "a changed dial addr is a graph change"
        );
        assert_eq!(
            admit_member(&state, &NodeId("me".into()), &pk_me, "127.0.0.1:9"),
            AdmitMemberResult::Refused,
            "self is never admitted"
        );
        assert_eq!(
            mlock(&state.peers_by_pubkey).get(&pk_a),
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
        let pk_a = test_pubkey_hex();
        let pk_b = test_pubkey_hex();
        state.max_members.store(1, Ordering::Relaxed);

        assert_eq!(
            admit_member(&state, &NodeId("a".into()), &pk_a, "127.0.0.1:1"),
            AdmitMemberResult::Changed
        );
        assert_eq!(
            admit_member(&state, &NodeId("b".into()), &pk_b, "127.0.0.1:2"),
            AdmitMemberResult::Refused,
            "new member refused at capacity"
        );
        assert!(!mlock(&state.members).contains_key(&NodeId("b".into())));
        assert!(
            !mlock(&state.peers_by_pubkey).contains_key(&pk_b),
            "refused member must not enter the handshake allowlist"
        );

        assert_eq!(
            admit_member(&state, &NodeId("a".into()), &pk_a, "127.0.0.1:3"),
            AdmitMemberResult::Changed,
            "existing member updates at capacity"
        );
        assert_eq!(
            mlock(&state.members).get(&NodeId("a".into())).map(|m| m.addr.clone()),
            Some("127.0.0.1:3".into())
        );

        state.max_members.store(0, Ordering::Relaxed);
        assert_eq!(
            admit_member(&state, &NodeId("b".into()), &pk_b, "127.0.0.1:2"),
            AdmitMemberResult::Changed,
            "0 is the explicit unbounded opt-out"
        );
    }

    #[test]
    fn admit_member_refuses_malformed_shape_without_retaining_it() {
        let state = test_state("me");
        let pk = test_pubkey_hex();

        assert_eq!(
            admit_member(&state, &NodeId("bad space".into()), &pk, "127.0.0.1:1"),
            AdmitMemberResult::Refused,
            "cluster node ids are bounded printable tokens"
        );
        assert_eq!(
            admit_member(&state, &NodeId("bad-pubkey".into()), "not-hex", "127.0.0.1:1"),
            AdmitMemberResult::Refused,
            "peer pubkeys must be 32-byte ed25519 hex"
        );
        assert_eq!(
            admit_member(&state, &NodeId("bad-addr".into()), &pk, "localhost:9001"),
            AdmitMemberResult::Refused,
            "the dialer only accepts IP socket addresses, so reject other address shapes early"
        );

        assert!(mlock(&state.members).is_empty(), "malformed members must not be retained");
        assert!(
            mlock(&state.peers_by_pubkey).is_empty(),
            "malformed members must not enter the handshake allowlist"
        );
    }

    #[test]
    fn configured_peers_are_shape_checked_and_pubkeys_canonicalized() {
        let (self_key, _) = Ed25519KeyMaterial::generate().unwrap();
        let peer_pk = test_pubkey_hex();
        let passive_pk = test_pubkey_hex();
        let cfg = TransportConfig {
            self_key,
            self_node: NodeId("me".into()),
            listen_addr: "127.0.0.1:0".into(),
            peers: vec![
                PeerConfig {
                    node_id: NodeId("peer".into()),
                    pubkey_hex: peer_pk.to_uppercase(),
                    dial_addr: Some("127.0.0.1:9".into()),
                },
                PeerConfig {
                    node_id: NodeId("passive".into()),
                    pubkey_hex: passive_pk.clone(),
                    dial_addr: Some("localhost:10".into()),
                },
                PeerConfig {
                    node_id: NodeId("bad peer".into()),
                    pubkey_hex: test_pubkey_hex(),
                    dial_addr: Some("127.0.0.1:10".into()),
                },
            ],
        };

        let transport = TransportTcp::new(cfg);
        assert_eq!(transport.cfg.peers.len(), 2, "malformed configured peers are dropped");
        assert_eq!(transport.cfg.peers[0].pubkey_hex, peer_pk);
        assert_eq!(
            transport.cfg.peers[1].dial_addr, None,
            "peers with invalid dial addresses stay passive so bind() will not dial them"
        );
        let state = transport.state;
        assert_eq!(mlock(&state.peers_by_pubkey).get(&peer_pk), Some(&NodeId("peer".into())));
        assert_eq!(
            mlock(&state.peers_by_pubkey).get(&passive_pk),
            Some(&NodeId("passive".into())),
            "a valid peer with a bad address can still dial us inbound"
        );
        assert_eq!(
            mlock(&state.members).get(&NodeId("peer".into())).map(|m| m.pubkey_hex.clone()),
            Some(peer_pk)
        );
        assert!(
            !mlock(&state.members).contains_key(&NodeId("passive".into())),
            "invalid dial addresses do not enter the member graph"
        );
        assert!(
            !mlock(&state.members).contains_key(&NodeId("bad peer".into())),
            "malformed configured peers are ignored before retention"
        );
    }

    #[test]
    fn control_connect_replies_rejected_when_member_table_is_at_capacity() {
        let state = test_state("me");
        let pk_a = test_pubkey_hex();
        let pk_b = test_pubkey_hex();
        state.max_members.store(1, Ordering::Relaxed);
        assert_eq!(
            admit_member(&state, &NodeId("a".into()), &pk_a, "127.0.0.1:1"),
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
                origin: None,
            },
            payload: TransportCtl::Connect {
                node_id: "b".into(),
                pubkey_hex: pk_b.clone(),
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
        assert!(!mlock(&state.peers_by_pubkey).contains_key(&pk_b));
    }

    #[test]
    fn control_payload_is_capped_before_json_decode() {
        let state = test_state("me");
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
                origin: None,
            },
            payload: vec![b' '; MAX_TRANSPORT_CTL_BYTES + 1],
        };

        assert!(
            TransportCtl::parse(&env.payload).is_none(),
            "oversized control payloads are rejected before serde"
        );
        let out = handle_ctl(&state, &env);
        assert_eq!(out.dispatches.len(), 1);
        match TransportCtlReply::parse(&out.dispatches[0].payload) {
            Some(TransportCtlReply::Rejected { reason }) => {
                assert!(reason.contains("byte cap"), "reason: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(
            mlock(&state.members).is_empty(),
            "oversized control payloads must not alter the member table"
        );
    }

    #[test]
    fn control_reply_payload_is_capped_before_json_decode() {
        let payload = vec![b' '; MAX_TRANSPORT_CTL_REPLY_BYTES + 1];
        assert!(
            TransportCtlReply::parse(&payload).is_none(),
            "oversized control replies are rejected before serde"
        );

        let ok = TransportCtlReply::Members {
            self_node: "me".into(),
            members: vec![MemberView {
                node_id: "peer".into(),
                addr: "127.0.0.1:9".into(),
                connected: true,
            }],
        }
        .to_bytes();
        assert!(matches!(TransportCtlReply::parse(&ok), Some(TransportCtlReply::Members { .. })));
    }

    #[test]
    fn ingest_gossip_admits_unknown_members_and_skips_self() {
        let state = test_state("me");
        let pk_a = test_pubkey_hex();
        let pk_me = test_pubkey_hex();
        ingest_gossip(
            &state,
            vec![
                GossipMember {
                    node_id: "a".into(),
                    pubkey_hex: pk_a.clone(),
                    addr: "127.0.0.1:1".into(),
                },
                GossipMember {
                    node_id: "me".into(),
                    pubkey_hex: pk_me,
                    addr: "127.0.0.1:2".into(),
                },
            ],
        );
        assert!(mlock(&state.members).contains_key(&NodeId("a".into())), "learned `a` from gossip");
        assert!(!mlock(&state.members).contains_key(&NodeId("me".into())), "did not learn self");
        assert_eq!(mlock(&state.peers_by_pubkey).get(&pk_a), Some(&NodeId("a".into())));
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
        assert!(matches!(parse_wire_payload(&g.to_bytes()), Some(ParsedWireFrame::Gossip { .. })));

        let gx_header =
            gawdxfer::ChunkFrameHeader::new("xfer-1".into(), 3, gawdxfer::hash_bytes(b"chunk"));
        let gx = encode_gx_wire_frame(&gx_header, b"chunk").expect("encode gx frame");
        assert!(gx.starts_with(GX_FRAME_PREFIX));
        assert!(
            WireFrame::parse(&gx).is_none(),
            "GX binary frames must not be parsed as JSON wire frames"
        );
        assert!(matches!(parse_wire_payload(&gx), Some(ParsedWireFrame::GxChunk(_, _))));
        match decode_gx_wire_frame(&gx) {
            Some((header, payload)) => {
                assert_eq!(header, gx_header);
                assert_eq!(payload, b"chunk");
            }
            other => panic!("expected decoded GX chunk, got {other:?}"),
        }
    }
}
