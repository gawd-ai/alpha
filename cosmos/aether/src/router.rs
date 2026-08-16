//! The Router — the whole spine in one place: a read-mostly address table of per-creature **bounded
//! inboxes**, the IoC role-binding table, topic subscriptions, and the append-only history journal.
//! Not one global queue — the kernel owns the *table*, not the *traffic*.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use sigil::{Capabilities, Verifier};

use crate::address::{node_role_capability_key, Address, CreatureId, Role, Topic};
use crate::envelope::{address_depth_error, header_size_error, Envelope};

/// The kernel's reserved routing handle. [`Address::Kernel`] resolves here.
pub const KERNEL_ID: CreatureId = CreatureId(0);

/// Default cap on the in-memory history journal — a bounded ring (drop-oldest). The journal is an
/// append-only audit / proprioception *window*, never durable storage, so bounding it keeps a
/// long-lived node's memory `O(cap)` instead of `O(envelopes-ever-routed)`. All real consumers read
/// only `.len()` or a recent tail, so drop-oldest at a generous cap is invisible to them. (This
/// closes the direct contradiction of the crate's own "never OOM — R9" claim on the same `route()`
/// choke point that bounds the inboxes.)
const DEFAULT_JOURNAL_CAP: usize = 65_536;

/// Default cap on the number of *distinct* topics the subscription table will hold. `subscribe` is
/// host-only (the `Bus`/`BusHandle` a creature holds exposes no `subscribe`; see the field doc on
/// [`Router::topics`]), so this is **defense-in-depth + hygiene** — it stops a buggy composition-root
/// loop from growing the map without bound — not a creature-facing DoS mitigation. `0` selects the
/// explicit unbounded opt-out (lab/demo workloads only); production deployments MUST set a finite cap.
/// (The unified escape-hatch convention — see `docs/design/substrate.md`.)
const DEFAULT_MAX_TOPICS: usize = 4_096;

// ── Poison-tolerant lock acquisition (R9 fabric-integrity floor) ────────────────────────────────
// A blind `.lock().unwrap()` turns a single panic *while a holder is mid-section* into a poisoned
// lock that panics every subsequent acquire — on the bus's single choke point that cascades one
// creature's fault into total, permanent routing failure, the exact opposite of fault isolation.
// Recovering the guard (`into_inner`) is sound here because every locked section below guards plain
// owned data (`HashMap` / `VecDeque`) with no cross-field invariant a mid-section panic could leave
// half-broken. Same idiom already in-repo at `creatures/build-cargo` (`cargo_lock`).
#[inline]
fn mlock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
#[inline]
fn rlock<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}
#[inline]
fn wlock<T>(l: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|p| p.into_inner())
}

/// The receiving end of a creature's bounded inbox. The kernel moves this into the creature's drain
/// thread; a bare endpoint (the REPL, a test probe) reads it directly.
pub type InboxReceiver = Receiver<Envelope>;
type InboxSender = SyncSender<Envelope>;

struct Registration {
    inbox: InboxSender,
    caps: Capabilities,
}

#[derive(Clone, Copy)]
struct RoleBinding {
    creature: CreatureId,
    /// Host-selected remote exposure. Local role binding alone never grants this.
    remote: bool,
}

/// One row of the history primitive — the ordered header log (registry lineage is the same idea at
/// artifact grain).
#[derive(Clone, Debug)]
pub struct JournalEntry {
    pub from: Address,
    pub to: Address,
    pub seq: u64,
    pub stamp: u64,
    pub corr: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("no such creature: {0:?}")]
    NoSuchModule(CreatureId),
    #[error("no provider bound for role/hook: {0}")]
    NoProvider(String),
    #[error("inbox full (backpressure) for {0:?}")]
    Backpressure(CreatureId),
    #[error("sender {from:?} is not permitted to address that destination")]
    Denied { from: CreatureId },
    #[error("envelope header is {len} bytes, exceeds {limit} byte limit")]
    HeaderTooLarge { len: usize, limit: usize },
    #[error("envelope address nesting depth {depth} exceeds max {max}")]
    TooDeep { depth: usize, max: usize },
}

pub struct Router {
    table: RwLock<HashMap<CreatureId, Registration>>,
    /// Host-only IoC bindings. Remote exposure is one bit on the same row, so the new seam adds no
    /// remotely growable table and an ordinary rebind clears exposure by default.
    roles: RwLock<HashMap<Role, RoleBinding>>,
    /// Topic fan-out table. `subscribe` is **host-only** — the `Bus`/`BusHandle` handed to a creature
    /// exposes no `subscribe`, only `send`/`id`/`may_attest`/backpressure (`bus.rs`) — so a creature
    /// cannot grow this map. It is bounded by [`Router::max_topics`] anyway, as defense-in-depth
    /// against a buggy composition root, and subscribers are deduped per topic (idempotent subscribe).
    topics: RwLock<HashMap<Topic, Vec<CreatureId>>>,
    /// Cap on the number of *distinct* topics. A `subscribe` to a **new** topic past this is refused
    /// (no-op); existing topics still accept subscribers. `0` = unbounded opt-out. See
    /// [`DEFAULT_MAX_TOPICS`] and [`Router::with_max_topics`].
    max_topics: usize,
    /// History primitive — a **bounded** ring (drop-oldest past `journal_cap`). See
    /// [`DEFAULT_JOURNAL_CAP`].
    journal: Mutex<VecDeque<JournalEntry>>,
    /// Ring capacity for [`Router::journal`]; entries past this drop oldest-first.
    journal_cap: usize,
    /// Logical change-of-state clock — the source of every envelope's `stamp`. Never a wall clock.
    clock: AtomicU64,
    /// Next routing handle to hand out (monotone, never reused).
    next_id: AtomicU64,
    /// The verify **mechanism**, injected. Whether a failure rejects, and which
    /// keys are roots, is injected *policy* applied elsewhere.
    verifier: Arc<dyn Verifier>,
    /// This node's own bus-signing public key, set once at boot when the node has a real ed25519
    /// identity (a clustered node — its handshake key doubles as its bus signer). Unset on a
    /// local-only/dev node. Resolves [`public_key_of`](Router::public_key_of) for *local* senders so
    /// verify-on-delivery is a real check rather than always exercising the negative branch. A
    /// cross-node frame's *original* signature is verified at the transport boundary (where the
    /// peer's key is known), not here, so the router only ever needs its own key.
    local_pubkey: OnceLock<String>,
    /// Inbox capacity for newly registered creatures (bounded → backpressure, never OOM).
    inbox_capacity: usize,
}

impl Router {
    pub fn new(verifier: Arc<dyn Verifier>, inbox_capacity: usize) -> Self {
        Router {
            table: RwLock::new(HashMap::new()),
            roles: RwLock::new(HashMap::new()),
            topics: RwLock::new(HashMap::new()),
            journal: Mutex::new(VecDeque::new()),
            journal_cap: DEFAULT_JOURNAL_CAP,
            max_topics: DEFAULT_MAX_TOPICS,
            clock: AtomicU64::new(0),
            next_id: AtomicU64::new(KERNEL_ID.0 + 1), // ids start after the reserved kernel id
            verifier,
            local_pubkey: OnceLock::new(),
            inbox_capacity: inbox_capacity.max(1),
        }
    }

    /// Override the distinct-topic cap (default `DEFAULT_MAX_TOPICS`). Consuming builder, applied
    /// before the `Router` is wrapped in its `Arc`. `0` selects the explicit unbounded opt-out
    /// (lab/demo workloads only); production deployments MUST set a finite cap. (The unified
    /// escape-hatch convention — see `docs/design/substrate.md`.)
    pub fn with_max_topics(mut self, max_topics: usize) -> Self {
        self.max_topics = max_topics;
        self
    }

    /// Record this node's bus-signing public key (its ed25519 node identity). Set once at boot via
    /// `Kernel::set_node_identity`; idempotent (a second call is ignored). With it set, the internal
    /// `public_key_of` resolves local senders to this key so the verify-on-delivery mechanism actually
    /// validates the signature.
    pub fn set_local_pubkey(&self, pubkey: String) {
        let _ = self.local_pubkey.set(pubkey);
    }

    /// The public key the verifier should check `from`'s signature against. A **local** sender
    /// (`Address::Creature`) signed with this node's bus key, so it resolves to `local_pubkey` when
    /// the node has an identity (else empty, the dev/stub path). Non-local `from` addresses don't
    /// carry a resolvable key here — a cross-node frame is verified at the transport boundary, before
    /// the bus reseals `from` — so they return empty.
    fn public_key_of(&self, from: &Address) -> String {
        match from {
            Address::Creature(_) => self.local_pubkey.get().cloned().unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Register a new creature endpoint: allocate a handle, create its bounded inbox, store the
    /// sender. Returns the handle + the receiving end (the caller drives it).
    pub fn register(&self, caps: Capabilities) -> (CreatureId, InboxReceiver) {
        let id = CreatureId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = sync_channel(self.inbox_capacity);
        wlock(&self.table).insert(id, Registration { inbox: tx, caps });
        (id, rx)
    }

    /// Register the kernel's own control inbox at the reserved [`KERNEL_ID`].
    pub fn register_kernel(&self) -> InboxReceiver {
        let (tx, rx) = sync_channel(self.inbox_capacity);
        wlock(&self.table)
            .insert(KERNEL_ID, Registration { inbox: tx, caps: Capabilities::default() });
        rx
    }

    /// Remove a creature from the table. After this, routing to it yields `NoSuchModule` — the
    /// routing half of safe unload. Dropping the stored sender disconnects the inbox, so the drain
    /// thread's `recv` returns and it can exit (then the kernel joins it, then frees the library).
    pub fn deregister(&self, id: CreatureId) {
        wlock(&self.table).remove(&id);
        wlock(&self.roles).retain(|_, binding| binding.creature != id);
        for subs in wlock(&self.topics).values_mut() {
            subs.retain(|v| *v != id);
        }
    }

    /// Bind a creature into an IoC socket (the `bind_role` hook). Plugging a strategy creature into
    /// e.g. [`Role::DISTRIBUTOR`] is how a *model* enters the fabric — the fabric supplies none.
    /// This local-only form deliberately clears any prior remote exposure for the role.
    pub fn bind_role(&self, role: Role, id: CreatureId) {
        wlock(&self.roles).insert(role, RoleBinding { creature: id, remote: false });
    }
    /// Bind a role locally and explicitly expose that exact binding to an attesting transport's
    /// [`Address::NodeRole`] resolution. This is host-only; no creature or manifest can self-expose.
    pub fn bind_remote_role(&self, role: Role, id: CreatureId) {
        wlock(&self.roles).insert(role, RoleBinding { creature: id, remote: true });
    }
    pub fn unbind_role(&self, role: &Role) {
        wlock(&self.roles).remove(role);
    }
    pub fn role_binding(&self, role: &Role) -> Option<CreatureId> {
        rlock(&self.roles).get(role).map(|binding| binding.creature)
    }
    /// Resolve an explicitly remote-exposed role. The boot-granted transport reaches this only
    /// through [`crate::Bus::remote_role_target`]; ordinary creature buses fail closed.
    pub fn remote_role_binding(&self, role: &Role) -> Option<CreatureId> {
        rlock(&self.roles)
            .get(role)
            .filter(|binding| binding.remote)
            .map(|binding| binding.creature)
    }

    /// Whether a creature is currently routable (registered and not yet deregistered) — the
    /// observable, source-of-truth half of safe unload.
    pub fn is_registered(&self, id: CreatureId) -> bool {
        rlock(&self.table).contains_key(&id)
    }

    /// Subscribe a creature to a topic (fan-out target). Host-only (see the `topics` field).
    /// Idempotent — a repeat `(topic, id)` does not grow the subscriber `Vec`. Bounded by
    /// `max_topics`: once the table holds that many distinct topics, a `subscribe` to a
    /// **new** topic is refused (no-op, logged); subscribers to already-known topics still go through.
    /// `max_topics == 0` is the explicit unbounded opt-out.
    pub fn subscribe(&self, topic: Topic, id: CreatureId) {
        let mut topics = wlock(&self.topics);
        if !topics.contains_key(&topic) && self.max_topics != 0 && topics.len() >= self.max_topics {
            // Defense-in-depth: a buggy host loop cannot grow the table without bound. Drop the new
            // topic rather than block or OOM (R9 discipline), consistent with fan-out's best-effort.
            eprintln!(
                "aether: topic-subscription table at cap ({}); refusing new topic {:?}",
                self.max_topics, topic
            );
            return;
        }
        let subs = topics.entry(topic).or_default();
        if !subs.contains(&id) {
            subs.push(id);
        }
    }

    /// Whether any creature is subscribed to `topic`. Lets a hot-path publisher (the kernel's
    /// per-envelope FITNESS sense) skip serializing + routing a fan-out envelope that would reach
    /// nobody — without changing per-envelope semantics for topics that *do* have a subscriber.
    pub fn has_subscribers(&self, topic: &Topic) -> bool {
        rlock(&self.topics).get(topic).is_some_and(|subs| !subs.is_empty())
    }

    /// A copy of the history journal (for tests / proprioception / audit), oldest-first.
    pub fn journal_snapshot(&self) -> Vec<JournalEntry> {
        mlock(&self.journal).iter().cloned().collect()
    }

    /// Every current IoC role binding (for a node-status / introspection surface). Order is
    /// unspecified (it's a snapshot of a `HashMap`); callers that want a stable view sort it.
    pub fn bound_roles(&self) -> Vec<(Role, CreatureId)> {
        rlock(&self.roles).iter().map(|(role, binding)| (role.clone(), binding.creature)).collect()
    }

    /// The one delivery method — every interaction flows through here, the single choke point for
    /// time (`stamp`), permission (verify), history (journal), and the bus-level capability check.
    pub fn route(&self, mut env: Envelope) -> Result<(), RouteError> {
        // Depth before size: the depth walk is iterative and cheap; the size gate serializes the
        // header, so an overdeep address must be refused before it can reach the serializer.
        if let Some((depth, max)) = address_depth_error(&env.header) {
            return Err(RouteError::TooDeep { depth, max });
        }
        if let Some((len, limit)) = header_size_error(&env.header) {
            return Err(RouteError::HeaderTooLarge { len, limit });
        }

        // time = a change of state: every routed envelope advances the node's logical clock.
        env.header.stamp = self.clock.fetch_add(1, Ordering::Relaxed) + 1;

        // permission mechanism: verification is *invoked* on every delivery (R5). Whether a failure
        // rejects is injected policy; the default invokes the verifier and proceeds. With a node
        // identity set, `public_key_of` resolves the local key so this is a real check.
        let _verified = self.verifier.verify(
            &self.public_key_of(&env.header.from),
            &env.signing_payload(),
            &env.header.sig,
        );

        // bus-level capability at the one choke point (opt-in; empty `calls` = unrestricted).
        if let Address::Creature(from_id) = &env.header.from {
            let table = rlock(&self.table);
            if let Some(reg) = table.get(from_id) {
                if !reg.caps.calls.is_empty() && !caps_allow(&reg.caps.calls, &env.header.to) {
                    return Err(RouteError::Denied { from: *from_id });
                }
            }
        }

        // history primitive — bounded ring: append then drop-oldest past the cap so a long-lived
        // node's journal memory is O(cap), not O(envelopes-ever-routed). Lock hold stays O(1).
        {
            let mut journal = mlock(&self.journal);
            journal.push_back(JournalEntry {
                from: env.header.from.clone(),
                to: env.header.to.clone(),
                seq: env.header.seq,
                stamp: env.header.stamp,
                corr: env.header.corr,
            });
            while journal.len() > self.journal_cap {
                journal.pop_front();
            }
        }

        // deliver by address mode.
        match env.header.to.clone() {
            Address::Creature(id) => self.deliver(id, env),
            Address::Kernel => self.deliver(KERNEL_ID, env),
            Address::Topic(t) => self.fan_out(&t, env),
            Address::Role(r) => {
                let id = self.role_binding(&r).ok_or(RouteError::NoProvider(r.0))?;
                self.deliver(id, env)
            }
            Address::Intent(_) => {
                let id = self
                    .role_binding(&Role::new(Role::DISTRIBUTOR))
                    .ok_or_else(|| RouteError::NoProvider(Role::DISTRIBUTOR.to_string()))?;
                self.deliver(id, env)
            }
            Address::Node(_, _) | Address::NodeRole(_, _) => {
                let id = self
                    .role_binding(&Role::new(Role::TRANSPORT))
                    .ok_or_else(|| RouteError::NoProvider(Role::TRANSPORT.to_string()))?;
                self.deliver(id, env)
            }
            Address::Realm { .. } => {
                // Federation grain: the bound realm-gateway creature unwraps `target` and
                // re-routes — locally for same-Realm peers, via transport for cross-Realm. The
                // router's job is the same one-line dispatch as `Node → Transport`: deliver to the
                // bound IoC creature, never resolve federation itself.
                let id = self
                    .role_binding(&Role::new(Role::REALM_GATEWAY))
                    .ok_or_else(|| RouteError::NoProvider(Role::REALM_GATEWAY.to_string()))?;
                self.deliver(id, env)
            }
            Address::Omega { .. } => {
                // Federation grain: the bound omega-gateway resolves cross-Realm via Omega
                // discovery. The router's contract is identical to the Realm case — one-line
                // dispatch to the bound creature, never federation logic in the fabric. The bound
                // creature may be the stub or the real omega-federator.
                let id = self
                    .role_binding(&Role::new(Role::OMEGA_GATEWAY))
                    .ok_or_else(|| RouteError::NoProvider(Role::OMEGA_GATEWAY.to_string()))?;
                self.deliver(id, env)
            }
        }
    }

    fn deliver(&self, id: CreatureId, env: Envelope) -> Result<(), RouteError> {
        let table = rlock(&self.table);
        let reg = table.get(&id).ok_or(RouteError::NoSuchModule(id))?;
        // bounded + non-blocking: shed on overflow (never block the router, never OOM) — R9.
        match reg.inbox.try_send(env) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(RouteError::Backpressure(id)),
            Err(TrySendError::Disconnected(_)) => Err(RouteError::NoSuchModule(id)),
        }
    }

    fn fan_out(&self, topic: &Topic, env: Envelope) -> Result<(), RouteError> {
        let ids = rlock(&self.topics).get(topic).cloned().unwrap_or_default();
        let table = rlock(&self.table);
        // Fan-out is best-effort: a slow/absent subscriber never blocks the publisher (R9).
        for id in ids {
            if let Some(reg) = table.get(&id) {
                let _ = reg.inbox.try_send(env.clone());
            }
        }
        Ok(())
    }
}

/// Whether `calls` permits addressing `to`. A coarse match by destination kind/name (with `"*"`
/// as wildcard). Empty `calls` is handled by the caller (unrestricted).
fn caps_allow(calls: &[String], to: &Address) -> bool {
    // Wildcard fast-path: skip the per-envelope `format!` of the destination key when the sender is
    // unrestricted (`"*"`). This runs on every routed envelope from a capability-restricted sender.
    if calls.iter().any(|c| c == "*") {
        return true;
    }
    // `node:<id>` is the existing coarse authority to address any creature on the node, so it also
    // dominates a NodeRole call. The exact key is length-prefixed because NodeId/Role are open strings;
    // delimiter-only concatenation would make component boundaries ambiguous.
    if let Address::NodeRole(node, role) = to {
        return calls.contains(&format!("node:{}", node.0))
            || calls.contains(&node_role_capability_key(node, role));
    }
    let want = match to {
        Address::Creature(id) => format!("creature:{}", id.0),
        Address::Node(n, _) => format!("node:{}", n.0),
        Address::NodeRole(..) => unreachable!("handled above"),
        Address::Kernel => "kernel".to_string(),
        Address::Topic(t) => format!("topic:{}", t.0),
        Address::Role(r) => format!("role:{}", r.0),
        Address::Intent(i) => format!("intent:{}", i.outcome),
        // Federation grain: the cap key names the *Realm*, not the inner target
        // — the substrate's bus-level capability gate authorizes "you may speak into Realm X",
        // never "you may address every possible inner target by enumeration." A creature that
        // means "any inner target in Realm X" lists `realm:X`; cross-realm authorization is by
        // Realm, the unit at which trust actually composes. Omega keys the same way on the
        // Realm name inside the Omega address.
        Address::Realm { realm, .. } => format!("realm:{}", realm.0),
        Address::Omega { realm, .. } => format!("omega:{}", realm.0),
    };
    calls.contains(&want)
}
