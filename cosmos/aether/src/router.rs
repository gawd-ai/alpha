//! The Router — the whole spine in one place: a read-mostly address table of per-creature **bounded
//! inboxes**, the IoC role-binding table, topic subscriptions, and the append-only history journal.
//! Not one global queue — the kernel owns the *table*, not the *traffic*.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use sigil::{Capabilities, Verifier};

use crate::address::{Address, CreatureId, Role, Topic};
use crate::envelope::{header_size_error, Envelope};

/// The kernel's reserved routing handle. [`Address::Kernel`] resolves here.
pub const KERNEL_ID: CreatureId = CreatureId(0);

/// Default cap on the in-memory history journal — a bounded ring (drop-oldest). The journal is an
/// append-only audit / proprioception *window*, never durable storage, so bounding it keeps a
/// long-lived node's memory `O(cap)` instead of `O(envelopes-ever-routed)`. All real consumers read
/// only `.len()` or a recent tail, so drop-oldest at a generous cap is invisible to them. (This
/// closes the direct contradiction of the crate's own "never OOM — R9" claim on the same `route()`
/// choke point that bounds the inboxes.)
const DEFAULT_JOURNAL_CAP: usize = 65_536;

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
}

pub struct Router {
    table: RwLock<HashMap<CreatureId, Registration>>,
    roles: RwLock<HashMap<Role, CreatureId>>,
    topics: RwLock<HashMap<Topic, Vec<CreatureId>>>,
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
            clock: AtomicU64::new(0),
            next_id: AtomicU64::new(KERNEL_ID.0 + 1), // ids start after the reserved kernel id
            verifier,
            inbox_capacity: inbox_capacity.max(1),
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
        wlock(&self.roles).retain(|_, v| *v != id);
        for subs in wlock(&self.topics).values_mut() {
            subs.retain(|v| *v != id);
        }
    }

    /// Bind a creature into an IoC socket (the `bind_role` hook). Plugging a strategy creature into
    /// e.g. [`Role::DISTRIBUTOR`] is how a *model* enters the fabric — the fabric supplies none.
    pub fn bind_role(&self, role: Role, id: CreatureId) {
        wlock(&self.roles).insert(role, id);
    }
    pub fn unbind_role(&self, role: &Role) {
        wlock(&self.roles).remove(role);
    }
    pub fn role_binding(&self, role: &Role) -> Option<CreatureId> {
        rlock(&self.roles).get(role).copied()
    }

    /// Whether a creature is currently routable (registered and not yet deregistered) — the
    /// observable, source-of-truth half of safe unload.
    pub fn is_registered(&self, id: CreatureId) -> bool {
        rlock(&self.table).contains_key(&id)
    }

    /// Subscribe a creature to a topic (fan-out target).
    pub fn subscribe(&self, topic: Topic, id: CreatureId) {
        wlock(&self.topics).entry(topic).or_default().push(id);
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
        rlock(&self.roles).iter().map(|(r, id)| (r.clone(), *id)).collect()
    }

    /// The one delivery method — every interaction flows through here, the single choke point for
    /// time (`stamp`), permission (verify), history (journal), and the bus-level capability check.
    pub fn route(&self, mut env: Envelope) -> Result<(), RouteError> {
        if let Some((len, limit)) = header_size_error(&env.header) {
            return Err(RouteError::HeaderTooLarge { len, limit });
        }

        // time = a change of state: every routed envelope advances the node's logical clock.
        env.header.stamp = self.clock.fetch_add(1, Ordering::Relaxed) + 1;

        // permission mechanism: verification is *invoked* on every delivery (R5). Whether a failure
        // rejects is injected policy; the default invokes the stub and proceeds.
        let _verified = self.verifier.verify(
            &public_key_of(&env.header.from),
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
            Address::Node(_, _) => {
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

fn public_key_of(_from: &Address) -> String {
    // The stub verifier ignores the key. A full implementation resolves the sender's Abode key.
    String::new()
}

/// Whether `calls` permits addressing `to`. A coarse match by destination kind/name (with `"*"`
/// as wildcard). Empty `calls` is handled by the caller (unrestricted).
fn caps_allow(calls: &[String], to: &Address) -> bool {
    // Wildcard fast-path: skip the per-envelope `format!` of the destination key when the sender is
    // unrestricted (`"*"`). This runs on every routed envelope from a capability-restricted sender.
    if calls.iter().any(|c| c == "*") {
        return true;
    }
    let want = match to {
        Address::Creature(id) => format!("creature:{}", id.0),
        Address::Node(n, _) => format!("node:{}", n.0),
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
