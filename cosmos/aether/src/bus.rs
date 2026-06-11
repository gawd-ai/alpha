//! A creature's send authority, and the signing mechanism.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::address::{Address, CreatureId};
use crate::envelope::{address_depth_error, header_size_error, Envelope, Header};
use crate::instance::Dispatch;
use crate::router::{RouteError, Router};

/// The signing **mechanism** (permission primitive). The *model* — what keys mean, the scheme — is
/// injected; the real implementation is `ring`/ed25519. Its dual is the
/// [`Verifier`](sigil::Verifier) the router invokes on delivery.
pub trait Signer: Send + Sync {
    fn sign(&self, payload: &[u8]) -> String;
    fn public_key(&self) -> String;
}

/// A stand-in: a deterministic, non-empty, **non-cryptographic** tag so a `sig` is present on
/// every envelope (**R5**). Not a real signature. Never a trust root.
pub struct StubSigner {
    pub key: String,
}

impl StubSigner {
    pub fn new(key: impl Into<String>) -> Self {
        StubSigner { key: key.into() }
    }
}

impl Signer for StubSigner {
    fn sign(&self, payload: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(self.key.as_bytes());
        h.update(payload);
        format!("stub:{:x}", h.finalize())
    }
    fn public_key(&self) -> String {
        self.key.clone()
    }
}

/// The real ed25519 signer — the production implementation of [`StubSigner`]. Mirrors the verifier's hex-on-the-
/// wire discipline so signatures and pubkeys travel through manifest JSON / CLI / config without
/// any binary handling. Cheap to clone (the underlying `Ed25519KeyMaterial` holds the 32-byte seed
/// and a precomputed pubkey hex).
pub struct Ed25519Signer {
    material: sigil::Ed25519KeyMaterial,
}

impl Ed25519Signer {
    /// Wrap an existing keypair (operator-loaded seed). The shared type with the verifier means
    /// the same material drives a creature's bus signing and the manifest provenance signing.
    pub fn new(material: sigil::Ed25519KeyMaterial) -> Self {
        Ed25519Signer { material }
    }

    /// Generate a fresh keypair for tests / first-boot. Returns `(signer, persisted_seed)`; the
    /// caller is responsible for writing the seed to a keystore if it ever needs to be reused.
    pub fn generate() -> Result<(Self, [u8; 32]), String> {
        let (material, seed) = sigil::Ed25519KeyMaterial::generate()?;
        Ok((Ed25519Signer { material }, seed))
    }

    /// The hex-encoded ed25519 public key — what a peer/verifier consumes.
    pub fn public_hex(&self) -> &str {
        self.material.public_hex()
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, payload: &[u8]) -> String {
        self.material.sign(payload)
    }
    fn public_key(&self) -> String {
        self.material.public_hex().to_string()
    }
}

/// A creature's only ambient authority: the ability to put sealed envelopes onto the bus. Handed in
/// `CreatureCtx` at `bind`. Cloning shares the per-sender `seq` counter, so order stays monotone
/// across a creature's own threads.
#[derive(Clone)]
pub struct BusHandle {
    me: CreatureId,
    seq: Arc<AtomicU64>,
    router: Arc<Router>,
    signer: Arc<dyn Signer>,
}

impl BusHandle {
    pub fn new(me: CreatureId, router: Arc<Router>, signer: Arc<dyn Signer>) -> Self {
        BusHandle { me, seq: Arc::new(AtomicU64::new(0)), router, signer }
    }

    pub fn id(&self) -> CreatureId {
        self.me
    }

    /// Seal a dispatch into an envelope (set `from` / `seq` / `sig`) and route it. `stamp` is set by
    /// the router. Returns the router's result (`NoProvider`, `NoSuchModule`, `Backpressure`, …).
    pub fn send(&self, d: Dispatch) -> Result<(), RouteError> {
        let header = Header {
            from: Address::Creature(self.me),
            to: d.to,
            reply_to: d.reply_to,
            seq: self.seq.fetch_add(1, Ordering::Relaxed),
            causal: Vec::new(),
            stamp: 0, // sealed by the router
            sig: String::new(),
            corr: d.corr,
            commitment: d.commitment,
            schema: d.schema,
        };
        // Depth first: it is a cheap iterative walk, while the size gate serializes the header —
        // a pathologically deep address must never reach the recursive serializer.
        if let Some((depth, max)) = address_depth_error(&header) {
            return Err(RouteError::TooDeep { depth, max });
        }
        if let Some((len, limit)) = header_size_error(&header) {
            return Err(RouteError::HeaderTooLarge { len, limit });
        }
        let mut env = Envelope { header, payload: d.payload };
        env.header.sig = self.signer.sign(&env.signing_payload());
        self.router.route(env)
    }
}

/// The creature-facing bus abstraction. A creature codes against this, never the concrete host
/// [`BusHandle`], so the *same* `Creature` works whether it runs in-process (a real handle) or
/// as a native `.so` (an FFI shim that serializes across the boundary) — the multi-tier seam
/// (**R1**/**R3**). Methods are `emit`/`whoami` to avoid colliding with `BusHandle`'s inherent API.
pub trait Bus: Send + Sync {
    /// Put a dispatch on the bus (the fabric seals identity/order/time/permission).
    fn emit(&self, d: Dispatch) -> Result<(), BusError>;
    /// This creature's own routing handle.
    fn whoami(&self) -> CreatureId;
}

/// A failure putting a dispatch on the bus. The in-process bus preserves the full router detail via
/// [`BusError::Route`]; the native FFI shim (which only sees a wire rc) maps to the shape-only
/// variants. A creature that wants to react to backpressure differently from `NoSuchModule` checks
/// [`BusError::is_backpressure`] / matches the shape variants — soundness of R9 depends on this
/// being observable, not just on the queue being bounded.
#[derive(Debug, thiserror::Error)]
pub enum BusError {
    /// Full router detail — in-process path only.
    #[error(transparent)]
    Route(#[from] RouteError),
    /// FFI: no creature with that id is registered.
    #[error("no such creature (ffi)")]
    NoSuchModule,
    /// FFI: nothing is bound to the role/intent socket the dispatch addresses.
    #[error("no provider bound (ffi)")]
    NoProvider,
    /// FFI: the target's inbox is full — transient; the sender may retry later.
    #[error("backpressure (ffi)")]
    Backpressure,
    /// FFI: the sender lacks a capability to address that destination.
    #[error("denied by capability (ffi)")]
    Denied,
    /// FFI lower-level failure (null pointer, deserialize, etc.) — see `RC_*` in `aether::ffi`.
    #[error("ffi send failed with code {0}")]
    Ffi(i32),
    /// Serialization failed before crossing the FFI boundary.
    #[error("serialize: {0}")]
    Serialize(String),
}

impl BusError {
    /// Whether this failure was the router refusing to enqueue because the target inbox is full.
    /// Backpressure is *transient* — the sender may retry — and is the one shape a creature is
    /// generally expected to handle differently from the others.
    pub fn is_backpressure(&self) -> bool {
        matches!(self, BusError::Backpressure | BusError::Route(RouteError::Backpressure(_)))
    }

    /// Whether this failure means the target doesn't exist (creature unloaded, no provider bound).
    /// Permanent: retrying without re-resolving the address won't help.
    pub fn is_unreachable(&self) -> bool {
        matches!(
            self,
            BusError::NoSuchModule
                | BusError::NoProvider
                | BusError::Route(RouteError::NoSuchModule(_))
                | BusError::Route(RouteError::NoProvider(_))
        )
    }
}

impl Bus for BusHandle {
    fn emit(&self, d: Dispatch) -> Result<(), BusError> {
        self.send(d).map_err(BusError::Route)
    }
    fn whoami(&self) -> CreatureId {
        self.id()
    }
}
