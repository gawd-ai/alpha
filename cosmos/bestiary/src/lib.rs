//! `bestiary` — the Bestiary contract crate **and** the durable store.
//!
//! ## Two things live here
//!
//! 1. **The registry wire vocabulary** ([`RegistryOp`], [`RegistryReply`], [`Entry`],
//!    [`SyncEntry`], [`ReputationScore`], [`QuarantineNotice`]). These were born inside the
//!    `registry-mem` *creature* but two creatures need them — the in-memory `registry-mem` stub and
//!    the durable `bestiary-daemon`. A second creature cannot reach into the first for a shared type
//!    (a creature→creature edge), so the contract lives here, in a leaf crate both depend on.
//!    `registry-mem` re-exports them (`pub use bestiary::…`) so every `registry_mem::TypeName`
//!    consumer compiles unchanged.
//!
//! 2. **The durable store** — the [`BestiaryStore`] trait and its [`FsBestiaryStore`] reference
//!    filling (a realm-hashed, signed-log, content-addressed on-disk Bestiary), the standalone
//!    [`EntryProof`] attestation, and the injected [`Curator`] seam. The `bestiary-daemon` creature
//!    binds a `BestiaryStore` to `Role::REGISTRY`, serving every existing `RegistryOp` byte-identically
//!    while persisting, replicating, and AI-curating the catalog.
//!
//! ## The load-bearing layering invariant (B-guard)
//!
//! `bestiary` depends **only** on leaf/contract crates — `aether` (the wire encoder + `Creature`
//! scaffold types), `sigil` (`Manifest`, `RealmId`, the signing/verifier primitives), and `mind` (the
//! injected [`Model`](mind::Model) seam, for the AI curator) — and **never** on a creature crate. If it
//! reached back into a creature, the `registry-mem` re-export shim would drag a cycle into the contract
//! layer. The crate sits beside the concept crates in the workspace layering, below every creature.
//!
//! ## On security: a wire-sourced Realm is **only ever hashed, never path-joined**
//!
//! [`RealmId`](sigil::RealmId) is `pub struct RealmId(pub String)` and its `is_valid()` permits `/`
//! and `..`. A Realm name reaches the store from untrusted sources (`PublishInRealm`, a pulled
//! `SyncEntry`, a pushed entry), so path-joining it would be a remote arbitrary-file-write primitive.
//! [`FsBestiaryStore`] hashes every Realm to a `sha256` hex stem and keeps the human name only inside a
//! signed sidecar index — see the [`store`] module.

pub mod curator;
pub mod op;
pub mod store;
mod wire;

pub use wire::{Entry, QuarantineNotice, RegistryOp, RegistryReply, ReputationScore, SyncEntry};

pub use curator::{AICurator, CurationContext, CurationDecision, Curator, DeterministicCurator};
pub use op::{BestiaryOp, BestiaryReply};
pub use store::{
    BestiaryStore, CompactStats, CurationSnapshot, EntryProof, FsBestiaryStore, LogOp, LogRecord,
    MergeOutcome, SignedSyncEntry, StoreError,
};

/// The `registry.op` schema string — the existing in-memory and durable stores both answer it
/// byte-identically. Provided as a named constant for the durable daemon; `registry-mem` keeps its
/// own literal (the bytes are identical).
pub const REGISTRY_OP_SCHEMA: &str = "registry.op";
/// The `registry.reply` schema string (see [`REGISTRY_OP_SCHEMA`]).
pub const REGISTRY_REPLY_SCHEMA: &str = "registry.reply";
/// The additive `bestiary.op` schema — durable-Bestiary operations with no `RegistryOp` equivalent.
pub const BESTIARY_OP_SCHEMA: &str = "bestiary.op";
/// The `bestiary.reply` schema string (see [`BESTIARY_OP_SCHEMA`]).
pub const BESTIARY_REPLY_SCHEMA: &str = "bestiary.reply";
