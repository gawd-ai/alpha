//! `gawdxfer` - the GAWD bulk-transfer contract.
//!
//! This crate is the transport-neutral core of the existing GX/STP work from `sctl`: typed init,
//! chunk, ack, progress, resume, status, completion, and error messages; a binary chunk-frame codec;
//! chunk-count math; and streaming SHA-256 helpers. It intentionally knows nothing about TCP, HTTP,
//! WebSockets, axum, tokio, temp files, or UI progress channels.
//!
//! Alpha transports and control surfaces should adapt this contract instead of inventing local
//! one-off artifact transfer formats. Large artifacts do not belong in one hex-encoded JSON
//! envelope; they should move as bounded raw chunks with per-chunk integrity and whole-file
//! verification.
//!
//! Where this lives: `gawdxfer` is *shared GAWD foundation* (the `gawd_*` cross-system namespace),
//! not Alpha cosmology — it sits under `foundation/`, beside `cosmos/`, and `sctl` shares the same
//! contract. It is slated to externalize into its own crate/repo (and, eventually, a `gx` CLI).
//!
//! Module layout (each responsibility is its own module; tests live in `tests.rs`). The modules are
//! private; every public item is re-exported at the crate root, so the public path stays
//! `gawdxfer::Type`:
//! - `consts` — the `*_BYTES`/size caps and the `GX_*` message-type names.
//! - `wire` — the typed init / chunk / ack / progress / resume / status / list / error structs,
//!   each with a `shape_error()` pressure guard, plus the field-validation helpers they share.
//! - `frame` — the binary frame codec ([`ChunkFrameHeader`] + [`encode_binary_frame`] /
//!   [`decode_binary_frame`]).
//! - `engine` — the transfer engine: [`TransferPlan`] (sender), [`ChunkAssembler`] /
//!   [`FileChunkReceiver`] (receivers), and chunk-count math ([`compute_chunks`]).
//! - `hash` — streaming SHA-256 helpers ([`hash_bytes`] / [`hash_reader`] / [`hash_file`]).
//!
//! The boundaries are drawn so this crate externalizes cleanly: the modules above become the file
//! tree of the standalone crate unchanged.

#![forbid(unsafe_code)]

mod consts;
mod engine;
mod frame;
mod hash;
mod wire;

pub use consts::*;
pub use engine::*;
pub use frame::*;
pub use hash::*;
pub use wire::*;

#[cfg(test)]
mod tests;
