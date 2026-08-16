//! `gawdfn` — shared GAWD typed-function and durable-job contracts.
//!
//! A function is a typed, signed entrypoint inside a creature. An invocation is accepted as an
//! asynchronous job whose authority lives with a home Abode. This crate contains only bounded data,
//! canonical hashing/signature helpers, and structural validation. Placement, trust, retry timing,
//! retention, prioritisation, workflow, and recovery decisions remain injected creature policy.

#![forbid(unsafe_code)]

mod consts;
mod crypto;
mod types;
mod wire;

pub use consts::*;
pub use crypto::*;
pub use types::*;
pub use wire::*;

#[cfg(test)]
mod tests;
