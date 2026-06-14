//! omega — the **Ω** of GAWD: the federation apex / mesh **server** (the Ω pole's body).
//!
//! GAWD's cosmology is a **closed membrane**: `alpha` is **α** (the front door — the local operator /
//! client, where every stimulus enters and every product leaves) and `omega` is **Ω** (the federation
//! apex — the network graph of Realms, the server side). This crate is the Ω pole's *body*: a thin
//! `omega` binary that dispatches to the composition root in [`serve`], which boots a kernel
//! configured as a dedicated **federation / gateway Sanctum** — transport mesh + registry + the
//! `omega-federator` bound to [`GATEWAY_ROLE`]. It is the dual of `alpha node`: where `alpha node`
//! boots an operator/authoring seat (a REPL + the authoring organs), `omega serve` boots a headless
//! gateway that other Sanctums and Realms federate with.
//!
//! - `omega serve [flags]` — boot a federation / gateway Sanctum (see [`serve::run`]).
//! - `omega version` · `omega help`
//!
//! ## The frozen Ω wire contract lives next door
//!
//! The Ω **wire contract** — the `omega.deferred` reply, [`GATEWAY_ROLE`], and the reserved
//! [`OmegaServices`] seam — lives in the lean `omega-contract` leaf crate (just `realm` + `aether` +
//! `serde`), so a stub gateway or an orchestrator can parse it without pulling the kernel this server
//! crate depends on. It is re-exported here, so the public path `omega::deferred` /
//! `omega::GATEWAY_ROLE` / `omega::OmegaServices` keeps resolving unchanged.

pub mod serve;

pub use omega_contract::{deferred, OmegaServices, GATEWAY_ROLE};
