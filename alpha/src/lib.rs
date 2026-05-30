//! alpha — the **α** front door library.
//!
//! The composition roots for every operator surface live here, and the `alpha` binary
//! ([`main`](../main.rs)) is a thin dispatcher over them. Each operator surface is "compose a
//! [`Kernel`] + engines + injected policy + the `omni` control core + the loadable surface creatures,
//! then run":
//!
//! - [`node`] — `alpha node`: the interactive node daemon (REPL + optional HTTP/WS + optional
//!   cluster).
//! - [`mcp`] — `alpha mcp`: the MCP control-hub (a headless sanctum whose `surface-mcp` creature owns
//!   stdio).
//! - [`http`] — `alpha http`: the HTTP/WS control plane (a headless node bound to the `surface-http`
//!   creature) — the symmetric sibling of `alpha mcp`.
//!
//! [`demo`] is different: `alpha demo [list|run <name>]` is a managed runner for the narrated demos.
//! The demos are NOT linked here — they are external crates listed in `demos/demos.json` and spawned,
//! so one is added/removed by editing that manifest, not by recompiling `alpha`.
//!
//! **Why here and not in `sanctum`?** A composition root sits *above* everything it assembles: the
//! daemon needs `omni` (the control core) and the async surfaces, and `omni` already depends on
//! `sanctum` (the kernel). Putting the daemon in the `sanctum` crate would cycle. `alpha` is **α** —
//! the outermost membrane — which is exactly where "wire it all together and run" belongs.
//!
//! [`Kernel`]: sanctum::Kernel

pub mod demo;
pub mod http;
pub mod mcp;
pub mod node;
