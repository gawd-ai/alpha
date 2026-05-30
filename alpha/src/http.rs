//! `alpha http` — serve the HTTP/WebSocket control plane.
//!
//! The symmetric sibling of `alpha mcp`: a node booted **headless** with the loadable `surface-http`
//! creature bound, so a web UI or any remote client drives this node's `Role::CONTROL`
//! over the bus. It delegates to the [node daemon](crate::node)'s `--listen` path with the REPL
//! disabled, so there is exactly **one** boot recipe — `alpha http --listen <addr>` is precisely
//! "`alpha node` serving only the HTTP/WS plane." All `alpha node` flags pass through (`--allow-ai`,
//! `--minimal`, `--api-key`, the cluster flags, …).

/// Run the HTTP/WS control plane to completion. `--listen <addr>` is required (it is the surface this
/// subcommand exists to serve); the REPL is forced off (`--headless`).
pub fn run(args: &[String]) -> std::io::Result<()> {
    if !args.iter().any(|a| a == "--listen") {
        eprintln!(
            "alpha http: needs --listen <addr> (e.g. 127.0.0.1:7777) — the HTTP/WS control plane to serve.\n\
             (all `alpha node` flags pass through; the REPL is disabled. Use `alpha node --listen <addr>` if you also want the local REPL.)"
        );
        std::process::exit(2);
    }
    let mut combined: Vec<String> = args.to_vec();
    if !combined.iter().any(|a| a == "--headless") {
        combined.push("--headless".to_string());
    }
    crate::node::run(&combined)
}
