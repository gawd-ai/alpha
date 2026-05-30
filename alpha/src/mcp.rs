//! # alpha mcp — the Alpha MCP control-hub entry point ([`run`])
//!
//! The body `alpha mcp` invokes in-process (the hub is a subcommand of the α front
//! door, not a standalone crate).
//! What an MCP host (Claude/Codex) spawns is **itself a headless Alpha Sanctum** participating in
//! the GAWD fabric, in an MCP-control-hub profile. Its `surface-mcp` creature owns this process's
//! stdio and speaks newline-delimited JSON-RPC 2.0 to the host (NOT LSP framing); each tool call
//! becomes a `Verb` envelope on GAWD's own bus, and the `VerbResult` rides back. There is **no** REST
//! / Bearer side-channel and **no** separate shim — the consumer↔MCP edge stays the world's
//! standard, but the MCP-server↔node hop is GAWD protocol now.
//!
//! ## Two profiles
//! - **Local (default):** the hub boots its own organs + `ControlCore` and the MCP surface drives
//!   `Role::CONTROL` on this node. A fully self-contained MCP server that authors/loads/runs on
//!   itself. `--minimal` boots a bare control plane (no AUTHORING/BUILD organs).
//! - **Remote (`--target <node-id@control-id>` + `--seed …`):** the hub joins the mesh and the MCP
//!   surface routes verbs to a **peer** node's `Role::CONTROL` over the authenticated transport
//!   One control point fronting another node — the sctl-fronts-a-device model. The
//!   target node's allow-AI / admission still gate; the mesh only delivers the envelope.
//!
//! ## Flags
//! `--allow-ai` open the gate on the hub's own node (local mode) · `--minimal` no local organs ·
//! `--target <node-id@control-id>` remote mode · `--node-id <id>` `--listen <addr>` `--seed
//! <id@host:port#pubkey>` `--cluster-key <64-hex>` the hub's mesh identity (remote mode).
//!
//! **All diagnostics go to stderr** — stdout is reserved for JSON-RPC.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use aether::{CreatureId, Deadline, NodeId, Role, StubSigner, StubVerifier};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;

use omni::{boot_control, boot_manifest, boot_organs_with_monitor, AiControl, ControlTarget};
use surface_mcp::SurfaceMcp;

struct Opts {
    allow_ai: bool,
    minimal: bool,
    /// `Some((node_id, control_id))` → remote mode: front that peer node's control plane.
    target: Option<(String, u64)>,
    node_id: Option<String>,
    listen: Option<String>,
    seeds: Vec<String>,
    cluster_key: Option<String>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        allow_ai: false,
        minimal: false,
        target: None,
        node_id: None,
        listen: None,
        seeds: Vec::new(),
        cluster_key: None,
    };
    let mut args = args.iter().cloned();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--allow-ai" => o.allow_ai = true,
            "--minimal" => o.minimal = true,
            "--target" => {
                let spec = args.next().ok_or("--target needs <node-id@control-id>")?;
                let (node, id) = spec.split_once('@').ok_or(
                    "--target wants <node-id@control-id> (the peer's control creature id)",
                )?;
                let control_id = id
                    .parse::<u64>()
                    .map_err(|_| "--target control-id must be a number".to_string())?;
                if node.is_empty() {
                    return Err("--target node-id must not be empty".into());
                }
                o.target = Some((node.to_string(), control_id));
            }
            "--node-id" => o.node_id = Some(args.next().ok_or("--node-id needs <id>")?),
            "--listen" => {
                o.listen = Some(args.next().ok_or("--listen needs <addr> (e.g. 127.0.0.1:9100)")?)
            }
            "--seed" => o.seeds.push(args.next().ok_or("--seed needs <id@host:port#pubkey-hex>")?),
            "--cluster-key" => {
                o.cluster_key = Some(args.next().ok_or("--cluster-key needs <64-hex seed>")?)
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    Ok(o)
}

/// Run the MCP control-hub to completion over the given CLI args (everything after the subcommand).
/// Invoked by `alpha mcp`.
pub fn run(args: &[String]) {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("alpha mcp: {e}");
            std::process::exit(2);
        }
    };

    let kernel = Arc::new(Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("mcp-hub")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        1024,
    ));

    // Clean teardown on SIGINT/SIGTERM (the MCP host usually kills the hub at session end).
    {
        let kernel = Arc::clone(&kernel);
        let shutting = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _ = ctrlc::set_handler(move || {
            if shutting.swap(true, Ordering::SeqCst) {
                return;
            }
            kernel.shutdown_all(Deadline::default());
            std::process::exit(0);
        });
    }

    eprintln!("alpha mcp — Alpha MCP control-hub (a headless Sanctum)");

    let target = match &opts.target {
        // Remote mode: join the mesh, front the peer's control plane.
        Some((node, control_id)) => {
            if let Err(e) = join_mesh(&kernel, &opts) {
                eprintln!("alpha mcp: could not join the mesh for remote control: {e}");
                std::process::exit(1);
            }
            eprintln!("alpha mcp: remote mode — fronting node `{node}` control id {control_id} over the mesh.");
            ControlTarget::Node { node: node.clone(), control_id: *control_id }
        }
        // Local mode: this hub IS the node it controls.
        None => {
            let ai = Arc::new(AiControl::new(opts.allow_ai));
            let critter_builder = if opts.minimal {
                eprintln!("alpha mcp: local mode (--minimal) — bare control plane, no AUTHORING/BUILD organs.");
                None
            } else {
                match boot_organs_with_monitor(&kernel, false) {
                    Ok(bc) => Some(bc),
                    Err(e) => {
                        eprintln!("alpha mcp: organ boot incomplete: {e}");
                        None
                    }
                }
            };
            if let Err(e) = boot_control(&kernel, &ai, critter_builder, None) {
                eprintln!("alpha mcp: could not bind the control plane: {e}");
                std::process::exit(1);
            }
            eprintln!(
                "alpha mcp: local mode — self-contained sanctum; allow-ai is {} (grant more at a REPL on this node).",
                if ai.allowed() { "ON" } else { "OFF" }
            );
            ControlTarget::Local
        }
    };

    // Load the MCP surface creature — it owns this process's stdio and speaks JSON-RPC to the host.
    let surface = SurfaceMcp::new(target);
    let done = surface.done_flag();
    if let Err(e) = kernel.load_instance(boot_manifest("surface-mcp"), Box::new(surface)) {
        eprintln!("alpha mcp: could not load the MCP surface: {e}");
        std::process::exit(1);
    }
    eprintln!("alpha mcp: ready — speaking MCP/JSON-RPC on stdio.");

    // Park until the host closes stdin (the surface flips `done`), then shut the node down cleanly.
    while !done.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
    }
    kernel.shutdown_all(Deadline::default());
}

/// Boot the `transport-tcp` organ in gossip mode and bind it to `Role::TRANSPORT`, dialing each
/// `--seed`, so the hub joins the mesh and can reach a peer node's `Role::CONTROL` (remote mode).
fn join_mesh(kernel: &Arc<Kernel>, opts: &Opts) -> Result<CreatureId, String> {
    use sigil::{crypto, Ed25519KeyMaterial};

    let node_id = opts.node_id.clone().ok_or("--target (remote mode) requires --node-id <id>")?;
    let listen = opts.listen.clone().ok_or("--target (remote mode) requires --listen <addr>")?;
    if opts.seeds.is_empty() {
        return Err("--target (remote mode) requires at least one --seed to reach the peer".into());
    }

    let seed: [u8; 32] = match &opts.cluster_key {
        Some(hex) => {
            let bytes = crypto::hex_decode(hex)
                .filter(|b| b.len() == 32)
                .ok_or("--cluster-key must be 64 hex chars (a 32-byte seed)")?;
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes);
            s
        }
        None => crypto::fresh_seed()?,
    };
    let key = Ed25519KeyMaterial::from_seed(seed).map_err(|e| format!("hub key: {e}"))?;

    let mut peers = Vec::new();
    for s in &opts.seeds {
        let bad = || format!("bad --seed {s:?} (want node-id@host:port#pubkey-hex)");
        let (id, rest) = s.split_once('@').ok_or_else(bad)?;
        let (addr, pk) = rest.split_once('#').ok_or_else(bad)?;
        if id.is_empty() || addr.is_empty() || pk.is_empty() {
            return Err(bad());
        }
        peers.push(transport_tcp::PeerConfig {
            node_id: NodeId(id.to_string()),
            pubkey_hex: pk.to_string(),
            dial_addr: Some(addr.to_string()),
        });
    }

    let cfg = transport_tcp::TransportConfig {
        self_key: key,
        self_node: NodeId(node_id),
        listen_addr: listen.clone(),
        peers,
    };
    let transport = kernel
        .load_instance(
            boot_manifest("transport-tcp"),
            Box::new(transport_tcp::TransportTcp::new(cfg).with_gossip(Some(listen))),
        )
        .map_err(|e| format!("transport admits: {e}"))?;
    kernel.bind_role(Role::new(Role::TRANSPORT), transport);
    Ok(transport)
}
