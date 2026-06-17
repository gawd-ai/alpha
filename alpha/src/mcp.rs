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

use aether::{
    CreatureId, Deadline, Ed25519Signer, Ed25519Verifier, Signer, StubSigner, StubVerifier,
    Verifier,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;

use omni::{boot_control, boot_manifest, boot_organs_with, AiControl, ControlTarget};
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
    // Model-backed author selection (per hub instance; needs `--features openai` to take effect).
    author: crate::AuthorFlags,
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
        author: crate::AuthorFlags::default(),
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
            "--author-model" => {
                o.author.model = Some(args.next().ok_or("--author-model needs <model-id>")?)
            }
            "--author-base-url" => {
                o.author.base_url = Some(args.next().ok_or("--author-base-url needs <url>")?)
            }
            "--author-api-key" => {
                o.author.api_key = Some(args.next().ok_or("--author-api-key needs <key>")?)
            }
            "--author-api-key-file" => {
                o.author.api_key_file =
                    Some(args.next().ok_or("--author-api-key-file needs <path>")?)
            }
            "--author-timeout-secs" => {
                let v = args.next().ok_or("--author-timeout-secs needs <seconds>")?;
                o.author.timeout_secs =
                    Some(v.parse::<u64>().map_err(|_| "--author-timeout-secs needs an integer")?);
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

    // Remote mode joins a mesh, so the hub needs a real ed25519 identity — and the bus signer must
    // be that same key so the peer can verify the hub's control envelopes under the pubkey it
    // authenticated at the handshake. Local mode never leaves the process; the stub signer suffices.
    let node_identity: Option<omni::NodeKeyBoot> = if opts.target.is_some() {
        match omni::derive_node_key(opts.cluster_key.as_deref()) {
            Ok(nk) => Some(nk),
            Err(e) => {
                eprintln!("alpha mcp: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    let (signer, verifier): (Arc<dyn Signer>, Arc<dyn Verifier>) = match &node_identity {
        Some(nk) => (Arc::new(Ed25519Signer::new(nk.key.clone())), Arc::new(Ed25519Verifier)),
        None => (Arc::new(StubSigner::new("mcp-hub")), Arc::new(StubVerifier)),
    };
    let kernel = Arc::new(Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        signer,
        verifier,
        Arc::new(policy_dev::DevPolicy),
        1024,
    ));
    if let Some(nk) = &node_identity {
        kernel.set_node_identity(nk.key.public_hex().to_string());
    }

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
            let nk = node_identity.as_ref().expect("node identity derived in remote mode");
            if let Err(e) = join_mesh(&kernel, &opts, nk) {
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
                match boot_organs_with(&kernel, false, crate::chosen_authoring(&opts.author)) {
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
fn join_mesh(
    kernel: &Arc<Kernel>,
    opts: &Opts,
    nk: &omni::NodeKeyBoot,
) -> Result<CreatureId, String> {
    let node_id = opts.node_id.clone().ok_or("--target (remote mode) requires --node-id <id>")?;
    let listen = opts.listen.clone().ok_or("--target (remote mode) requires --listen <addr>")?;
    if opts.seeds.is_empty() {
        return Err("--target (remote mode) requires at least one --seed to reach the peer".into());
    }
    // Same cluster-transport boot the α/Ω composition roots use (ADR-0044) — single source of truth.
    omni::boot_cluster(kernel, &node_id, &listen, &opts.seeds, &nk.key)
}
