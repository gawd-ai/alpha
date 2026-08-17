//! The node-daemon entry point ([`run`]) — the body `alpha node` invokes (the daemon
//! is a subcommand of the α front door, not a standalone crate). Boots the kernel (three engines + an
//! injected dev policy) and, by default,
//! self-hosts its own organs ([`boot_organs_with`]) so a fresh daemon is a *live* substrate.
//! It then drives that one live kernel through the shared command core ([`run_verb`]) over up to
//! three front-ends:
//! - the **stdin REPL** — the local human seat, never gated;
//! - the **HTTP/WebSocket API** (`--listen`) — the loadable `surface-http` creature, a remote
//!   surface a future web UI or the MCP control-hub drives, subject to the allow-AI gate;
//! - **non-interactive** `--exec`/`--script` runs over the same verbs.
//!
//! `--minimal` boots the bare kernel; `--headless` runs the API with no REPL. With `--features openai`,
//! `--author-model <id>` (+ optional `--author-base-url` / `--author-api-key-file` or `--author-api-key`
//! / `--author-timeout-secs`) binds the model-backed author per node instance — see [`crate::AuthorFlags`].
//! `--functions <config.json>` explicitly composes the durable reference Function/Job organs and a
//! durable Bestiary. Its config references protected operational-key files; it never accepts an
//! Abode root private key.
//!
//! **Dev posture (disclosed at boot):** the dev policy admits everything. A non-clustered node's bus
//! signer is a stub; a clustered node (`--cluster-listen`) signs with its real ed25519 node identity
//! so peers can verify its cross-node traffic. Either way this is a developer surface, not a hardened
//! deployment.

use std::io::{BufRead, Write};
use std::sync::Arc;

use aether::{
    CreatureId, Deadline, Ed25519Signer, Ed25519Verifier, Signer, StubSigner, StubVerifier,
    Verifier,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;

use omni::{
    boot_control_with_function_deployer, boot_organs_with, parse_verb, run_verb, AiControl,
    VerbCtx, COMMANDS,
};

/// Parsed command-line options.
struct Opts {
    minimal: bool,
    headless: bool,
    allow_ai: bool,
    json: bool,
    listen: Option<String>,
    api_key: Option<String>,
    exec: Option<String>,
    script: Option<String>,
    // Explicit, root-private-key-free reference Function/Job composition.
    functions: Option<String>,
    // Clustering: present `cluster_listen` boots the transport organ + joins a mesh.
    node_id: Option<String>,
    cluster_listen: Option<String>,
    seeds: Vec<String>,
    cluster_key: Option<String>,
    // Model-backed author selection (per node instance; needs `--features openai` to take effect).
    author: crate::AuthorFlags,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        minimal: false,
        headless: false,
        allow_ai: false,
        json: false,
        listen: None,
        api_key: None,
        exec: None,
        script: None,
        functions: None,
        node_id: None,
        cluster_listen: None,
        seeds: Vec::new(),
        cluster_key: None,
        author: crate::AuthorFlags::default(),
    };
    let mut args = args.iter().cloned();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--minimal" => o.minimal = true,
            "--headless" => o.headless = true,
            "--allow-ai" => o.allow_ai = true,
            "--json" => o.json = true,
            "--listen" => {
                o.listen = Some(args.next().ok_or("--listen needs <addr> (e.g. 127.0.0.1:7777)")?)
            }
            "--api-key" => o.api_key = Some(args.next().ok_or("--api-key needs <key>")?),
            "--exec" => o.exec = Some(args.next().ok_or("--exec needs <verb>")?),
            "--script" => o.script = Some(args.next().ok_or("--script needs <file>")?),
            "--functions" => {
                o.functions = Some(args.next().ok_or("--functions needs <config.json>")?)
            }
            "--node-id" => o.node_id = Some(args.next().ok_or("--node-id needs <id>")?),
            "--cluster-listen" => {
                o.cluster_listen =
                    Some(args.next().ok_or("--cluster-listen needs <addr> (e.g. 127.0.0.1:9001)")?)
            }
            "--seed" => {
                o.seeds.push(args.next().ok_or("--seed needs <node-id@host:port#pubkey-hex>")?)
            }
            "--cluster-key" => {
                o.cluster_key = Some(args.next().ok_or("--cluster-key needs <64-hex-char seed>")?)
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

/// Run the node daemon to completion over the given CLI args (everything after the `node` subcommand).
/// Invoked by `alpha node`.
pub fn run(args: &[String]) -> std::io::Result<()> {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("alpha node: {e}");
            std::process::exit(2);
        }
    };
    if opts.minimal && opts.functions.is_some() {
        eprintln!(
            "alpha node: --minimal and --functions are mutually exclusive; the Function runtime requires the normal authoring/registry composition"
        );
        std::process::exit(2);
    }
    let function_config = match opts.functions.as_deref() {
        Some(path) => match crate::functions::load_config(path) {
            Ok(config) => Some(config),
            Err(error) => {
                eprintln!("alpha node: {error}");
                std::process::exit(2);
            }
        },
        None => None,
    };

    // One identity: when this node will cluster, derive its ed25519 node key *up front* so the bus
    // signer is the *same* key the transport authenticates links with. A peer that authenticates this
    // node at the handshake can then verify the envelopes it signs (real cross-node `Verified`). A
    // non-clustered dev node keeps the stub signer/verifier (no real crypto needed).
    let node_identity: Option<omni::NodeKeyBoot> = if opts.cluster_listen.is_some() {
        match omni::derive_node_key(opts.cluster_key.as_deref()) {
            Ok(nk) => Some(nk),
            Err(e) => {
                eprintln!("alpha node: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    let (signer, verifier): (Arc<dyn Signer>, Arc<dyn Verifier>) = match &node_identity {
        Some(nk) => (Arc::new(Ed25519Signer::new(nk.key.clone())), Arc::new(Ed25519Verifier)),
        None => (Arc::new(StubSigner::new("local-node")), Arc::new(StubVerifier)),
    };
    let kernel = Arc::new(Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        signer,
        verifier,
        Arc::new(DevPolicy),
        1024,
    ));
    if let Some(nk) = &node_identity {
        kernel.set_node_identity(nk.key.public_hex().to_string());
    }
    let ai = Arc::new(AiControl::new(opts.allow_ai));

    // Clean shutdown on SIGINT/SIGTERM (T14): the signal handler runs the kernel's reverse-order
    // `shutdown_all` and exits, turning an abrupt kill into the orderly `quit` teardown.
    {
        let kernel = Arc::clone(&kernel);
        let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let install = ctrlc::set_handler(move || {
            if shutting_down.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            eprintln!("\nalpha node: signal received — shutting down the substrate cleanly…");
            kernel.shutdown_all(Deadline::default());
            std::process::exit(0);
        });
        if let Err(e) = install {
            eprintln!("alpha node: could not install the SIGINT/SIGTERM handler ({e}); Ctrl-C will hard-kill.");
        }
    }

    // In non-interactive modes (`--exec`/`--script`) stdout must carry ONLY the verb output, so
    // `--json` is machine-parseable; boot/banner chatter goes to stderr instead. `note!` routes it.
    let quiet = opts.exec.is_some() || opts.script.is_some();
    let (probe_id, probe_bus, probe_rx) = omni::open_probe(&kernel);
    let mut out = std::io::stdout();
    macro_rules! note {
        ($($a:tt)*) => {
            if quiet {
                eprintln!($($a)*);
            } else {
                let _ = writeln!(out, $($a)*);
            }
        };
    }

    note!("alpha node — Alpha Sanctum daemon (v{})", env!("CARGO_PKG_VERSION"));
    if node_identity.is_some() {
        note!("posture: DEV — the dev policy admits everything; the bus signer is this node's real ed25519 identity (cross-node origins are verified), but admission is not hardened.");
    } else {
        note!("posture: DEV — the dev policy admits everything and the bus signer is a stub; not a hardened deployment.");
    }

    let mut critter_builder: Option<CreatureId> = None;
    if opts.minimal {
        note!("boot: --minimal — empty kernel, nothing bound (use `bind`/`load` to wire it).");
    } else {
        let authoring = crate::chosen_authoring(&opts.author);
        let author_desc = authoring.describe();
        match boot_organs_with(&kernel, !quiet, authoring) {
            Ok(bc_id) => {
                critter_builder = Some(bc_id);
                if quiet {
                    note!("boot: live substrate — {author_desc}→AUTHORING, build-cargo→BUILD (+build-critter), registry-mem→REGISTRY; stdout monitor omitted for non-interactive output.");
                } else {
                    note!("boot: live substrate — {author_desc}→AUTHORING, build-cargo→BUILD (+build-critter), registry-mem→REGISTRY, monitor watching the sense streams.");
                }
            }
            Err(e) => {
                if function_config.is_some() {
                    eprintln!(
                        "alpha node: base organ wiring failed before the requested Function runtime could start: {e}"
                    );
                    kernel.shutdown_all(Deadline::default());
                    std::process::exit(1);
                }
                note!("boot: organ wiring incomplete ({e}); some organs may already be loaded/bound — run `list` / `status` to see what actually came up.");
            }
        }
    }

    // Optionally join/form a cluster: boot the `transport-tcp` organ bound to TRANSPORT,
    // in gossip mode, dialing any `--seed`. The mesh self-completes; `cluster` reads the graph.
    let mut cluster_transport: Option<CreatureId> = None;
    if let Some(listen) = &opts.cluster_listen {
        let Some(node_id) = opts.node_id.clone() else {
            eprintln!("alpha node: --cluster-listen requires --node-id <id>");
            std::process::exit(2);
        };
        let nk = node_identity.as_ref().expect("node identity derived when clustering");
        match omni::boot_cluster(&kernel, &node_id, listen, &opts.seeds, &nk.key) {
            Ok(transport) => {
                cluster_transport = Some(transport);
                note!("cluster: node-id={node_id}  listen={listen}  seeds={}", opts.seeds.len());
                note!("cluster: node pubkey = {}", nk.key.public_hex());
                if nk.generated {
                    note!(
                        "cluster: generated a node key — reuse this identity with `--cluster-key {}`",
                        sigil::crypto::hex_encode(&nk.seed)
                    );
                }
                note!(
                    "cluster: peers join this node with  cluster join {node_id}@{listen}#{}",
                    nk.key.public_hex()
                );
                // ADR-0041: clustering is on but the reference dev composition subscribes no
                // origin-defense policy by default. Warn loudly that BadSig frames are admitted
                // absent an injected `policy-origin` (or equivalent) consumer.
                omni::warn_if_no_origin_defense(false);
            }
            Err(e) => {
                eprintln!("alpha node: cluster boot failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // Compose Functions only after transport is available. A recovering Home may immediately
    // re-emit policy questions or exact executor queries; booting it earlier would drop remote
    // recovery work on a clustered node before Role::TRANSPORT existed.
    let function_runtime = match function_config {
        Some(config) => match crate::functions::boot(&kernel, config, opts.node_id.as_deref()) {
            Ok(runtime) => {
                note!(
                    "functions: opt-in reference runtime for Home {} — durable Bestiary(id={}), resolver(id={}), executor(id={}), locator(id={}), policy(id={}), home(id={}).",
                    runtime.home,
                    runtime.catalog.0,
                    runtime.resolver.0,
                    runtime.executor.0,
                    runtime.locator.0,
                    runtime.policy.0,
                    runtime.home_creature.0
                );
                note!(
                    "functions: Abode root private key is not loaded; callers/root service must sign requests and custody grants externally."
                );
                Some(runtime)
            }
            Err(error) => {
                eprintln!("alpha node: Function runtime refused startup: {error}");
                kernel.shutdown_all(Deadline::default());
                std::process::exit(1);
            }
        },
        None => None,
    };

    // Optionally start the daemon HTTP/WS control plane. This is two
    // creatures on the bus: the `ControlCore` translator on `Role::CONTROL`, and the loadable
    // `surface-http` creature that drives it. The REPL (this file) keeps driving `run_verb` directly
    // (the local human seat, never gated); the HTTP plane and any MCP hub are gated bus clients.
    if let Some(addr) = &opts.listen {
        let listen: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("alpha node: bad --listen address `{addr}`: {e}");
                std::process::exit(2);
            }
        };
        let key = opts
            .api_key
            .clone()
            .or_else(|| std::env::var("SANCTUM_API_KEY").ok().filter(|s| !s.is_empty()))
            .map(Ok)
            .unwrap_or_else(surface_http::generate_api_key);
        let key = match key {
            Ok(key) => key,
            Err(e) => {
                eprintln!("alpha node: could not generate API key: {e}");
                std::process::exit(1);
            }
        };
        // Bind the control plane so the surface has something to talk to. Bound on the
        // `--listen` path specifically, so a `--minimal --exec` run still loads nothing (and a bare
        // node that wants no remote control simply never opens a surface).
        let control_id = match boot_control_with_function_deployer(
            &kernel,
            &ai,
            critter_builder,
            cluster_transport,
            function_runtime.as_ref().map(|runtime| runtime.function_deployer.clone()),
        ) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("alpha node: could not bind the control plane: {e}");
                std::process::exit(1);
            }
        };
        // Load the HTTP/WS surface creature. omni binds the listener (synchronously, so a port
        // conflict is reported before load) + wires the sense endpoint; we supply the surface.
        let key_for_surface = key.clone();
        match omni::boot_http_surface(&kernel, listen, move |listener, sense_rx| {
            surface_http::SurfaceHttp::new(
                listener,
                key_for_surface,
                surface_http::ControlTarget::Local,
                sense_rx,
            )
            .map(|s| Box::new(s) as Box<dyn aether::Creature>)
            .map_err(|e| format!("surface-http setup: {e}"))
        }) {
            Ok(surface_id) => {
                note!("control: ControlCore on Role::CONTROL (id={}), surface-http (id={}) — control rides the bus.", control_id.0, surface_id.0);
                note!("api: HTTP/WS control plane on http://{listen}  (Bearer key: {key})");
                if opts.headless {
                    note!(
                        "api: allow-ai is {} — a remote AI may{} author/load/mutate (headless: configure with --allow-ai at boot; restart without it to close the gate).",
                        if ai.allowed() { "ON" } else { "OFF" },
                        if ai.allowed() { "" } else { " NOT" }
                    );
                } else {
                    note!(
                        "api: allow-ai is {} — a remote AI may{} author/load/mutate (flip with `allow-ai on|off` here).",
                        if ai.allowed() { "ON" } else { "OFF" },
                        if ai.allowed() { "" } else { " NOT" }
                    );
                }
            }
            Err(e) => {
                eprintln!("alpha node: could not start the API on {listen}: {e}");
                std::process::exit(1);
            }
        }
    }

    // Non-interactive modes: run verbs and exit (reproducible demos / CI).
    if let Some(verbs) = opts.exec.clone() {
        let mut ctx =
            VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, critter_builder, &ai, false);
        ctx.transport = cluster_transport;
        if let Some(runtime) = &function_runtime {
            ctx.set_function_deployer(runtime.function_deployer.as_ref());
        }
        run_line(&verbs, &mut ctx, opts.json, &mut out)?;
        kernel.shutdown_all(Deadline::default());
        return Ok(());
    }
    if let Some(path) = opts.script.clone() {
        let body = match crate::read_text_file_bounded(
            &path,
            crate::MAX_ALPHA_SCRIPT_BYTES,
            "alpha node script",
        ) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("alpha node: --script {path}: {e}");
                std::process::exit(1);
            }
        };
        let mut ctx =
            VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, critter_builder, &ai, false);
        ctx.transport = cluster_transport;
        if let Some(runtime) = &function_runtime {
            ctx.set_function_deployer(runtime.function_deployer.as_ref());
        }
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if !run_line(trimmed, &mut ctx, opts.json, &mut out)? {
                break;
            }
        }
        kernel.shutdown_all(Deadline::default());
        return Ok(());
    }

    // Headless: API only, no REPL — park until a signal tears the node down.
    if opts.headless {
        if opts.listen.is_none() {
            eprintln!("alpha node: --headless needs --listen (nothing to do without the API).");
            std::process::exit(2);
        }
        writeln!(out, "headless: REPL disabled; serving the API. Ctrl-C to shut down.")?;
        out.flush()?;
        loop {
            std::thread::park();
        }
    }

    writeln!(out, "probe endpoint id = {}", probe_id.0)?;
    writeln!(out, "{COMMANDS}")?;
    prompt(&mut out)?;

    let mut ctx = VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, critter_builder, &ai, false);
    ctx.transport = cluster_transport;
    if let Some(runtime) = &function_runtime {
        ctx.set_function_deployer(runtime.function_deployer.as_ref());
    }
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    loop {
        let line = match read_repl_line_capped(&mut reader, crate::MAX_ALPHA_REPL_LINE_BYTES) {
            Ok(ReplLine::Line(line)) => line,
            Ok(ReplLine::TooLong) => {
                writeln!(
                    out,
                    "input line exceeds {} byte limit; skipped",
                    crate::MAX_ALPHA_REPL_LINE_BYTES
                )?;
                prompt(&mut out)?;
                continue;
            }
            Ok(ReplLine::Eof) | Err(_) => break,
        };
        if !run_line(&line, &mut ctx, opts.json, &mut out)? {
            // `quit`/`exit` — shutdown already requested below.
            kernel.shutdown_all(Deadline::default());
            return Ok(());
        }
        prompt(&mut out)?;
    }

    // EOF on stdin — clean shutdown for piped use.
    kernel.shutdown_all(Deadline::default());
    Ok(())
}

enum ReplLine {
    Line(String),
    Eof,
    TooLong,
}

fn read_repl_line_capped<R: BufRead>(reader: &mut R, max: usize) -> std::io::Result<ReplLine> {
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if out.is_empty() { Ok(ReplLine::Eof) } else { bytes_to_repl_line(out) };
        }

        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map_or(available.len(), |i| i + 1);
        if out.len().saturating_add(take) > max {
            reader.consume(take);
            if newline.is_none() {
                drain_repl_line(reader)?;
            }
            return Ok(ReplLine::TooLong);
        }

        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return bytes_to_repl_line(out);
        }
    }
}

fn drain_repl_line<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.map_or(available.len(), |i| i + 1);
        reader.consume(take);
        if newline.is_some() {
            return Ok(());
        }
    }
}

fn bytes_to_repl_line(mut bytes: Vec<u8>) -> std::io::Result<ReplLine> {
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    String::from_utf8(bytes)
        .map(ReplLine::Line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Parse + run one line against `ctx`, render the result (human text or `--json`). Returns
/// `keep_going` (false on `quit`/`exit`).
fn run_line(
    line: &str,
    ctx: &mut VerbCtx,
    json: bool,
    out: &mut std::io::Stdout,
) -> std::io::Result<bool> {
    let verb = match parse_verb(line) {
        Ok(None) => return Ok(true),
        Ok(Some(v)) => v,
        Err(usage) => {
            writeln!(out, "{usage}")?;
            return Ok(true);
        }
    };
    // Progress lines use a fresh handle (so they don't borrow `out` across run_verb). In `--json`
    // mode they go to stderr so stdout stays one JSON result per verb.
    let mut progress = |s: &str| {
        if json {
            eprintln!("{s}");
        } else {
            let mut o = std::io::stdout();
            let _ = writeln!(o, "{s}");
            let _ = o.flush();
        }
    };
    let res = run_verb(verb, ctx, &mut progress);
    if json {
        writeln!(out, "{}", serde_json::to_string(&res.json).unwrap_or_else(|_| "{}".into()))?;
    } else {
        writeln!(out, "{}", res.human)?;
    }
    Ok(res.keep_going)
}

fn prompt(out: &mut std::io::Stdout) -> std::io::Result<()> {
    out.write_all(b"alpha> ")?;
    out.flush()
}

// Node-identity minting (`NodeKeyBoot` / `derive_node_key`), cluster-transport boot (`boot_cluster`),
// and the HTTP-surface sense-endpoint wiring (`boot_http_surface`) now live in `omni` — one source of
// truth shared by this α front door, the Ω `omega serve` gateway, and the MCP-hub boot path (ADR-0044).
