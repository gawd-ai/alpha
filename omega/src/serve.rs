//! `omega serve` — the Ω server composition root (the dual of `alpha node`).
//!
//! Boots a kernel configured as a dedicated **federation / gateway Sanctum**: three engines + the dev
//! policy, an ed25519 node identity (a gateway is always a mesh node), the gateway boot recipe
//! ([`boot_gateway`]: `transport-tcp` on `Role::TRANSPORT` + `registry-mem` on `Role::REGISTRY` +
//! `omega-federator` on [`omega::GATEWAY_ROLE`](crate::GATEWAY_ROLE)), and an optional HTTP/WS control
//! plane. There is **no authoring agent and no REPL** — that is `alpha`'s seat; `omega serve` is
//! headless by nature.
//!
//! The recipe is split out as [`boot_gateway`] so both [`run`] (the binary) and the integration test
//! drive the *same* composition. The transport/identity helpers mirror `alpha::node` rather than
//! being shared through `omni`: putting the federation recipe in `omni` would couple the shared
//! control spine — which every `alpha` build links — to a federation creature, for no reuse.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use std::time::Duration;

use aether::{
    Address, CreatureId, Deadline, Ed25519Signer, Ed25519Verifier, NodeId, RealmId, Role, Signer,
    Verifier,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use federation_scheduler::{FederationScheduler, PullTarget};
use omega_federator::{FederatorConfig, OmegaFederator};
use omni::{boot_control, boot_manifest, AiControl};
use policy_dev::DevPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use sigil::{Ed25519KeyMaterial, Manifest};

/// Parsed `omega serve` options.
struct Opts {
    /// This gateway's node id (required).
    node_id: Option<String>,
    /// The transport mesh listen address (required — a gateway is a mesh node).
    cluster_listen: Option<String>,
    /// This gateway's own Realm (the federator's `self_realm`). Defaults to `global`.
    realm: String,
    /// Mesh seeds to dial: `node-id@host:port#pubkey-hex` (repeatable).
    seeds: Vec<String>,
    /// Realm→peer routes for Omega routing: `<realm>=<node-id>` (repeatable).
    peer_realms: Vec<(String, String)>,
    /// Self-driving anti-entropy: pull every peer Realm once per this many seconds. `None` keeps the
    /// poke-driven default (no clock); `Some(n)` boots the `federation-scheduler` companion.
    pull_interval_secs: Option<u64>,
    /// Reuse a node identity from a 32-byte hex seed (else one is minted at boot).
    cluster_key: Option<String>,
    /// Optional HTTP/WS control-plane listen address.
    listen: Option<String>,
    /// Optional bearer key for the control plane (else `SANCTUM_API_KEY`, else generated).
    api_key: Option<String>,
    /// Allow a remote AI to drive the control plane (off by default).
    allow_ai: bool,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        node_id: None,
        cluster_listen: None,
        realm: "global".to_string(),
        seeds: Vec::new(),
        peer_realms: Vec::new(),
        pull_interval_secs: None,
        cluster_key: None,
        listen: None,
        api_key: None,
        allow_ai: false,
    };
    let mut args = args.iter().cloned();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--node-id" => o.node_id = Some(args.next().ok_or("--node-id needs <id>")?),
            "--cluster-listen" => {
                o.cluster_listen =
                    Some(args.next().ok_or("--cluster-listen needs <addr> (e.g. 127.0.0.1:9100)")?)
            }
            "--realm" => o.realm = args.next().ok_or("--realm needs <id>")?,
            "--seed" => {
                o.seeds.push(args.next().ok_or("--seed needs <node-id@host:port#pubkey-hex>")?)
            }
            "--peer-realm" => {
                let v = args.next().ok_or("--peer-realm needs <realm>=<node-id>")?;
                let (realm, node) =
                    v.split_once('=').ok_or("--peer-realm wants <realm>=<node-id>")?;
                if realm.is_empty() || node.is_empty() {
                    return Err("--peer-realm wants <realm>=<node-id> (both non-empty)".to_string());
                }
                o.peer_realms.push((realm.to_string(), node.to_string()));
            }
            "--pull-interval" => {
                let v = args.next().ok_or("--pull-interval needs <seconds>")?;
                let secs: u64 = v.parse().map_err(|_| "--pull-interval wants whole seconds")?;
                if secs == 0 {
                    return Err("--pull-interval must be >= 1 second".to_string());
                }
                o.pull_interval_secs = Some(secs);
            }
            "--cluster-key" => {
                o.cluster_key = Some(args.next().ok_or("--cluster-key needs <64-hex-char seed>")?)
            }
            "--listen" => {
                o.listen = Some(args.next().ok_or("--listen needs <addr> (e.g. 127.0.0.1:7900)")?)
            }
            "--api-key" => o.api_key = Some(args.next().ok_or("--api-key needs <key>")?),
            "--allow-ai" => o.allow_ai = true,
            // `omega serve` is headless by nature; accepted for symmetry with `alpha node`.
            "--headless" => {}
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    Ok(o)
}

/// Run the Ω gateway server to completion over the given CLI args (everything after `serve`).
/// Invoked by `omega serve`.
pub fn run(args: &[String]) -> std::io::Result<()> {
    let opts = match parse_opts(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("omega serve: {e}");
            std::process::exit(2);
        }
    };
    let Some(node_id) = opts.node_id.clone() else {
        eprintln!("omega serve: --node-id <id> is required");
        std::process::exit(2);
    };
    let Some(mesh_listen) = opts.cluster_listen.clone() else {
        eprintln!("omega serve: --cluster-listen <addr> is required (a gateway is a mesh node)");
        std::process::exit(2);
    };

    // One identity: a gateway always clusters, so its ed25519 node key signs the bus AND
    // authenticates transport links — a peer that authenticates this node at the handshake can then
    // verify the envelopes it signs (real cross-node `Verified`). Mirrors `alpha node --cluster-listen`.
    let nk = match derive_node_key(opts.cluster_key.as_deref()) {
        Ok(nk) => nk,
        Err(e) => {
            eprintln!("omega serve: {e}");
            std::process::exit(2);
        }
    };
    let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::new(nk.key.clone()));
    let verifier: Arc<dyn Verifier> = Arc::new(Ed25519Verifier);
    // `Kernel::new` already returns `Arc<Kernel>`.
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        signer,
        verifier,
        Arc::new(DevPolicy),
        1024,
    );
    kernel.set_node_identity(nk.key.public_hex().to_string());
    let ai = Arc::new(AiControl::new(opts.allow_ai));

    // Clean shutdown on SIGINT/SIGTERM (T14): reverse-order `shutdown_all`, then exit.
    {
        let kernel = Arc::clone(&kernel);
        let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let install = ctrlc::set_handler(move || {
            if shutting_down.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            eprintln!("\nomega serve: signal received — shutting down the gateway cleanly…");
            kernel.shutdown_all(Deadline::default());
            std::process::exit(0);
        });
        if let Err(e) = install {
            eprintln!("omega serve: could not install the SIGINT/SIGTERM handler ({e}); Ctrl-C will hard-kill.");
        }
    }

    let mut realm_to_peer = HashMap::new();
    for (realm, node) in &opts.peer_realms {
        realm_to_peer.insert(RealmId::new(realm), NodeId(node.clone()));
    }
    let self_realm = RealmId::new(&opts.realm);

    let cfg = GatewayConfig {
        node_id: node_id.clone(),
        self_realm: self_realm.clone(),
        listen: mesh_listen.clone(),
        seeds: opts.seeds.clone(),
        realm_to_peer,
        node_key: nk.key.clone(),
    };
    let ids = match boot_gateway(&kernel, &cfg) {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("omega serve: gateway boot failed: {e}");
            std::process::exit(1);
        }
    };

    println!("omega serve — Ω federation gateway (v{})", env!("CARGO_PKG_VERSION"));
    println!("posture: DEV — the dev policy admits everything; the bus signer is this node's real ed25519 identity (cross-node origins are verified), but admission is not hardened.");
    println!(
        "gateway: node-id={node_id}  realm={}  mesh-listen={mesh_listen}  seeds={}  peer-realms={}",
        self_realm.0,
        opts.seeds.len(),
        opts.peer_realms.len()
    );
    println!("gateway: node pubkey = {}", nk.key.public_hex());
    if nk.generated {
        println!(
            "gateway: generated a node key — reuse this identity with `--cluster-key {}`",
            sigil::crypto::hex_encode(&nk.seed)
        );
    }
    println!(
        "gateway: peers join this node with  cluster join {node_id}@{mesh_listen}#{}",
        nk.key.public_hex()
    );
    println!(
        "gateway: transport(id={}) → TRANSPORT, registry-mem(id={}) → REGISTRY, omega-federator(id={}) → OMEGA_GATEWAY",
        ids.transport.0, ids.registry.0, ids.federator.0
    );

    // Optional self-driving anti-entropy: the `federation-scheduler` companion. With `--pull-interval`,
    // the gateway pokes its own federator on a clock instead of waiting for an operator — Ω reconciles
    // itself. Without the flag the gateway stays poke-driven (the substrate ships no clock).
    if let Some(secs) = opts.pull_interval_secs {
        match boot_scheduler(&kernel, &ids, &opts.peer_realms, secs) {
            Ok(Some(sched_id)) => println!(
                "gateway: federation-scheduler (id={}) pulling {} peer-realm(s) every {secs}s → self-driving anti-entropy.",
                sched_id.0,
                opts.peer_realms.len()
            ),
            Ok(None) => eprintln!(
                "omega serve: --pull-interval set but no --peer-realm routes — nothing to pull; staying poke-driven."
            ),
            Err(e) => {
                eprintln!("omega serve: federation-scheduler boot failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // Optional HTTP/WS control plane — the same two creatures `alpha node --listen` boots: the
    // `ControlCore` translator on `Role::CONTROL` and the loadable `surface-http` creature.
    if let Some(addr) = &opts.listen {
        let listen: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("omega serve: bad --listen address `{addr}`: {e}");
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
                eprintln!("omega serve: could not generate API key: {e}");
                std::process::exit(1);
            }
        };
        let control_id = match boot_control(&kernel, &ai, None, Some(ids.transport)) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("omega serve: could not bind the control plane: {e}");
                std::process::exit(1);
            }
        };
        match boot_http_surface(&kernel, listen, key.clone()) {
            Ok(surface_id) => {
                println!("control: ControlCore on Role::CONTROL (id={}), surface-http (id={}) — control rides the bus.", control_id.0, surface_id.0);
                println!("api: HTTP/WS control plane on http://{listen}  (Bearer key: {key})");
                println!(
                    "api: allow-ai is {} — a remote AI may{} drive this gateway (flip with `allow-ai on|off`).",
                    if ai.allowed() { "ON" } else { "OFF" },
                    if ai.allowed() { "" } else { " NOT" }
                );
            }
            Err(e) => {
                eprintln!("omega serve: could not start the API on {listen}: {e}");
                std::process::exit(1);
            }
        }
    }

    println!("omega serve: gateway up. Ctrl-C to shut down.");
    let _ = std::io::stdout().flush();
    loop {
        std::thread::park();
    }
}

/// The wiring [`boot_gateway`] needs — built by [`run`] from the CLI, or by a test directly.
pub struct GatewayConfig {
    /// This gateway's node id.
    pub node_id: String,
    /// This gateway's own Realm (the federator's `self_realm`).
    pub self_realm: RealmId,
    /// The transport mesh listen address.
    pub listen: String,
    /// Mesh seeds to dial (`node-id@host:port#pubkey-hex`).
    pub seeds: Vec<String>,
    /// Realm→peer routes for Omega routing.
    pub realm_to_peer: HashMap<RealmId, NodeId>,
    /// The node's ed25519 identity — signs the bus, authenticates transport links, and is the
    /// federator's Abode key for outbound signed reputation deltas (one identity per gateway).
    pub node_key: Ed25519KeyMaterial,
}

/// The creature ids the gateway recipe bound (for the binary's banner and the test's drivers).
pub struct GatewayIds {
    pub transport: CreatureId,
    pub registry: CreatureId,
    pub federator: CreatureId,
}

/// Boot the federation/gateway organs into `kernel`: `transport-tcp` on `Role::TRANSPORT`,
/// `registry-mem` on `Role::REGISTRY`, and `omega-federator` on `Role::OMEGA_GATEWAY` (via
/// [`boot_federator`]). No authoring agent — a gateway does not author. Mirrors the per-node boot in
/// `cosmos/sanctum/tests/omega_federation_cross_node.rs`.
pub fn boot_gateway(kernel: &Arc<Kernel>, cfg: &GatewayConfig) -> Result<GatewayIds, String> {
    let transport = boot_cluster(kernel, &cfg.node_id, &cfg.listen, &cfg.seeds, &cfg.node_key)?;

    let registry = kernel
        .load_instance(boot_manifest("registry-mem"), Box::new(RegistryMem::new()))
        .map_err(|e| format!("registry-mem admits: {e}"))?;
    kernel.bind_role(Role::new(Role::REGISTRY), registry);

    let federator = boot_federator(
        kernel,
        boot_manifest("omega-federator"),
        FederatorBootConfig {
            self_node: NodeId(cfg.node_id.clone()),
            self_realm: cfg.self_realm.clone(),
            local_registry: registry,
            abode_key: cfg.node_key.clone(),
            realm_to_peer: cfg.realm_to_peer.clone(),
        },
    )?;

    Ok(GatewayIds { transport, registry, federator })
}

/// The wiring [`boot_federator`] needs — everything that distinguishes one gateway's federator from
/// another's. The weigher is not a field: `boot_federator` always binds the reference
/// `RoundRobinReputation` (the shared recipe's one fixed choice).
pub struct FederatorBootConfig {
    /// This gateway's node id.
    pub self_node: NodeId,
    /// This gateway's own Realm.
    pub self_realm: RealmId,
    /// The local registry the federator answers from and merges pulled entries into.
    pub local_registry: CreatureId,
    /// The node's ed25519 identity — the federator's Abode key for outbound signed reputation deltas.
    pub abode_key: Ed25519KeyMaterial,
    /// Realm→peer routes for Omega routing.
    pub realm_to_peer: HashMap<RealmId, NodeId>,
}

/// Bind an `omega-federator` on `Role::OMEGA_GATEWAY` with the reference `RoundRobinReputation`
/// weigher. This is the one omega-specific organ that both `omega serve` (via [`boot_gateway`]) and
/// the in-process `federation` demo share, so the `OMEGA_GATEWAY` binding never drifts between the
/// running server and the demo that illustrates it.
///
/// `manifest` is the caller's admission manifest, because the two callers run under different
/// policies: [`boot_manifest`]`("omega-federator")` for the binary's `DevPolicy`, or a
/// `signed_boot_manifest` for a `SignedPolicy` kernel (the demo). Everything else — the federator's
/// config and the weigher — is identical, which is the point of sharing it.
pub fn boot_federator(
    kernel: &Kernel,
    manifest: Manifest,
    cfg: FederatorBootConfig,
) -> Result<CreatureId, String> {
    let federator = OmegaFederator::new(FederatorConfig {
        self_node: cfg.self_node,
        self_realm: cfg.self_realm,
        local_registry: cfg.local_registry,
        abode_key: cfg.abode_key,
        realm_to_peer: cfg.realm_to_peer,
        weigher: Box::new(RoundRobinReputation::new()),
    });
    let federator = kernel
        .load_instance(manifest, Box::new(federator))
        .map_err(|e| format!("omega-federator admits: {e}"))?;
    kernel.bind_role(Role::new(Role::OMEGA_GATEWAY), federator);
    Ok(federator)
}

/// Boot the optional `federation-scheduler` companion: it pokes `ids.federator`'s anti-entropy on a
/// fixed cadence, one `PullFrom` per `peer_realms` route, making the gateway self-reconciling.
///
/// The peer's registry id is taken to be the gateway's own `ids.registry`: every `omega serve`
/// gateway boots the identical recipe (transport → registry → federator), so the registry lands at
/// the same `CreatureId` on each — the id a peer answers `ListEntries` from. (Resolving a
/// heterogeneous peer's ids is what peer discovery buys in v0.5; this homogeneous-mesh assumption is
/// the same one the operator-driven cross-node path already relies on, here automated.)
///
/// Returns `Ok(None)` when there are no peer-realm routes (nothing to pull).
pub fn boot_scheduler(
    kernel: &Kernel,
    ids: &GatewayIds,
    peer_realms: &[(String, String)],
    interval_secs: u64,
) -> Result<Option<CreatureId>, String> {
    let targets: Vec<PullTarget> = peer_realms
        .iter()
        .map(|(realm, node)| {
            PullTarget::new(RealmId::new(realm), NodeId(node.clone()), ids.registry)
        })
        .collect();
    if targets.is_empty() {
        return Ok(None);
    }
    let scheduler = FederationScheduler::new(
        Address::Creature(ids.federator),
        targets,
        Duration::from_secs(interval_secs),
    );
    let id = kernel
        .load_instance(boot_manifest("federation-scheduler"), Box::new(scheduler))
        .map_err(|e| format!("federation-scheduler admits: {e}"))?;
    Ok(Some(id))
}

/// This node's derived ed25519 identity — the one key it signs bus envelopes with and authenticates
/// transport links with. Minted once before the kernel is constructed. (Copied from `alpha::node`;
/// shared promotion into `omni` is a deferred DRY follow-up.)
struct NodeKeyBoot {
    key: Ed25519KeyMaterial,
    seed: [u8; 32],
    generated: bool,
}

/// Mint (or load, via `--cluster-key`) the node's ed25519 identity.
fn derive_node_key(cluster_key: Option<&str>) -> Result<NodeKeyBoot, String> {
    use sigil::crypto;
    let (seed, generated): ([u8; 32], bool) = match cluster_key {
        Some(hex) => {
            let bytes = crypto::hex_decode(hex)
                .filter(|b| b.len() == 32)
                .ok_or("--cluster-key must be 64 hex chars (a 32-byte seed)")?;
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes);
            (s, false)
        }
        None => (crypto::fresh_seed()?, true),
    };
    let key = Ed25519KeyMaterial::from_seed(seed).map_err(|e| format!("node key: {e}"))?;
    Ok(NodeKeyBoot { key, seed, generated })
}

/// Boot the `transport-tcp` organ in gossip (cluster) mode bound to `Role::TRANSPORT`, dialing each
/// seed. Loaded via [`Kernel::load_transport_instance`] so the transport holds the boot-only
/// origin-attestation grant. (Copied from `alpha::node::boot_cluster`.)
fn boot_cluster(
    kernel: &Kernel,
    node_id: &str,
    listen: &str,
    seeds: &[String],
    node_key: &Ed25519KeyMaterial,
) -> Result<CreatureId, String> {
    let mut peers = Vec::new();
    for s in seeds {
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
        self_key: node_key.clone(),
        self_node: NodeId(node_id.to_string()),
        listen_addr: listen.to_string(),
        peers,
    };
    let transport = kernel
        .load_transport_instance(
            boot_manifest("transport-tcp"),
            Box::new(transport_tcp::TransportTcp::new(cfg).with_gossip(Some(listen.to_string()))),
        )
        .map_err(|e| format!("transport-tcp admits: {e}"))?;
    kernel.bind_role(Role::new(Role::TRANSPORT), transport);
    Ok(transport)
}

/// Load the HTTP/WS surface creature and subscribe it to the sense topics. The listener is bound
/// here so a port conflict surfaces synchronously, then handed to the creature. (Copied from
/// `alpha::node::boot_http_surface`.)
fn boot_http_surface(
    kernel: &Arc<Kernel>,
    listen: std::net::SocketAddr,
    api_key: String,
) -> Result<CreatureId, String> {
    use aether::Topic;
    use sigil::Capabilities;
    let listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let (sense_id, _sense_bus, sense_rx) = kernel.open_endpoint(Capabilities::default());
    kernel.subscribe(Topic::new(Topic::PROPRIOCEPTION), sense_id);
    kernel.subscribe(Topic::new(Topic::FITNESS), sense_id);
    kernel.subscribe(Topic::new("seer"), sense_id);
    let surface = surface_http::SurfaceHttp::new(
        listener,
        api_key,
        surface_http::ControlTarget::Local,
        sense_rx,
    )
    .map_err(|e| format!("surface-http setup: {e}"))?;
    let id = kernel
        .load_instance(boot_manifest("surface-http"), Box::new(surface))
        .map_err(|e| format!("surface-http admits: {e}"))?;
    Ok(id)
}
