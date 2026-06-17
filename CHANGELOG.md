# Changelog

Alpha is **pre-1.0**. 0.4 is the first public contract baseline: the `Envelope` (a message in motion)
and the signed `Manifest` (a creature at rest) are documented deliberately, but minor releases may
still change contracts when correctness, security, or the operating model requires it.
Semantic-versioning guarantees begin at 1.0.

For how the system works, see [`docs/CONCEPTS.md`](docs/CONCEPTS.md),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the design notes under [`docs/design/`](docs/design/).

## 0.4.3 - 2026-06-17

The **convergence release**: no new features — make the current surface genuinely *work and make
sense*, close resource/security/coherence gaps, and remove needless complexity, so that before v0.5.0
Alpha is already a stable AI-OS / ASI fabric and v0.5.0 lands as *composition*, not a rewrite. Driven by
a design corpus authored first: five TRDs (`docs/trd/`) and ADRs 0037–0045 (`docs/adr/`). **Every change
is additive — no existing wire shape changes.**

### Cross-node origin & relay integrity (the v0.5.0 cross-mesh load-bearer)
- **App-signed dialogue provenance (ADR-0038).** The SEER `dialogue` answer body gains optional,
  serde-elided `signer_pubkey` + `signature` over `(corr, prompt, reply)` — *end-to-end* "which agent
  answered" that survives a relay, because the transport `Origin` is hop-by-hop by construction (a
  creature can never forge a cross-node origin). Realized end to end: `dialogue-responder` signs
  (`DialogueResponder::signed`), `dialogue-initiator` verifies on relay (`with_verifier` /
  `with_expected_signer`) and fails a tampered/forged/wrong-signer reply rather than relaying it as
  authentic. We deliberately did **not** add a creature-settable `Dispatch.origin` — it would be
  forgeable.
- **Nested `reply_to` rewrite (ADR-0039).** The transport now rewrites a peer's `Creature(mid)` to
  `Node(peer, mid)` recursively through `Realm`/`Omega` wrappers, so a cross-Realm `reply_to` routes
  back to the right creature on the right node.
- **Replay guard specified (ADR-0040).** The per-`(peer, sender)` `seq` guard is documented as
  *session-scoped* (reset on reconnect); cross-reconnect exactly-once is an application property keyed
  on `corr`, not a transport promise. The contract is now pinned by a test.
- **Origin-verdict posture (ADR-0041).** The router/transport stay non-enforcing (publish an
  `OriginVerdict`, never drop a `BadSig` frame); a clustered node with no `Role::IMMUNE_RESPONSE` bound
  now prints a loud boot warning (`omni::warn_if_no_immune_response`), and SECURITY.md documents the
  baseline. No fail-closed mode in the kernel.

### Resource-safety & hygiene
- **Bounded topic-subscription table (ADR-0037).** `Router` gains a finite `max_topics` cap (+ existing
  subscriber dedup); `subscribe` is host-only, so this is defense-in-depth, not a creature-facing DoS.
- **Unified escape-hatch convention (ADR-0042).** `with_max_*(0) = unbounded` is one documented "lab
  posture" across the spine (`Router`, registry-mem, embodiment-advertiser, realm-gateway, dialogue
  initiator, bestiary curator), with finite defaults and one canonical doc phrase. See
  `docs/design/substrate.md`.
- **`omni` control-plane DRY (ADR-0044).** Node-identity minting (`NodeKeyBoot`/`derive_node_key`),
  cluster-transport boot (`boot_cluster`), and the HTTP-surface sense wiring (`boot_http_surface`, via a
  surface-factory closure) move into `omni` — one source of truth for both the α front door and the Ω
  gateway (and the MCP-hub mesh join), replacing two drifting copies.

### App-surface coherence
- **Demo registry is authoritative (ADR-0045).** The multi-process `cluster` demo is now in
  `demos.json` tagged `(manual runbook)`: `alpha demo list` shows it and `alpha demo run cluster` prints
  its runbook steps and exits cleanly instead of "unknown demo". `alpha demo list` and `demos/README.md`
  agree.
- **MCP / allow-AI discoverability.** `docs/design/bus-and-control.md` now enumerates all **19** `alpha_*`
  tools (added `alpha_registry_fetch_load`); the MCP `instructions` explain *why* there is no remote
  allow-AI tool (the gate is local-REPL-only by design); the verb×surface parity matrix is pinned by a
  test.

## 0.4.2 - 2026-06-16

Makes the Ω pole earn its name *and* lays the rails for the v0.5.0 headline — **AIs interacting across
the mesh, across Realms and Sanctums**. The federation gateway reconciles itself on a clock, the
reserved SEER topics gain reference creatures, and — the larger arc — application traffic, agent
placement, and a live agent-to-agent conversation now cross a Realm boundary. Every change is additive:
no existing wire shape changes, so the v0.5.0 agents land as consumers, not a refactor.

### Federation — a self-driving Ω
- `federation-scheduler`, a daemon creature: the omega-federator's cadence companion. On its own
  injected interval it emits one `FederatorMsg::PullFrom` per configured peer-Realm target, turning
  operator-poked anti-entropy into a self-reconciling gateway. The substrate still ships no clock —
  time enters as this creature, hot-swappable like every other choice; stop it and the schedule stops.
  It honors the federator's pending-pull backpressure with an in-flight counter decremented on each
  `Accepted`/`Rejected` ack: a federator that stops answering drives the counter to the cap and the
  scheduler quietly backs off rather than flooding it.
- `omega serve --pull-interval <seconds>` boots the companion: the gateway pulls every `--peer-realm`
  route on that cadence. Without the flag the gateway stays poke-driven (the no-clock default). Peer
  discovery and quorum remain the v0.5 follow-ons; the cadence is the v0.4.2 down-payment.

### SEER — reference standing consumers for the reserved topics
- `seer::responder::respond_query`, the standing-consumer skeleton factored into the `seer` crate
  (schema check → bounded parse → topic isolation → Query-only → typed decode → shape check → decide →
  reply). A new responder is now just a topic + a typed body + a decision.
- Four reference responders under `creatures/prototypes/responders/` for the reserved topics that
  shipped a typed body but no creature standing on them: `responder-policy` (allowlist admission),
  `responder-budget` (grant up to a ceiling from a depleting pool), `responder-fitness` (an injected
  `Rater`, clamped `[0,1]`, non-finite folds to `0` fail-closed), and `responder-curation`
  (keep/gc/quarantine from configured lists). Each is a starting point operators fork — the decision is
  the model, the skeleton is shared. `placement`, `authoring`, and `consensus` already had live consumers.

### Cross-mesh interaction — the rails for v0.5.0
- **Cross-Realm application routing.** The `omega-federator` now forwards arbitrary *application*
  envelopes (any schema) to a creature on a peer Realm — not just system registry traffic — and also
  accepts the `Omega(realm, Node(gateway, creature))` target form (the shape a cross-Realm placement
  offer carries). `Omega(realm, Creature(m))` already worked; this proves and widens it. Reply routing
  (`reply_to` rewritten by transport on the way back) carries the answer to the original requester
  across the boundary. Proven end-to-end in `omega_app_routing_cross_node`.
- **Cross-Realm placement (Beat B).** Placement gains a Realm grain, additively: `placement::EmbodimentOffer`
  carries an optional `realm`, `placement::QueryBody` an optional `target_realm` (both elide from the
  wire when absent — pre-cross-Realm offers are byte-identical). A distributor learns its own Realm
  (`Distributor::with_realm`) and a set of cross-Realm advertisers (`with_peer_realm_advertisers`),
  fans placement Queries to them through the Omega gateway, and routes a chosen cross-Realm offer via
  `Address::Omega`. An advertiser declares its Realm (`EmbodimentAdvertiser::in_realm`) and tags its
  offers. Placement stays ask-and-wait over the Omega grain, never federator anti-entropy. Proven in
  `distributor_cross_realm`.
- **Agent-to-agent dialogue (the conversation seam).** A new reserved SEER topic, `Dialogue`, and a
  reference pair under `creatures/prototypes/dialogue/`: `dialogue-initiator` opens a conversation by
  sending a turn to a **named peer** (a plain `Address` — local, cross-node, or cross-Realm `Omega`),
  parks the requester by `corr`, and relays the peer's reply back; `dialogue-responder` answers a turn
  with an injected model (the reference echoes). The `(corr, query_id)` thread carries a back-and-forth
  of any length; the reduction theorem holds. Proven in `dialogue_seam`. Two LLM agents conversing
  across the mesh are the same shape on this topic — no new wire.
- **Persistent critter memory (Tier-1 #2).** The script (critter) tier — until now the only tier with
  no state carried across `handle()` calls — gains a bounded key→value store reached through three host
  functions (`mem_get` / `mem_set` / `mem_del`). It survives across calls for the instance's lifetime
  and is dropped on unload; at most `MAX_PERSIST_ENTRIES` keys (refuse-new at capacity).
- **Registry eviction (Tier-1 #3).** `registry-mem` gains an injected `EvictionPolicy` seam and the
  reference `LowValueEviction` (evict quarantined first, then lowest reputation, deterministic
  tiebreak), so a bounded catalog under a fixed `max_entries` keeps accepting fresh artifacts instead
  of refusing at the cap. Bound it with `RegistryMem::with_eviction`; unbound, the at-capacity posture
  stays refuse-new.
- **`dialogue` demo.** A narrated, runnable demo (`cargo run -p dialogue`, or `alpha demo dialogue`):
  two Realms over real ed25519 TCP, an initiator on one and a stateful agent on the other holding a
  multi-turn conversation through the Omega gateway — the v0.5.0 cross-mesh story, out of `#[test]`.

## 0.4.1 - 2026-06-14

Turns two seam-proven claims into shipped reality — a *real model* authors creatures, and the Bestiary
is a *durable, federated* registry — and hardens migration and budgets. Every contract change is
strictly additive (serde-optional fields, a new `bestiary.op` schema, byte-identical existing
`RegistryOp`s); no existing wire breaks.

### Authoring — a real model on the AUTHORING socket
- `mind`, a leaf crate carrying the injected **model seam**: the `Model` trait plus an `OpenAiModel`
  (feature `openai`, any OpenAI-compatible server — api.openai.com or a local Ollama/LM-Studio) and a
  zero-dep `FakeModel` that proves the loop (including the compile-error retry) hermetically. The crate
  never reads the environment; a `ModelConfig` is supplied by the operator surface, so a node binds a
  model per instance.
- `agent-mind`, a model-backed author binding the same `Role::AUTHORING` socket as `agent-templated`. It
  is **in-process only** (never a `.so`: construction takes the model explicitly, so no
  `Default`-built fake can be substituted), runs its slow model call **off the kernel drain thread** on
  a self-owned worker that joins within the unload deadline, and parses the model's two-fenced-block
  response **fail-closed** (a missing or malformed manifest stub is a structured failure, never a
  silently-permissive default). The author is contained at the **route + admission layer**, not the
  prompt — the live path defaults to the sandboxed tier — and emits a structured audit line per
  completion.
- First-run ergonomics: the default templated author now reports a guidance-friendly miss instead of a
  raw Debug dump. `AuthoringError` gains a `Display` that, on a no-template-match, names the recognized
  keywords and points to `--features openai` for free-form English authoring (single source of truth in
  `agent_templated::recognized_templates_hint`); the control surfaces render it via `Display`. The
  operator/daemon quickstarts and the README example are corrected to say the default author is
  keyword-matched, not arbitrary English.

### Bestiary — durable, distributed, AI-curated
- `bestiary`, a contract crate that now owns the registry wire types (`registry-mem` re-exports them),
  plus the `BestiaryStore` trait and the `FsBestiaryStore` reference: content-addressed deduplicated
  blobs and a per-Realm **tamper-evident signed log**. Realm names are only ever hashed, never
  path-joined (a wire-sourced `RealmId` can carry `/` or `..`); `recover()` rejects any foreign-authored
  record — the log is a self-owned journal, not a federation inbox.
- `EntryProof` — a standalone signed attestation over `(realm, artifact_hash, manifest_hash,
  first_seen, attester)` that anyone verifies and that **survives compaction**. `Compact`
  garbage-collects orphan blobs across all Realms, preserving each survivor's `first_seen`.
- `bestiary-daemon`, a creature filling `Role::REGISTRY` that serves every existing `RegistryOp`
  byte-for-byte plus an additive `bestiary.op` schema (`ProveEntry` / `Compact` / `PushEntries`).
  Replication is a **monotonic lattice**, not last-write-wins: membership unions, signed reputation
  takes the verified-greater, quarantine is sticky (cleared only by a signed `Unquarantine`), and a
  `Tombstone` federates as a permanent eviction. An injected `Curator` decides keep/promote/demote/
  quarantine/GC — `DeterministicCurator` is safe-by-default, and `AICurator` consults an injected
  `mind::Model` over an entry's bytes off the synchronous catalogue path. `SeerTopic::Curation` reserves
  the external-curator seam. `registry-mem` stays the in-memory stub reference.

### Control plane — registry & Bestiary verbs
- Four verbs across `omni` + the HTTP and MCP surfaces: `registry publish` (by node-local path,
  mutating/gated), `registry fetch` (metadata, not raw bytes), `registry list`, and `bestiary prove`
  (a verifiable `EntryProof`; only a `bestiary-daemon` answers, the stub returns a structured error).
  Each round-trips a `RegistryOp` / `BestiaryOp` on the orchestration lane; the three reads are ungated.
- New **`registry fetch-load`** operator verb (`omni` + `POST /api/registry/fetch-load` +
  `alpha_registry_fetch_load`): fetch a creature artifact over GX from a local or peer registry,
  assemble + integrity-check it (per-chunk + whole-file SHA-256), and admit + load it — the one command
  that wraps the choreography `m2_two_node` used to hand-script. It drives `FetchGxPlan` → a windowed
  `FetchGxChunk` pull that re-requests only the missing chunks on a stall (resume without restart, via a
  new additive `gawdxfer::ChunkAssembler::missing_chunks()`; the content-addressed registry needs no
  `Resume` wire op) → `kernel.load` (which re-verifies at admission, so a tampered fetch is refused).
  Loads code → gated. New runnable `demos/distribute` shows it cross-node over real ed25519 TCP.

### Ω — a real server (`omega serve`)
- `omega` is now a **lib+bin**, giving the Ω pole a body symmetric to the α front door. `omega serve`
  boots a kernel configured as a dedicated **federation / gateway Sanctum** — `transport-tcp` on
  `Role::TRANSPORT` (gossip mesh + seeds), `registry-mem` on `Role::REGISTRY`, and the real
  `omega-federator` on `Role::OMEGA_GATEWAY` (with the reference `RoundRobinReputation` weigher), plus
  an optional HTTP/WS control plane. It is headless with no authoring agent and no REPL — the dual of
  `alpha node` (which keeps its operator/authoring seat and its own `--cluster-listen`). The split is
  posture/defaults, not a capability fence.
- The frozen Ω **wire contract** moved to a new lean `omega-contract` leaf crate (`omega.deferred`,
  `GATEWAY_ROLE`, the reserved `OmegaServices` seam — just `realm`/`aether`/`serde`), so a stub gateway
  or an orchestrator parses an `omega.deferred` reply without pulling the server's kernel deps. The
  `omega` crate re-exports it, so the public path `omega::deferred` / `omega::GATEWAY_ROLE` is
  unchanged. **No wire change**: `Address::Omega`, `Role::OMEGA_GATEWAY = "omega-gateway"`, and the
  `omega.deferred` schema are byte-identical; this is pure code-motion + a new composition root.
- The demos and docs now reflect — and *use* — the two-pole structure. The federation demo's in-process
  Realm gateways bind their `omega-federator` through the new shared `omega::serve::boot_federator`
  recipe (the same one `omega serve` runs), so the demo and the server cannot drift. The `demos/cluster/`
  runbook now stands up both poles on one mesh — node A an `omega serve` server (mesh anchor + idle
  federator), B/C `alpha node` operators — and cross-executes a creature authored on an α operator from
  the Ω server. Concept and operator docs (CONCEPTS, ARCHITECTURE, SECURITY, the bus/control design note,
  the READMEs, AGENTS) now describe a Sanctum as realized by **both** `alpha node` and `omega serve`.

### Abode — authenticated migration (M9-2)
- A migration responder now returns a **cryptographic witness**: having passed all six admission gates,
  it signs `(source abode_key ‖ state_hash ‖ challenge ‖ responder_node ‖ responder_pubkey)` with its
  own Abode key. The source verifies it and binds the responder's pubkey to a pre-shared
  `expected_responder_pubkey` anchor pinned on the `Migrate` op, reconstructing the witness from its own
  parked state. Signed responders are required by default (an opt-out builder exists for legacy peers);
  any failure keeps the source authoritative and re-parks the pending. Closes the gap where the source
  verified only an echoed challenge.

### Cross-node sender authentication (node grain)
- A clustered node now signs its **bus envelopes with the same ed25519 key it authenticates links
  with** (its bus signer is `Ed25519Signer(node_key)`, not an unrelated stub). A peer that
  authenticated the node at the handshake can therefore verify the envelopes it signs. The receiving
  transport does exactly that **at the wire boundary** — before it reseals `from`, while the inbound
  bytes are still what the sender signed — and stamps the proven node into a new sealed
  `Header.origin` (`Origin { node }`). `origin` is unforgeable by construction: it is absent from
  `Dispatch`, so a creature cannot express it; it is set only through the transport's privileged
  `Bus::emit_attested`, reachable only from the boot-only grant the kernel hands the transport
  (`Kernel::load_transport_instance` → `BusHandle::new_attesting`) — there is no manifest capability
  for it. It rides inside the signing payload, so the local re-seal covers it.
- The transport publishes a non-enforcing **`OriginVerdict`** (`Verified` / `BadSig` / `Unresolved`;
  `Local` is inferred from `origin == None`) per cross-node frame on `PROPRIOCEPTION`. The spine never
  rejects on it — enforcement is injected. The reference **`policy-origin`** creature counts a peer's
  non-`Verified` verdicts and, past an injected threshold, pulls the new reversible
  **`TransportCtl::Forget`** lever (drop a peer from the allowlist + tear down its link until an
  operator re-`Connect`s it — the missing inverse of `Connect`). A receiver-side **replay guard**
  drops a cross-node frame whose `seq` does not advance its per-`(node, sender)` high-water mark
  (reset on reconnect).
- The router's verify-on-delivery is now **real for local senders**: `Kernel::set_node_identity`
  records the node's own public key, which `public_key_of` resolves so a genuine local signature
  actually validates instead of always exercising the stub's negative branch.
- Honestly deferred: per-creature portable identity, end-to-end proof across an untrusted relay (the
  mesh is direct authenticated links — there is none today), revocation, and signed membership gossip.

### Budgets — real enforcement
- The **beast** tier now enforces a per-envelope `wall_ms` wall-clock cap via `wasmtime` epoch
  interruption (one engine-global ticker; a per-handle `ceil(wall_ms / tick)` deadline), surfacing an
  exceeded deadline as a `Hard` `BudgetSignal { kind: Wall }`. The cap is **fail-closed**: if the
  ticker can't spawn, the engine refuses to load a beast that declares `wall_ms` rather than ignore it.
  `Capabilities.wall_ms` is a new serde-optional manifest field (`LimitKind::Wall` is no longer
  reserved). A failing-first regression pins beast initial-memory-over-cap rejection, and post-apoptosis
  `NoSuchModule` assertions prove the kill actually stops the creature on the beast and critter tiers.
- **`ExtendBudget` is honest, per dimension — it can no longer silently no-op.** `Kernel::extend_budget`
  now returns a per-dimension `ExtendOutcome` (`Applied` / `Unenforceable` / `NotRequested`, plus an
  `unknown_creature` flag), and the control listener surfaces every requested dimension the creature's
  tier cannot live-lift. Enforcement was widened to match: the **beast** tier now live-lifts memory (the
  `ResourceLimiter` reads a shared mem cell) and wall-clock (a shared epoch-deadline cell) in addition to
  fuel; the **critter** tier now enforces wall-clock via the Rhai `on_progress` watchdog (a `Hard`/`Wall`
  breach distinct from a Fuel op-budget trap) and lifts fuel + wall live (its structural memory caps stay
  fixed at load, so a critter memory lift is honestly reported `Unenforceable`); **native** is
  trusted-by-admission and reports every dimension `Unenforceable`. `BudgetControl` carries the live
  mem/wall cells and per-tier enforceability flags (a runtime handle — no wire-shape change). New tests
  cover each tier×dimension, a live beast memory lift, and a critter wall trip.

### Resilience — hostile-input & resource bounds
- A uniform resource-exhaustion pass across the substrate: every consumer that decodes a wire payload
  now bounds the **serialized size before JSON decode** (`SeerEnvelope::parse_bounded` +
  `seer::MAX_SEER_ENVELOPE_BYTES`, `aether::MAX_SENSE_EVENT_BYTES`, registry/bestiary op caps, migrator
  and reconciler pre-parse ceilings, the verifiable-die and kernel-control message caps, and bounded
  control-verb / control-result / JSON-RPC-line readers on the surfaces), and the TCP transport caps a
  single frame and the grafted gossip-member count.
- Reference creatures that retain per-key state now **bound it by default**, each with an explicit `0`
  opt-out: `registry-mem` and the durable `FsBestiaryStore` (entries + artifact bytes),
  `fitness-selector` (observed ids), `immune-response` (watched ids), `policy-budget` (tracked modules),
  `agent-curious` (parked Query exchanges), `omega-federator` (in-flight pulls), `verifiable-die`
  (unrevealed rounds), `transport-tcp` (member table), and the HTTP/MCP surfaces (parked `corr → reply`
  waiters, which shed new requests as `503` / `surface-busy` rather than allocate without bound).
  **Behavior note:** these defaults flip the affected reference creatures from *unbounded* to *bounded*;
  embedders that relied on unbounded growth opt back in with the matching `with_max_*(0)` builder.
- New **byte-light** read paths so control surfaces inspect the catalogue without dragging artifact
  bytes across the bus: additive `RegistryOp::{FetchMetadata, ListMetadata}` →
  `RegistryReply::{FetchedMetadata, Metadata}` over a new `CatalogEntry` (artifact-carrying `Fetch` /
  `ListEntries` stay for load and anti-entropy). A publish into a full catalogue is a wire-honest error,
  not a false `Published`.
- A second pass tightens **per-field shape caps** on top of the size caps, each rejecting a hostile
  shape before it amplifies into paths, replies, or retained state (and each with a paired test):
  envelope *header* bytes (bounded before signing/journaling), the critter `env.text` preview, the
  AI-curator decision cache, durable-Bestiary log-record and head-tip reads, quarantine reason /
  attesting-peer counts and sizes, `agent-mind`'s in-flight model-call set, the `PushEntries` batch
  count and the `ListEntries` snapshot artifact-byte total, the authored manifest-stub shape, placement
  query/answer/offer fields, the fitness/immune watch maps, cluster member ids + dial addresses, the
  verifiable-die nonce, AI-status text, and the control `bind` role name.
- Correctness fixes ride along: native byte-spilled `.so` tempfiles take unique `create_new` paths (two
  same-content loads never truncate each other); `forge::try_spawn` surfaces OS thread-spawn errors
  instead of swallowing them; the placement distributor gives each advertiser a distinct `query_id` so
  duplicate answers can't be double-counted; the abode reconciler refuses to merge forks whose signed
  `requires`/`realm` disagree (those fields ride outside the merge lattice); the TCP transport
  canonicalizes peer pubkeys and rejects malformed member ids/addresses before retention; the MCP
  surface detaches a still-blocked stdin reader at shutdown rather than hanging teardown; and the OpenAI
  usage parser rejects out-of-range token counts instead of wrapping.
- Anti-entropy stays live under the new source-side caps: the Omega federator reclaims a parked pull
  slot when a source registry answers a pull with a snapshot-cap `Error` (not only on an oversized
  payload), and a `PushEntries` merge that must drop an over-cap quarantine signal keeps the membership
  + reputation it already persisted and logs the dropped marker — never miscounting the landed entry as
  rejected.
- A third pass hardens the **front door and the contract layer**: `Manifest::parse` caps wire bytes at
  1 MiB and `Manifest::validate` bounds every metadata string and list (`MAX_MANIFEST_*`, mirrored as
  `maxLength`/`maxItems` in `manifest.schema.json` — the schema's `$comment` notes the node enforces
  UTF-8 *bytes*); the registry and durable Bestiary re-validate published manifests before retention
  (recovery of an existing journal never re-validates — old entries still load). The envelope
  address-depth gate now also runs at `BusHandle::send` (before signing) and `Router::route`, ahead of
  the serializing header-size gate, and `Router::subscribe` is idempotent (duplicate subscription no
  longer duplicates fan-out). Authoring text gets per-field caps (request 64 KiB / retry context
  128 KiB / `NoTemplate` echo a bounded preview) enforced by every AUTHORING bindee. The HTTP/MCP
  surfaces byte-cap each string argument before `Verb` construction and bound error-token echoes; the
  MCP tool schemas advertise the caps they enforce. `alpha` bounds its own local inputs (REPL line,
  `--script`, demo manifest at 1 MiB; `--author-api-key-file` at 8 KiB), and `anima` caps every
  byte-materializing artifact load at 128 MiB — including the native ship→spill path. Transport
  `transport.ctl` requests/replies are capped before decode (oversized ops get a wire-honest
  `Rejected`), outbound frames over the wire cap are shed loudly at the sender, and a gossip advertise
  address is shape-checked with an honest boot-time warning when the effective address would be refused
  by peers.
- Review fixes on that pass: admission's `build_hash` integrity gate now **streams** a path-backed
  artifact through the hasher (`Artifact::sha256_hex`) instead of materializing it — O(1) memory, and
  a large-but-legit native `.so` loaded by path is never refused by the artifact cap; the bounded
  front-door reader accepts FIFO/process-substitution inputs again (`--script <(...)`,
  `--author-api-key-file <(...)`) while still streaming under the cap; the author verbs and both
  surfaces share one operator-facing request cap (`omni::MAX_CONTROL_AUTHOR_REQUEST_BYTES` — the
  AUTHORING contract's own field cap, so the advertised limit is the enforced one and `author
  --critter` reports its effective limit honestly); and a native load fails loudly when the manifest
  would exceed the guest's re-parse cap after JSON escaping, rather than silently binding a creature
  with a placeholder self-view.
- A durable Bestiary that outgrows its `max_snapshot_artifact_bytes` no longer stalls *silently*: when
  the live set exceeds the cap the daemon still skips that cadence's anti-entropy PUSH and curation
  `observe` pass (the deliberate fail-closed bound), but now publishes a `MaintenanceStallEvent`
  (`bestiary_maintenance_stall`) on the proprioception topic, so a long-lived node that has grown past
  its cap surfaces a steady, observable signal — for a monitor, the immune system, or an operator —
  instead of ceasing to replicate behind only a stderr line. Recovery stays operator-driven (raise the
  cap or set it to `0` to opt out).

### Shape corrections (deliberately breaking — 0.4.0 wire compatibility is intentionally dropped)
This release takes the wire/type-shape corrections that were previously deferred to keep 0.4.0
compatibility, so 0.5.0 starts from a clean baseline. Each correction re-pins or updates the
determinism/round-trip test that locks its new shape.
- The kernel's proprioception/fitness sense events rename their `module` field to **`creature`** —
  the last vestige of the old "module" vocabulary on the wire. `Proprioception`, `Fitness`,
  `BudgetSignalEvent`, and `BudgetRequest` now serialize `creature`, and every consumer follows: the
  `immune-response` / `fitness-selector` deserialize mirrors, the `monitor` sense-tape renderer, and
  `policy-budget`. (The `KernelControl` control ops and each creature's own control protocol keep their
  own `module` field — only the kernel *sense events* are renamed.)
- The reserved SEER `budget` and `fitness` consult-topic bodies get their shapes corrected before any
  consumer ships: `fitness::QueryBody.candidate` → `candidate_hash` (the content-addressed registry
  artifact hash, so a selector and a rater always agree on which artifact a score is about), and
  `budget::AnswerBody` gains an explicit `granted: bool` so a denial is distinct from a deliberate
  grant-nothing (`granted: true, granted_units: 0`).
- The registry's full-artifact ops **collapse their `*InRealm` variant pairs** into one variant with an
  optional `realm`: `RegistryOp::{Publish, Fetch, FetchMetadata}` now carry `realm: Option<RealmId>`
  (absent = the local Realm, eliding from the wire), and the matching `RegistryReply::{Published,
  Fetched}` always echo the resolved Realm. The separate `PublishInRealm` / `FetchInRealm` /
  `FetchMetadataInRealm` ops and `PublishedInRealm` / `FetchedInRealm` replies are gone. (The GX
  bulk-transfer ops keep their explicit `*InRealm` split for now.)
- The **envelope signing payload** is domain-separated and gains the cross-node `origin`. Every
  envelope signature now commits to a `GAWD-ENVELOPE-v1:` prefix (so a node key's envelope signatures
  can never be confused with its handshake signatures) plus the new sealed `Header.origin` field
  (omitted from the bytes when absent, so a *local* envelope's signing payload moves only by the
  prefix). Both determinism tripwires are deliberately re-pinned. This is a cross-node-coordinated
  break: a 0.4.1 node verifies a 0.4.0 node's frames as `BadSig`, so a cluster upgrades together.
- **`Manifest::validate` now caps metadata shape**, which is an acceptance-tightening: a manifest that
  a pre-0.4.1 node admitted (no caps) but that exceeds a new `MAX_MANIFEST_*` bound — an over-long
  name, too many `provides`/`entrypoints`/`fs`/`calls`, an over-cap field — or that carries an empty
  `abi.abi_tag`, is now refused at admission, control-plane load, registry publish, and bestiary
  `put` with a structured error (`StoreError::Invalid` on the durable store; `RegistryReply::Error`
  on the bus). Durable state already at rest is unaffected — the Bestiary journal `recover()` replays
  records without re-validating, so an upgraded node still loads what it persisted; only fresh
  admission/publish (including a peer `PushEntries` of a pre-cap entry) re-checks. The caps are
  generous (see `sigil::MAX_MANIFEST_*`) and no in-tree creature approaches them.

## 0.4.0 - 2026-06-04

Alpha's first public release. The five governing loops are alive end to end, and the substrate's
properties are runnable, not just described. What the release contains:

### Substrate, tiers & the creature contract
- Three execution tiers behind one load path, selected by the manifest `abi.backend`: native
  `daemon` (`.so` via `dlopen`), `beast` (WASM on wasmtime), and `critter` (a metered, sandboxed Rhai
  script).
- The native ABI `gawd_creature_v1` — a single constructor symbol returning a POD vtable, with only
  bytes crossing the C boundary — and `gawd_critter_v1` for the script tier.
- Safe unload of native code: a fixed drop order (`shutdown` → instance `destroy` → `dlclose` last),
  an SDK thread-join barrier, a `/proc/self/task` runaway-thread guard that leaks one library rather
  than ever risk a use-after-free, and a real unload deadline.
- The signed `Manifest` as the sole metadata and permission source: identity, entrypoints,
  capabilities, requirements, provided roles, provenance, and a `sha256:` content address bound over
  the whole manifest body.

### Inversion of control & authoring
- Fabric, not model: the kernel does lifecycle, routing, and the admission *mechanism* only; every
  strategy — placement, policy, scoring, merge, consensus, transport, registry, authoring, build — is
  an injected creature bound to a role socket, and an unbound socket returns `NoProvider`.
- The self-authoring loop: `Role::AUTHORING` turns an intent into source plus a manifest stub,
  `Role::BUILD` returns a signed, content-addressed artifact admissible by the same gates as any
  shipped creature; compile failures are first-class retry input; the build sandbox is an injected,
  always-available model.
- Authoring as a `corr`-correlated conversation over SEER (Query / Answer / Steer / Progress /
  Thought), with single-shot request-reply as the reduced case.

### The bus, SEER & the control plane
- The `aether` bus: `Envelope` / `Address` / `Role`, bounded inboxes with backpressure, a bounded
  journal, identity reseal of `from`, and no-panic parsing of hostile input.
- SEER, the bus-level Query / Answer / Steer primitive, with reserved topics (placement, policy,
  budget, fitness, consensus, authoring) sharing one wire shape.
- Control is `Envelope` traffic on `Role::CONTROL` via the spine-only `omni` crate (`run_verb` +
  `ControlCore`); the control surfaces — `alpha mcp` (the MCP control-hub) and `alpha http` (HTTP/WS)
  — are loadable creatures driving that contract, and the MCP hub is itself a headless Alpha Sanctum.
  A human/AI shared-control allow-AI gate guards every mutating verb; HTTP uses Bearer auth,
  WebSocket a token.

### Identity, transport & clustering
- Per-node ed25519 identity (`sigil`), distinct from per-Abode author keys, with a root-blind
  verifier that is mechanism, not trust policy.
- An authenticated TCP transport bound to `Role::TRANSPORT`: a mutual ed25519 handshake with
  domain-separated, nonce- and direction-bound transcripts against a pubkey allowlist; length-bounded
  frames; `reply_to` / `from` resealed across hops; and kernel control refused at the wire boundary
  (local-only).
- Dynamic gossip clustering: a node joins a many-to-many mesh from seeds, membership floods by gossip
  over the authenticated link, the graph is observable on the proprioception stream, and `send
  node:id` routes cross-node. Trust among admitted peers is transitive; UDP transport is out of scope.

### Addressing, placement & federation
- A federated address grain — `Creature` / `Node` / `Realm` / `Omega` — with a bounded nesting depth,
  the grain living in `aether`.
- The Distributor: capability-addressed placement (`Address::Intent`) matching a creature's
  requirement predicates against nodes' advertised embodiment over the placement SEER topic.
- `realm` (a trust domain of sanctums) and `omega` (the cross-Realm membrane) own their gateway seam;
  the gateway creatures are injected. Omega federation runs by pull anti-entropy with signed
  reputation and a quarantine path.
- Verifiable randomness: a commit-reveal die over the `commitment` envelope slot for fair picks and
  tie-breaks.

### The distributed self & evolution
- The Abode — a creature's portable identity and state — snapshotted under size → integrity →
  signature gates; migration as a single-active-fork hand-off through admission gates; fork/merge
  reconciliation on an injected CRDT lattice.
- The five anti-entropy loops alive end to end: sense→act, author→select→promote (signed fitness
  promotion on an injected criterion, heredity via the registry reputation slot), distribute, defend
  (reversible, trust-gated quarantine on a sensed fault), and acculturate.
- Limits as a gradient: a `BudgetSignal` (Warn / Hard; level, kind, vector) published on the
  proprioception topic, an injected policy deciding the response, and `ExtendBudget` granting live
  grace — tier-honest, since the WASM and script tiers meter and the native tier does not.

### The front door & repository
- One binary, `alpha` (α): `alpha node` / `alpha mcp` / `alpha http` dispatch in-process, and `alpha
  demo` spawns external demos from a manifest. The terminal membrane is `omega` (Ω); everything
  interior lives under `cosmos/`, with only stimuli in and products out.
- The repository root holds only `alpha/` plus `cosmos/`, `demos/`, and `docs/`; loadable units live
  under `cosmos/creatures/` (production organs) ⊃ `prototypes/` (reference strategies) ⊃ `fixtures/`
  (test specimens).

### Security
- GPL-3.0-or-later. Capability declarations are enforced by construction on the sandboxed tiers (no
  host imports means no filesystem or network; fuel and operation budgets; byte-exact or best-effort
  memory caps); the native tier is trusted-by-admission, with OS-level confinement as the operator's
  deployment seam.
- No secrets are tracked in the tree; signing fails loud rather than fail-open; and hostile envelopes
  and manifests never panic the kernel.

[0.4.0]: https://github.com/gawd-ai/alpha/releases/tag/v0.4.0
