# Changelog

Alpha is **pre-1.0**. 0.4 is the first public contract baseline: the `Envelope` (a message in motion)
and the signed `Manifest` (a creature at rest) are documented deliberately, but minor releases may
still change contracts when correctness, security, or the operating model requires it.
Semantic-versioning guarantees begin at 1.0.

For how the system works, see [`docs/CONCEPTS.md`](docs/CONCEPTS.md),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the design notes under [`docs/design/`](docs/design/).

## 0.4.1 - unreleased

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

### Abode — authenticated migration (M9-2)
- A migration responder now returns a **cryptographic witness**: having passed all six admission gates,
  it signs `(source abode_key ‖ state_hash ‖ challenge ‖ responder_node ‖ responder_pubkey)` with its
  own Abode key. The source verifies it and binds the responder's pubkey to a pre-shared
  `expected_responder_pubkey` anchor pinned on the `Migrate` op, reconstructing the witness from its own
  parked state. Signed responders are required by default (an opt-out builder exists for legacy peers);
  any failure keeps the source authoritative and re-parks the pending. Closes the gap where the source
  verified only an echoed challenge.

### Budgets — real enforcement
- The **beast** tier now enforces a per-envelope `wall_ms` wall-clock cap via `wasmtime` epoch
  interruption (one engine-global ticker; a per-handle `ceil(wall_ms / tick)` deadline), surfacing an
  exceeded deadline as a `Hard` `BudgetSignal { kind: Wall }`. The cap is **fail-closed**: if the
  ticker can't spawn, the engine refuses to load a beast that declares `wall_ms` rather than ignore it.
  `Capabilities.wall_ms` is a new serde-optional manifest field (`LimitKind::Wall` is no longer
  reserved). A failing-first regression pins beast initial-memory-over-cap rejection, and post-apoptosis
  `NoSuchModule` assertions prove the kill actually stops the creature on the beast and critter tiers.

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
  bytes across the bus: additive `RegistryOp::{FetchMetadata, FetchMetadataInRealm, ListMetadata}` →
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
