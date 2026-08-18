# Alpha — Architecture (as built)

> The engineering truth: what exists, how it
> composes, and where it deliberately stops. For naming and vocabulary, see
> [`CONCEPTS.md`](CONCEPTS.md); for the thesis, [`VISION.md`](VISION.md). Where the
> substrate stops on purpose is in
> [§ "What the substrate does NOT do (yet)"](#what-the-substrate-does-not-do-yet).
>
> All five governing loops are alive. The composed end-to-end tests
> (`cosmos/sanctum/tests/v0{1,2,3}_end_to_end.rs`) run on in-process kernels: author on A → ship
> A→B over real ed25519 TCP → admit + load on B → invoke → reload → capability-gate,
> then cross-Realm placement, Abode migration, fitness selection, and immune-response
> quarantine. All three creature tiers are real: native `daemon`, sandboxed WASM `beast`,
> and metered sandboxed script `critter` (Rhai). The budget gradient and authoring-as-conversation
> seams both have live consumers. The substrate ships *sockets and mechanisms*; it deliberately
> ships **no models**.
>
> **v0.4.4 status.** The typed-function/durable-Job foundation and its reference organs are an
> additive application layer on this substrate. Its Met contract and suite-compositional proof are
> described in
> [`TRD-006`](trd/TRD-006-typed-functions-and-durable-jobs.md) and
> [`design/functions-and-jobs.md`](design/functions-and-jobs.md). It remains an application protocol,
> not a new kernel primitive; the proof does not claim crash-resume inside an unfinished GX transfer.

## The thesis

Every interaction rides one typed, signed, ordered **envelope**, across one **bus** —
local and remote use the *same* envelope type so transport is "route off-node," not
a new subsystem. Two contracts pin everything down: the **Manifest** (a creature at
rest, in transit) and the **Envelope** (a message in motion). A **tiny three-job
kernel** — lifecycle + routing + admission — is the only fixed fabric; *every* other
capability (logging, transport, registry, the authoring agent, even the admission
policy and the placement resolver) is an ordinary creature on the bus. The kernel
ships *sockets and mechanisms*; injected creatures supply *models*. This
makes "fabric, not model" structurally enforced, not promised.

## Workspace layout

```
.                          # repo root: the α door + support dirs only — "nothing mixed"
alpha/                      # the α pole — front door + local operator (client): node/mcp/http compose in-process; demo spawns external demos
omega/                      # the Ω pole — federation apex / mesh (server), dual to alpha: a lib+bin — `omega serve` boots a federation/gateway Sanctum (the frozen Ω wire contract is the cosmos/omega-contract leaf)
demos/                     # narrated, runnable demos (walkthrough, federation, distribute, bestiary-live, dialogue; cluster/ is a runbook)
docs/                      # CONCEPTS / ARCHITECTURE / ROADMAP / TOPICS + design notes …
foundation/                # shared GAWD foundations Alpha CONSUMES but does not own (cross-system, gawd-prefixed, externalize later):
  gawdxfer/                #   the GX bulk-transfer contract: chunk-frame codec + chunk math + streaming SHA-256; shared with sctl
  gawdfn/                  #   typed function + durable-Job identities, records, schemas, signatures, and validation
cosmos/                    # everything between α and Ω — the interior the front door opens onto:
  sigil/                   #   the at-rest contract (Manifest type + crypto)
  aether/                  #   the bus spine (Envelope, Address, Router, Creature seam, journal)
  anima/                   #   per-tier loaders: NativeEngine + WasmEngine + ScriptEngine
  sanctum/                 #   the kernel library (lifecycle + routing + admission); memcheck harnesses in tests/memcheck/ (ASan/Miri/Valgrind)
  forge/                   #   the creature-authoring surface (declare_creature! + NativeBus + managed::spawn)
  abode/  seer/            #   first-class concept crates: snapshot contract + Query/Answer primitive
  realm/  bestiary/        #   the trust domain + durable registry contract/store
  mind/                    #   injected model seam shared by authoring and curation organs
  omega-contract/          #   lean Ω wire contract; re-exported by the omega server
  omni/                    #   the spine-only control core every surface drives over the bus
  creatures/               #   production-capable reference organs (mostly native; critter source ships as bytes):
                           #     transport-tcp                     (ed25519 + framed TCP)
                           #     registry-mem, bestiary-daemon     (ephemeral + durable registry fillings)
                           #     build-cargo                       (native compile; operator-injected sandbox)
                           #     build-beast, build-critter        (no-cargo WASM/Rhai builders)
                           #     agent-templated, agent-curious, agent-mind  (reference authoring fillings)
                           #     surface-http, surface-mcp         (loadable control surfaces)
                           #     distributor-requirements          (the Distributor; consumes placement SEER)
                           #     embodiment-advertiser             (answers placement Queries with node embodiment)
                           #     abode-migrator                    (in-memory Abode hand-off reference; not durable home authority)
                           #     omega-federator, federation-scheduler  (cross-Realm pull anti-entropy + its cadence)
                           #     fitness-selector                  (signed promotion on an injected criterion — Loop 2)
                           #     immune-response                   (reversible local quarantine; optional inbound trust gate — Loop 4)
                           #     verifiable-die                    (commit-reveal randomness over the `commitment` slot)
                           #     abode-reconciler                  (CRDT fork/merge on an injected lattice)
                           #     function-{home,executor,locator,resolver} + job-blob-fs  (v0.4.4 Job mechanisms)
  creatures/prototypes/    #   injected reference-strategy MODELS — not substrate:
                           #     distributors/{distributor-roundrobin, …}         (IoC composability proof)
                           #     reputation/reputation-roundrobin                 (uniform verified-attestation weigher)
                           #     policies/{policy-dev, policy-signed, policy-origin, …}  (admission + origin-defense policies)
                           #     policies/policy-job-basic                         (bounded deterministic Job policy)
                           #     policies/policy-budget                           (consumes the BudgetSignal)
                           #     policies/policy-quarantine-{trust-all,trust-realm,aware}  (immune gates)
                           #     scorers/scorer-{success-rate,latency,roundrobin} (injected FitnessScorer models)
                           #     gateways/{realm-gateway, omega-gateway}       (federation gateways)
                           #     merge/merge-lww-map                              (LWW merge lattice for the reconciler)
                           #     responders/responder-{policy,budget,fitness,curation} (standing SEER consumers)
                           #     monitor/                                         (the nervous-system observer)
                           #     dialogue/{dialogue-initiator,dialogue-responder} (named-peer SEER conversation)
                           #     critters/{echo-critter, uppercase, rot13, …}     (reference Rhai source creatures; not crates)
  creatures/prototypes/fixtures/   # test-only specimens (the most reduced prototype) the kernel test suite dlopens:
                           #     echo-daemon, echo-daemon-v2       (reload pair)
                           #     loopback-gateway                  (local↔remote symmetry)
                           #     panic-daemon                      (panic-in-handle specimen)
                           #     runaway-thread-daemon             (unmanaged-thread specimen)
                           #     welbehaved-thread-daemon          (managed-thread control)
```

`sanctum` and `aether` are the only "load-bearing" crates; the rest are contract
types (`sigil`), engines (`anima`), authoring ergonomics
(`forge`), or ordinary creatures.

## The bus (`aether`) — one spine, end-to-end in two senses

The bus is one **logical** spine — spatially (Creature↔Creature, Node↔Node,
Kernel↔control, Topic fan-out) and across the lifecycle (the same `Envelope` carries
a manifest from author → compile → admit → load → run → ship → publish).

- **`Envelope`** — payload + header. The header is where trust primitives live:
  `from` / `to`, `seq` (per-sender monotone counter), the reserved `causal[]` slot,
  `stamp` (a *logical* clock, never `SystemTime::now()`), `sig` (a creature
  may sign — admission `may` require it, per injected policy), `corr` (correlation
  id so a reply matches its request across async / multi-turn / external delay). Current
  creature `Dispatch` cannot populate `causal[]`, and bus sealing writes it empty; durable Job
  causality therefore lives in `gawdfn::JobEventV1`, not in the header. The router journal is a
  bounded, in-memory, drop-oldest diagnostic window — not a durable event store.
- **`Address`** — `Creature(CreatureId) | Node(NodeId, CreatureId) | NodeRole(NodeId, Role) |
  Kernel | Topic(Topic) | Role(Role) | Intent(Intent{ outcome, requirements }) |
  Realm{ realm, target } | Omega{ realm, target }`. *Identity* addressing
  (`Creature`/`Node`/`Kernel`), topic fan-out, and *capability* addressing
  (`Intent`/`Role`/`NodeRole`) are the same envelope, resolved differently.
  `Intent`/`Role` route to whichever creature is **bound** to the socket. `NodeRole`
  scopes capability discovery to one exact node and resolves only an explicitly
  remote-exposed host binding (`Kernel::bind_remote_role`); it does not replace
  application-level authorization or proofs. An unbound `Intent`/`Role` returns a structured
  `RouteError::NoProvider`; an unexposed or unbound `NodeRole` fails closed at the receiving
  transport. The fabric never substitutes a model of its own. The `Realm`/`Omega` federation grain
  wraps an inner `target` address and resolves via a bound gateway creature —
  composition by depth, not a parallel routing system.
- **`Router`** — bounded address/role/topic tables + per-creature inboxes + the journal. The
  role-binding table. The kernel holds the table, not the traffic.
- **`Creature`** — the kernel-facing trait. Three verbs:
  `bind(CreatureCtx)`, `handle(Envelope) → Outcome`, `shutdown(Deadline)`. Local
  delivery is by-ref; serialization happens only at a real boundary (off-node, into
  WASM, or across the native `.so` FFI seam).
- **`Bus` + `NativeBus`** — `Bus` is the in-process trait every creature uses;
  `NativeBus` (in `forge`) is the FFI shim for native creatures loaded as a
  `.so`. Both implement the same trait, so a creature sees one bus API regardless of
  where it runs.

## The two contracts

**`Manifest`** — `name`, `version`, `abi { backend, abi_tag, target }`, `entrypoints[]`,
`capabilities { fs, net, cpu_ms, mem_bytes, wall_ms, calls }`, `requirements { accelerators,
sensors, min_mem, connectivity, jurisdiction }`, `provenance { author = Abode-key,
source_hash, build_hash, signature }`, `content_address`, `provides[]`.
`Manifest::validate` gates entrypoint shape and `provides` shape so an authored
manifest with a malformed catalog is rejected at admission. `capabilities.calls`
is a *bus-level* capability enforced at the one router choke point. `provides[]`
declares which roles a creature can fill (e.g. `resolver`, `policy`) so the
operator can `bind` it.

**`Envelope`** — described above. One wire format, carrying the trust primitives and real `ring`
ed25519 signatures; `capabilities.calls` is checked at the routing/delivery choke point.

## The function/Job foundation (`gawdfn`) — an application contract

`foundation/gawdfn` is a shared GAWD contract that Alpha **consumes but does not own**. It is not a
third kernel contract and does not change `Creature`, `Envelope`, or any engine. It defines bounded,
versioned data and verification mechanics for:

- immutable `FunctionId { manifest_content_address, entrypoint }` identities and friendly aliases;
- typed entrypoint contracts, attached additively as `sigil::Entrypoint.contract`;
- explicit deployment receipts and alias-resolution pins;
- asynchronous Job specifications, handles, states, signed events, attempts, progress, steer, and
  causal child links; and
- portable home checkpoints, custody grants, and home leases.

Eight frozen signed domains define that application protocol. Seven are carried as top-level
schemas over ordinary envelopes:
`gawd.function.deploy.v1`, `gawd.function.job.v1`, `gawd.function.execute.v1`,
`gawd.function.call.v1`, `gawd.function.home.v1`, `gawd.function.locate.v1`, and
`gawd.function.policy.v1`; `gawd.function.custody.rewrap.v1` is the nested KMS request/receipt
signature domain inside the Home handoff. The reference
organs below fill the contract-owned function roles. Resolver, placement, retry timing, workflow,
retention, trust, and recovery choices remain injected creature policy. See
[`functions-and-jobs.md`](design/functions-and-jobs.md).

## The kernel (`sanctum`) — three jobs, model-free

`Kernel` owns exactly three responsibilities:

1. **Lifecycle.** `load(Manifest, Artifact) → CreatureId` runs admission, picks the
   engine by `abi.backend`, calls `Engine::load`, registers the inbox.
   `unload(CreatureId, Deadline)` runs `deregister → drain (join threads) →
   Engine::unload` in that order (Opt B for native, Opt D for wasm). The
   1000-cycle reload loop (`cosmos/sanctum/tests/m1_reload_loop.rs`) is the ASan-clean
   RSS-stable proof.
2. **Routing.** Delegates to `aether::Router`. Same router for every address shape;
   same delivery choke point for every send (`may_send` checks
   `capabilities.calls`).
3. **Admission.** The kernel runs the *mechanism* — parse manifest, verify signature
   evidence, check capabilities, compute build-hash; the *policy* is an
   `Arc<dyn sanctum::Policy>` injected at `Kernel::new` (reference implementations include
   `policy-dev` and `policy-signed`). Admission is not yet a hot-swappable role-bound creature;
   `policy-budget` is instead a proprioception consumer. The kernel never decides what is admissible.

The kernel contains no built-in capability and no model of its own — that is why
it stays small and why it is the fixed fabric an AI cannot re-author; everything
woven *on* it is hot-swappable, but the fabric itself is not.

## The engines (`anima`)

- **`NativeEngine`** — exact-byte retained staging + `libloading` `dlopen` + the safe-unload
  sequence. Linux/Android stream into a sealed memfd and load its process-unique `/proc/self/fd`
  capability; other targets use a random private/read-only fallback with a narrower same-UID claim.
  Admission hashes the representation the engine opens rather than reopening a mutable source. A
  generation counter on the handle lets the router refuse stale routes after
  deregister; the SDK's managed-`spawn` registry joins every creature-spawned thread
  before the kernel `dlclose`s the library; the kernel's thread-count guard catches
  threads spawned via the raw stdlib path and refuses `dlclose` rather than UAF
  (bounded library leak, not undefined behavior).
- **`WasmEngine`** — real `wasmtime`, with a fuel + linear-memory limiter.
  Dropping the `Store` collapses all linear memory + tables (Opt D); no UAF class
  exists for beasts. Emits `BudgetSignal::Warn` at the configured threshold
  (`Capabilities.budget_warn_at`) — the budget-gradient emission on the path. A manifest with exactly
  one contracted `gawd.function.call.v1` entrypoint activates a host-side typed adapter: before guest
  execution the host validates the existing call proof, exact manifest-derived `FunctionId`, and
  canonical creature routes, then passes only canonical inline application JSON through the existing
  exported `memory + alloc + handle` ABI. It parses returned JSON and wraps it in a
  `FunctionResultV1` carrying the exact verified `AttemptId`. This is **not a host import** or a new
  guest ABI; typed modules still declare no imports, and ordinary beast payload handling is unchanged.
- **`ScriptEngine`** — the critter tier: a bare Rhai interpreter
  with no filesystem, network, clock, process, rand, imports, or runtime `eval`.
  The artifact is UTF-8 Rhai source (`abi_tag = gawd_critter_v1`) defining
  `fn handle(env)`. `cpu_ms` becomes a per-envelope operation budget; optional `wall_ms`
  becomes a progress-hook deadline. `budget_warn_at` emits the same `Warn` signal as the beast tier,
  and `KernelControl::ExtendBudget` lifts the next handle's operation/wall ceiling. `mem_bytes` maps
  to fixed-at-load Rhai structural caps (string / array / map size), a best-effort memory guard rather
  than the beast tier's byte-exact limiter. Bounded instance-local memory and pure JSON/Function-proof
  helpers add no ambient authority.

The v0.5.0 composition proves both that collaboration is not fixed to one model
pair and that these are three real execution backends. Builder, Reviewer, and Contract Tester make
four signer-verified, strictly decoded causal decisions across two in-process Kernel nodes/Realms over
authenticated TCP. The accepted result is a fresh bounded `affine_i32_v1` data program. The same
Builder Model injection confirms one source-free record per tier; `AgentMind` validates it against
the approved digest and trusted renderers produce Rust, no-import WAT, and Rhai. Models cannot place
source, dependencies, or authority in that path. Three builder outputs are durably recovered and
three distinct `FunctionId`s each execute one tester-selected local and one A-Home → B-executor Job.
Each retained Job proof carries the signed submission, complete contiguous Home event history and
terminal snapshot, execution grant/call/dispatch route, deployment receipt, and terminal execution
receipt; the final summary anchors a record hashing all six bundles. That proves intended signed
Home/deployment topology and one-attempt history, not packet-level traversal.
The default scripted run is regression only. TRD-007 remains Accepted/not Met until one clean exact
commit has both constrained push CI and a fresh protected-workflow live run retaining
provider-reported receipts and all signed/build/execution evidence under a verified index plus
external operator seal. The same packaged binary must independently accept that bundle through
`dialogue verify-live` under pinned commit/signer/novelty inputs; encrypted raw evidence, the
disclosure-safe pack, workflow provenance attestations, and run metadata then leave 90-day staging
for immutable supported-lifetime storage. Provider metadata and workflow attestations do not prove
model weights, and the latter are not a reproducible-build proof. This proves constrained typed
synthesis, not arbitrary code, general agency, broadcast/group Dialogue, arbitrary-N consensus, a
durable group transcript, or a three-process Sanctum deployment.

## The SDK (`forge`)

A creature author writes a type, `impl Creature + Default`, and calls
`declare_creature!(MyDaemon)`. The macro emits one `#[no_mangle] extern "C"`
constructor (`gawd_creature_v1`) returning a POD vtable — the only foreign boundary,
POD-only.

- **`NativeBus`** — wraps the host-supplied `send` callback into the `Bus` trait;
  cheap to clone; thread-safe (single-driver — the host's drain thread calls
  `handle` serially).
- **`managed::spawn(name, F)` / `managed::try_spawn(name, F)`** — **the thread discipline for native creatures**.
  A creature that spawns a thread *must* go through one of these so the SDK joins it
  in `shutdown` before the host `dlclose`s the library; `try_spawn` exposes OS spawn
  errors for authors that must fail synchronously. Threads via raw
  `std::thread::spawn` are invisible to the SDK and would UAF on unload — except
  the kernel's thread-count guard catches the leak and refuses `dlclose` (bounded
  library leak, not UB). Beasts have no native-unload UAF class (drop the `Store`
  → done), so this primitive is native-tier territory.
- **`prelude`** — re-exports the common types: `Address`, `Bus`, `BusError`,
  `Deadline`, `Dispatch`, `Envelope`, `Header`, `Intent`, `CreatureCtx`, `CreatureId`,
  `Creature`, `NodeId`, `Outcome`, `Role`, `Topic`, plus `Manifest`,
  `Capabilities`, `Requirements`, etc.

**The SDK depends on contract/authoring leaves (`aether`, `seer`, `sigil`, and `gawdfn`) — never on
the kernel.**
Creatures cannot call into the kernel; they emit envelopes through their `Bus`.
Every FFI glue function catches panics (`std::panic::catch_unwind`) before returning
across the `extern "C"` boundary — the fabric-integrity floor for the FFI
seam.

## The creatures: organs (`cosmos/creatures/*`), injected models + scripts (`cosmos/creatures/prototypes/*`), test fixtures (`cosmos/creatures/prototypes/fixtures/*`)

`cosmos/creatures/` holds the production-capable reference organs; `cosmos/creatures/prototypes/` holds operator-replaceable
injected models (policies, scorers, weighers, merge models, the monitor) plus the critter script
prototypes; `cosmos/creatures/prototypes/fixtures/` holds the test-only creatures (walking-skeleton + fault
specimens) the kernel test suite loads — the most reduced prototype, nested deepest. The
column below shows each crate's home.

| Crate | Tier | What it does |
|---|---|---|
| `cosmos/creatures/prototypes/fixtures/echo-daemon` | native | The reference creature — reverses its payload. The thing the reload loop runs 1000× to prove safe-unload. |
| `cosmos/creatures/prototypes/fixtures/echo-daemon-v2` | native | A second native creature proving the reload-as-a-new-version path (different version, same shape). |
| `cosmos/creatures/prototypes/fixtures/loopback-gateway` | native | The local↔remote symmetry test — routes `Node(self, …)` envelopes through a local socket as serialized bytes; proves the wire format is real without a remote peer. |
| `cosmos/creatures/transport-tcp` | native | The cross-node creature — ed25519 handshake + framed TCP. Bridges exact numeric `aether::Address::Node(…)` routes and explicitly remote-exposed `NodeRole(…)` bindings to a real peer Sanctum. |
| `cosmos/creatures/registry-mem` | native | The Bestiary seed — content-addressed `publish` / `fetch`; a manifest + bytes addressed by `artifact_hash`. |
| `cosmos/creatures/bestiary-daemon` | native | The durable `Role::REGISTRY` filling — Realm-sharded content-addressed artifacts/catalog entries, a signed local journal, entry proofs, curation, and bounded full-live-set PUSH anti-entropy. It stores package availability, not live deployments or the mutable Job ledger. |
| `cosmos/creatures/build-cargo` | native | The compiler — takes the author's `crate_name + source + manifest_stub + deps + template`, compiles in an isolated cargo workspace, and returns `BuildReply::Built { manifest, artifact }` signed by the Abode key. `Sandbox::None` is the default; operators inject containment with `Sandbox::Custom`. |
| `cosmos/creatures/build-beast` | native | The no-Cargo BUILD sibling for beasts: compiles exact WAT in-process, rejects imports and invalid `memory + alloc + handle` exports, assembles a `Backend::Beast` manifest, and signs the emitted core-WASM bytes through the same `BuildReply` shape. |
| `cosmos/creatures/build-critter` | native | The no-cargo BUILD sibling for critters: validates Rhai source, assembles a `Backend::Critter` manifest (`gawd_critter_v1`), signs it, and returns the source bytes as the artifact through the same `BuildReply` shape as `build-cargo`. |
| `cosmos/creatures/agent-templated` | native | The deterministic authoring creature — matches the request against a template catalog, emits an `AuthoringResponse`. |
| `cosmos/creatures/agent-curious` | native | The consultative authoring creature — when no template matches, emits `AuthoringQuery`, parks the conversation, resumes terminally on `AuthoringAnswer`. Reduction theorem preserved (single-shot `Request → Reply` works unchanged). |
| `cosmos/creatures/agent-mind` | native | The opt-in model-backed authoring filling. It consumes the injected `mind::Model` seam and binds the same authoring socket as the deterministic references. General mode can parse source/stub completions; v0.5 uses `approved_only`, which accepts a strict digest-bound affine data record and performs trusted host lowering to all three tiers. |
| `cosmos/creatures/surface-http` | native | **Loadable HTTP/WS surface.** Owns its listener and runtime, maps authenticated REST/WebSocket traffic to `Verb` envelopes on `Role::CONTROL`, and holds no kernel reference. |
| `cosmos/creatures/surface-mcp` | native | **Loadable MCP surface.** Owns stdio JSON-RPC, maps tool calls to `Verb` envelopes for a local or remote ControlCore, and uses no REST side channel. |
| `cosmos/creatures/prototypes/fixtures/panic-daemon` | native | Misbehavior specimen — panics in `handle`; verifies the FFI seam catches it and routes to unload. |
| `cosmos/creatures/prototypes/fixtures/runaway-thread-daemon` | native | Misbehavior specimen — spawns via raw `std::thread::spawn`; verifies the kernel's thread-count guard refuses `dlclose` (bounded leak, not UAF). |
| `cosmos/creatures/prototypes/fixtures/welbehaved-thread-daemon` | native | Control specimen — spawns via `managed::spawn`; verifies join-on-unload is clean. |
| trusted-lowered affine beast | beast (wasm) | The v0.5 dialogue composition lowers the approved affine IR to audited no-import WAT, sends it through `BuildBeast`, durably recovers the signed output, and loads it through `WasmEngine`; raw payload behavior remains covered by the smaller inline-WAT integration specimen. |
| `cosmos/creatures/prototypes/critters/echo-critter` | critter (Rhai) | The reference script-tier creature: a single `echo.rhai` source artifact, loaded as bytes through `ScriptEngine`, with no Cargo crate or compiled `.so`. |
| `cosmos/creatures/distributor-requirements` | native | **The Loop-3 keystone.** The Distributor: bound to `Role::DISTRIBUTOR`, consults SEER on the `placement` topic for every Intent (even N=1 local), reconciles `EmbodimentOffer`s by an injected `PickModel` (FirstFit / RoundRobin), routes the Intent to the picked target (local or peer). Companion: `embodiment-advertiser`. |
| `cosmos/creatures/embodiment-advertiser` | native | One per Sanctum; configured with `self_node` + a list of `(CreatureId, Embodiment)` offers. Answers placement Queries with the matching subset, tagged by `node + creature_id` for the distributor's local-or-peer collapse. |
| `cosmos/creatures/abode-migrator` | native | **Portable-state hand-off reference.** Ships a signed `abode::AbodeSnapshot` through an injected restore gate. Its payload and pending hand-off are memory-only, and the destination currently becomes authoritative before the source seals; it is not the crash-safe authority protocol used for a durable Job home. |
| `cosmos/creatures/omega-federator` | native | **Cross-Realm federation.** An `OMEGA_GATEWAY` consumer: pull anti-entropy across Realms, signed reputation over SEER consensus, and a quarantine path. Writes reputation/quarantine onto the registry `Entry`. |
| `cosmos/creatures/federation-scheduler` | native | **Federation cadence.** Pokes the federator's bounded anti-entropy pull at the operator-injected `omega serve --pull-interval`; it supplies timing, not trust or merge policy. |
| `cosmos/creatures/fitness-selector` | native | **Loop 2 (author → select → promote).** Aggregates the proprioceptive fitness signal per watched creature, scores each by an *injected* `FitnessScorer`, and signs a self-verifying promotion onto the registry reputation slot. The substrate ships no fitness criterion. |
| `cosmos/creatures/immune-response` | native | **Loop 4 (defend).** The dual of the selector: subscribes to PROPRIOCEPTION and applies a reversible quarantine for a watched local fault. Its injected `QuarantineTrust` gates only inbound cross-Realm notices. Defense overrides selection when the operator's admission policy consults the marker. |
| `cosmos/creatures/verifiable-die` | native | **Verifiable randomness.** A commit-and-reveal die over the envelope `commitment` slot; any peer can later verify a "random" pick was not secretly chosen. |
| `cosmos/creatures/abode-reconciler` | native | **Abode fork & merge.** Reconciles two forks of an Abode over an *injected* merge lattice (CRDT-style). |
| `cosmos/creatures/function-home` | native | **v0.4.4 Job authority mechanism.** A fail-closed, signed, hash-chained home ledger for submit/status/events, commands, grants, causal children, and verified execution observations. Scheduling and workflow stay outside it. |
| `cosmos/creatures/function-executor` | native | **v0.4.4 execution mechanism.** Realm-local durable deployment/claim dedup and signed attempt/refusal facts; injected Kernel introspection checks the current CreatureId occupant's exact manifest/artifact identity before invocation through the existing handle path. |
| `cosmos/creatures/function-resolver` | native | **v0.4.4 resolution mechanism.** Resolves one exact Realm/name/version/entrypoint alias to one immutable content address and refuses ambiguity. Ranking/trust stay injected. |
| `cosmos/creatures/function-locator` | native | **v0.4.4 location mechanism.** Tracks signed home leases; higher epochs supersede lower ones, while a same-epoch higher sequence may refresh only the coordinator over an otherwise identical authority/custody/location binding. |
| `cosmos/creatures/job-blob-fs` | native library | **v0.4.4 value mechanism.** Bounded fail-closed filesystem CAS for opaque input/result/checkpoint bytes, including ciphertext; it decides no retention, authorization, or encryption policy. |
| `cosmos/creatures/prototypes/distributors/distributor-roundrobin` | native | **Injected prototype, NOT substrate.** Binds to `Role::DISTRIBUTOR`; a minimal-viable round-robin demo that proves the `Intent` socket works. Coexists with the real Distributor as the IoC-composability proof — two distributor creatures can coexist; operator picks one with `bind_role`. |
| `cosmos/creatures/prototypes/reputation/reputation-roundrobin` | native | **Injected prototype, NOT substrate.** A `ReputationWeigher` for `omega-federator` that assigns weight `1.0` to every verified attestation. |
| `cosmos/creatures/prototypes/policies/policy-dev` | native | **Injected prototype, NOT substrate.** Permissive dev policy — admits everything. |
| `cosmos/creatures/prototypes/policies/policy-signed` | native | **Injected prototype, NOT substrate.** Requires an Abode-signed manifest + verified build-hash. |
| `cosmos/creatures/prototypes/policies/policy-budget` | native | **Injected prototype, NOT substrate.** Consumes the `BudgetSignal { level, kind, vector }`; ships `BudgetApoptosis` and `BudgetGraceful` siblings. |
| `cosmos/creatures/prototypes/policies/policy-origin` | native | **Injected prototype, NOT substrate.** Consumes authenticated origin verdicts and, after an injected threshold of non-`Verified` events, asks `Role::TRANSPORT` to reversibly forget that peer. |
| `cosmos/creatures/prototypes/policies/policy-job-basic` | native | **Injected prototype, NOT substrate.** Deterministic bounded placement/retry filling for the `function-policy` socket; an AI-authored scheduler or workflow policy replaces it without changing Job custody. |
| `cosmos/creatures/prototypes/policies/policy-abode-allowlist` | native | **Injected prototype, NOT substrate.** Reference `RestorePolicy` for the abode-migrator's admission gate. |
| `cosmos/creatures/prototypes/policies/policy-prefer-promoted` | native | **Injected prototype, NOT substrate.** Admits by the fitness-selector's signed promotion (vs. an `AllowAll` baseline). |
| `cosmos/creatures/prototypes/policies/policy-quarantine-{trust-all,trust-realm,aware}` | native | **Injected prototypes, NOT substrate.** `QuarantineTrust` gates for immune-response; `-aware` makes defense override selection. |
| `cosmos/creatures/prototypes/scorers/scorer-{success-rate,latency,roundrobin}` | native | **Injected prototypes, NOT substrate.** `FitnessScorer` models for the selector. |
| `cosmos/creatures/prototypes/gateways/realm-gateway`, `cosmos/creatures/prototypes/gateways/omega-gateway` | native | **Injected prototypes, NOT substrate.** Reference gateways for the `Realm` / `Omega` address grain; preserve `commitment` on rewrite. |
| `cosmos/creatures/prototypes/merge/merge-lww-map` | native | **Injected prototype, NOT substrate.** A last-writer-wins merge lattice for the abode-reconciler. |
| `cosmos/creatures/prototypes/responders/responder-{policy,budget,fitness,curation}` | native | **Injected prototypes, NOT substrate.** Standing SEER consumers that share the bounded responder skeleton and inject only the topic-specific decision. |
| `cosmos/creatures/prototypes/monitor` | native | **Injected prototype, NOT substrate.** Read-only renderer for bounded PROPRIOCEPTION and FITNESS sense events. |
| `cosmos/creatures/prototypes/dialogue/dialogue-initiator`, `cosmos/creatures/prototypes/dialogue/dialogue-responder` | native | **Injected prototypes, NOT substrate.** A named-peer SEER turn pair over the same local, cross-node, or cross-Realm address seam. The responder retains its immediate injected `Responder` reference path and adds signed, bounded, off-drain `DialogueMind` calls through `mind::Model`; compositions causally chain turns. |

## Cosmology map

| Cosmology | Status |
|---|---|
| **creature** (daemon / beast / critter) | ✅ daemon + beast + critter real |
| **Sanctum** (node) | ✅ `sanctum`, run as `alpha node` (operator/authoring) or `omega serve` (federation/gateway) |
| **Abode** (portable per-identity state) | ✅ authorship key + `abode::AbodeSnapshot` + hand-off migration + fork/merge reconciler |
| **Function / Job** (typed capability + durable invocation) | ✅ v0.4.4 foundation, reference organs, and suite-compositional two-Realm process acceptance |
| **Realm** (federated mesh) | ✅ the `Realm` address grain + `realm-gateway`; cross-node ship over ed25519 TCP |
| **Omega** (global federation + Bestiary) | ✅ the `Omega` grain + `omega-gateway` + `omega-federator` (pull anti-entropy + reputation + quarantine), run as a server by `omega serve` |

## What the substrate does NOT do (yet)

The substrate ships sockets, not models — and it is pre-1.0. The following are *deliberately* not
here. Each is discipline, not omission.

- **Byte-exact script memory accounting.** The critter tier is real and sandboxed, but
  its `mem_bytes` enforcement is Rhai structural caps (string / array / map size), not
  the beast tier's byte-exact linear-memory limiter. A workload that needs exact memory
  caps should run as a beast.
- **Built-in models.** No placement intelligence, trust policy, consensus / weight scheme, fitness
  criterion, scheduler, workflow, retry timing, or clock semantics lives in the fabric. The substrate ships the *sockets* and prototype
  creatures (`cosmos/creatures/prototypes/*`) only; production models are injected per deployment. This is the central
  invariant, not a gap. The shipped mechanisms — the Distributor, reputation, fitness
  selection, immune quarantine, verifiable randomness — are each a creature bound to a socket, never
  a model baked into the kernel.
- **Cross-tier runtime migration.** A creature authored as a beast and re-instantiated as a native
  daemon (or vice versa) at runtime is unsolved — both load through one `Engine::load` path, but the
  artifact formats differ. See the hard problems below.
- **Running-execution migration or exactly-once side effects.** A Job home can move; an already
  executing attempt does not. Callers choose at-most-once or at-least-once delivery. Exactly once
  requires cooperation from an idempotent or transactional external sink and is not promised by
  the fabric.
- **A universal global locator.** v0.4.4 carries signed home leases and a replaceable locator role;
  discovery, gossip, quorum, and global routing policy remain injected mechanisms/models. Current
  Omega routes to an explicitly configured gateway/target.
- **Production security hardening / external audit.** The fabric-integrity floor is enforced by
  construction and the native trust limit is stated honestly, but Alpha has not been
  audited and is not hardened for hostile production. See [`../SECURITY.md`](../SECURITY.md).
- **Product UI / `gawd.ai`.** Out of scope at the substrate level.

## The hard problems the substrate is honest about leaving open

1. **Cross-tier ABI evolution.** Native speaks the `gawd_creature_v1` POD vtable; beasts
   speak the wasmtime instance contract. Both load via one `Engine::load` path, but
   crossing tiers at runtime (a creature authored as wasm, re-instantiated as native, or
   vice versa) remains an open question.
2. **Convergence at scale.** The `Realm` / `Omega` address grain, cross-node ship over
   ed25519 TCP, and pull anti-entropy with signed reputation all exist. The guarantees
   under partition, churn, and Byzantine peers *at scale* — the consensus / weight models that
   would harden them — are injected per deployment, and proving them out is future work.
3. **The native trust limit.** Native is *trusted-by-admission* — the substrate
   hardens its own surfaces against tenants (bounded queues + backpressure,
   no-panic parsing of hostile envelopes/manifests, creature-fault isolation at
   every FFI seam) but cannot fully contain malicious in-process native code; an
   operator who loads native vouches for it. Stated plainly, not pretended
   otherwise.
4. **Non-equivocating authority under partition.** A portable home uses monotone epoch grants and
   fail-closed hand-off, but freely delegated host keys cannot prove exclusive authority during a
   partition. Strict non-equivocation needs an injected root/quorum/lease authority that durably
   issues only one next epoch. Silence is never permission for a frozen source to thaw.
