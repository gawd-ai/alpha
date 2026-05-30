# Changelog

Alpha is **pre-1.0**. 0.4 is the first public contract baseline: the `Envelope` (a message in motion)
and the signed `Manifest` (a creature at rest) are documented deliberately, but minor releases may
still change contracts when correctness, security, or the operating model requires it.
Semantic-versioning guarantees begin at 1.0.

For how the system works, see [`docs/CONCEPTS.md`](docs/CONCEPTS.md),
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and the design notes under [`docs/design/`](docs/design/).

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
