# creatures — the substrate's production-capable reference organs

GAWD's real creatures: the reference implementation of each substrate role and governing loop — the
kind an operator could actually run ([`alpha node`](../../alpha) boots several of them at startup).
Every loadable organ is a creature: artifact-backed bodies use `Kernel::load`, while trusted stock
compositions install built-in organs through `load_instance` (and transport through its attesting
variant); all then share the same creature lifecycle. The one explicit non-creature entry,
`job-blob-fs`, is a direct injected storage adapter
kept beside the organs that consume its seam rather than promoted into the model-free kernel. They
sit at the top of a **reduction gradient**: production organs here, the operator-replaceable
strategy models one level down in [`prototypes/`](prototypes), and the test-only specimens deepest in
[`prototypes/fixtures/`](prototypes/fixtures) — *every loadable unit lives under one roof*, and the
nesting states the preference: don't reach for a fixture where a prototype would do.

These are distinct organs (not a family of interchangeable models), so the directory is flat:

| Organ | Role / loop | What it is |
|---|---|---|
| `agent-templated` | AUTHORING | deterministic template-matching authoring creature — the seam an LLM-backed agent plugs into |
| `agent-curious` | AUTHORING | consultative authoring: asks an `AuthoringQuery` when no template matches, resumes on the answer |
| `agent-mind` | AUTHORING | opt-in model-backed authoring filling over the injected `mind::Model` seam |
| `build-cargo` | BUILD | `cargo` compiler with an operator-injected containment seam (`Sandbox::None` by default) — source → signed, content-addressed `(manifest, artifact)` |
| `build-critter` | BUILD | the no-cargo sibling: validates Rhai source and signs a `Backend::Critter` manifest |
| `transport-tcp` | TRANSPORT | authenticated TCP peer link (mutual ed25519) + dynamic gossip clustering |
| `registry-mem` | REGISTRY | in-memory content-addressed Bestiary seed (`publish` / `fetch`) |
| `bestiary-daemon` | REGISTRY | durable Realm-sharded Bestiary filling with signed journaling, entry proofs, curation, and bounded PUSH anti-entropy |
| `surface-http` | (control surface) | loadable HTTP + WebSocket control plane driving `Role::CONTROL` over the bus |
| `surface-mcp` | (control surface) | loadable MCP surface owning stdio; each tool call becomes a `Verb` envelope |
| `distributor-requirements` | DISTRIBUTOR (Loop 3) | the real placement creature — consults SEER on `placement`, routes the Intent |
| `embodiment-advertiser` | (placement) | advertises a Sanctum's `EmbodimentOffer`s to the distributor |
| `abode-migrator` | ABODE_MIGRATOR | in-memory signed-snapshot hand-off reference; useful portability proof, not crash-safe authority or automatic private-key continuity |
| `abode-reconciler` | (distributed self) | fork **+ merge**: reconciles two divergent snapshots via an injected CRDT |
| `omega-federator` | OMEGA_GATEWAY (Loop 5) | cross-Realm routing, pull anti-entropy, signed reputation, quarantine path |
| `federation-scheduler` | (Loop 5 cadence) | the federator's clock: pokes its anti-entropy per injected interval (`omega serve --pull-interval`) so Ω self-reconciles |
| `fitness-selector` | (Loop 2) | author→select→promote — signs a verifiable promotion onto the registry reputation slot |
| `immune-response` | (Loop 4) | senses faults, reversibly quarantines the offending artifact |
| `verifiable-die` | — | first consumer of the envelope `commitment` slot — a commit-reveal fair pick anyone can audit |
| `function-resolver` | FUNCTION_RESOLVER | resolves an exact typed entrypoint from an injected Bestiary view; refuses ambiguity and legacy unstructured entries |
| `function-executor` | FUNCTION_EXECUTOR | durably registers deployments, filters them through injected exact manifest/artifact liveness, claims signed attempts before effects, proxies proof-bound typed calls, finitely retains observations/controls, and signs execution/refusal facts |
| `function-home` | FUNCTION_HOME | the single-active Abode facet owning durable Job intent, causal edges, finite observations/controls, route-bound private reads, policy consults, receipts, and fenced custody |
| `function-locator` | FUNCTION_LOCATOR | finite durable index of root-authorized Home leases; advances epochs and exposes equivocation instead of inventing a winner |
| `job-blob-fs` | injected storage seam | bounded, fsynced, content-addressed storage for caller/adaptor-supplied opaque value/checkpoint/ciphertext bytes |

Each carries its rationale and safety boundaries in its `lib.rs` header. The strategy *models* these
organs inject (fitness criteria, merge lattices, admission policies, …) are the reference creatures
under [`prototypes/`](prototypes).
