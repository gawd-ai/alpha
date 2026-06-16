# creatures — the substrate's production-capable reference organs

GAWD's real creatures: the reference implementation of each substrate role and governing loop — the
kind an operator could actually run ([`alpha node`](../../alpha) boots several of them at startup). Every
one is a creature loaded through the single `Kernel::load` path; none is privileged substrate. They
sit at the top of a **reduction gradient**: production organs here, the operator-replaceable
strategy models one level down in [`prototypes/`](prototypes), and the test-only specimens deepest in
[`prototypes/fixtures/`](prototypes/fixtures) — *every loadable unit lives under one roof*, and the
nesting states the preference: don't reach for a fixture where a prototype would do.

These are distinct organs (not a family of interchangeable models), so the directory is flat:

| Organ | Role / loop | What it is |
|---|---|---|
| `agent-templated` | AUTHORING | deterministic template-matching authoring creature — the seam an LLM-backed agent plugs into |
| `agent-curious` | AUTHORING | consultative authoring: asks an `AuthoringQuery` when no template matches, resumes on the answer |
| `build-cargo` | BUILD | sandboxed `cargo` compiler — source → signed, content-addressed `(manifest, artifact)` |
| `build-critter` | BUILD | the no-cargo sibling: validates Rhai source and signs a `Backend::Critter` manifest |
| `transport-tcp` | TRANSPORT | authenticated TCP peer link (mutual ed25519) + dynamic gossip clustering |
| `registry-mem` | REGISTRY | in-memory content-addressed Bestiary seed (`publish` / `fetch`) |
| `surface-http` | (control surface) | loadable HTTP + WebSocket control plane driving `Role::CONTROL` over the bus |
| `surface-mcp` | (control surface) | loadable MCP surface owning stdio; each tool call becomes a `Verb` envelope |
| `distributor-requirements` | DISTRIBUTOR (Loop 3) | the real placement creature — consults SEER on `placement`, routes the Intent |
| `embodiment-advertiser` | (placement) | advertises a Sanctum's `EmbodimentOffer`s to the distributor |
| `abode-migrator` | ABODE_MIGRATOR | single-active-fork migration of a running self with cryptographic continuity |
| `abode-reconciler` | (distributed self) | fork **+ merge**: reconciles two divergent snapshots via an injected CRDT |
| `omega-federator` | OMEGA_GATEWAY (Loop 5) | cross-Realm routing, pull anti-entropy, signed reputation, quarantine path |
| `federation-scheduler` | (Loop 5 cadence) | the federator's clock: pokes its anti-entropy per injected interval (`omega serve --pull-interval`) so Ω self-reconciles |
| `fitness-selector` | (Loop 2) | author→select→promote — signs a verifiable promotion onto the registry reputation slot |
| `immune-response` | (Loop 4) | senses faults, reversibly quarantines the offending artifact |
| `verifiable-die` | — | first consumer of the envelope `commitment` slot — a commit-reveal fair pick anyone can audit |

Each carries the full rationale in its `lib.rs` header. The strategy *models* these organs inject
(fitness criteria, merge lattices, admission policies, …) are the reference creatures under
[`prototypes/`](prototypes).
