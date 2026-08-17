# Addressing, placement, and federation

Alpha distributes *work*, not just code. A creature usually belongs on a particular kind of body
— near the data, on an accelerator, beside a sensor, inside a jurisdiction. Above any single body,
Sanctums federate into Realms, and Realms federate into the Omega (Ω). This document covers the
three mechanisms that make that real: the **address grain** that names a target at any depth, the
**Distributor** that places work on a fitting body, and the **federation** seam that lets Realms see
and trust each other across the Ω membrane.

The discipline throughout is inversion of control. The fabric ships *sockets* and an *address
shape*; the *models* — who is in a Realm, how Realms connect, how a placement tie is broken, how
much a peer's word counts — are creatures bound to roles, never substrate behaviour. One bus, one
envelope, a three-job kernel.

## The address grain

`aether::Address` is the single destination type every envelope carries. It composes **by depth**:
a federation-grain address is the *same* envelope as a local one, with one more layer of resolution
— not a parallel routing system.

```rust
pub enum Address {
    Creature(CreatureId),          // identity: a specific local creature
    Node(NodeId, CreatureId),      // identity: a creature on a peer node, via the transport socket
    NodeRole(NodeId, Role),        // capability: an explicitly exposed role on one exact peer node
    Kernel,                        // the kernel's own control surface
    Topic(Topic),                  // fan-out to every subscriber of a topic
    Role(Role),                    // capability: whoever is bound to this IoC socket
    Intent(Intent),                // capability: the Distributor hook — resolve + place this work
    Realm { realm: RealmId, target: Box<Address> },   // a target in some other mesh of Sanctums
    Omega { realm: RealmId, target: Box<Address> },   // a target reached across the Ω membrane
}
```

Three local delivery shapes coexist. **Identity addressing** (`Creature` / `Node` / `Kernel`) names
*this* creature or node. `Topic` fans out to every subscriber. **Capability addressing** (`Role` /
`NodeRole` / `Intent`) names *whoever* is bound to fill a concern — the IoC socket. `NodeRole`
narrows discovery to one exact node: the source sends it through transport, and the receiving
attesting transport resolves only a host binding explicitly exposed with `Kernel::bind_remote_role`.
That route is discovery, not end-to-end authority; application proofs still decide whether an
operation is valid. These shapes use the same envelope and are resolved differently: an unbound
`Role`/`Intent` returns `NoProvider`, while an unexposed or unbound `NodeRole` fails closed at the
receiving transport.

**`Realm` and `Omega` wrap an inner `target`.** Because the inner target is itself an `Address`, the
wire shape can express any destination inside the named Realm. A gateway unwraps one layer and
re-routes only the subset its implementation can reach. The reference `realm-gateway` forwards an
inner `Creature(m)` as `Node(peer, m)`. `omega-federator` admits `Creature(m)`, an exact
`Node(gateway, m)`, or an exact `NodeRole(gateway, role)` for the Realm's mapped gateway Sanctum;
bare ambient capabilities and targets on another Sanctum fail closed. Consequently
`transport-tcp` sees `Node` or `NodeRole`, never the `Realm`/`Omega` wrapper. This is the same
composition-by-depth trick used for capability addressing, lifted to federation depth.

**Nesting is bounded.** `MAX_ADDRESS_NESTING_DEPTH = 8` caps how many `Realm` / `Omega` wrappers an
envelope may carry. Real federation uses one wrapper (`Realm(R, Creature(m))`) or two
(`Omega(R, Realm(R, Creature(m)))`); the ceiling is generous so a richer multi-grain federation
creature has headroom, while a pathological deeply-wrapped address is rejected before any gateway
tries to unwrap it. `Address::nesting_depth` is iterative, so computing the depth is itself safe on
a hostile input.

**The grain lives in `aether`.** `Address`, the router that binds it, and the nesting ceiling are
all in the substrate's core crate. `RealmId(String)` is defined once in the base contract crate
`sigil` and re-exported through `aether` and `realm`, because the same type serves two concerns: an
**address grain** (`Address::Realm` / `Omega`) and an **authorship assertion** (`Provenance.realm` —
the author claims their creature belongs to this Realm, and the Abode key signs it alongside).
Defining it once keeps the routing type and the signed-assertion type from ever drifting, and avoids
a crate cycle. `RealmId::local()` is the default: a creature or entry with no Realm assertion belongs
to the `local` Realm.

## The Bestiary: registry and publication

A creature becomes useful beyond its origin node when it can be **published, discovered, and
fetched**. That is the registry — and, viewed across the Ω, the **Bestiary**: the catalogue of
creatures, which doubles as the evolutionary gene pool.

The substrate ships a socket, `Role::REGISTRY`, and two creatures fill it: `creatures/registry-mem`,
the reference **in-memory** store (the stub — no persistence, no replication), and
`creatures/bestiary-daemon`, a **durable, distributed, curator-injected** store (deterministic in the
stock compositions, optionally model-backed). Both speak the *same* op
vocabulary, so a test or a demo picks one by which `Box<dyn Creature>` it loads; an operator who wants
something else writes a third on the same socket and the kernel is none the wiser. The wire types
themselves live in the `bestiary` contract crate (`registry-mem` re-exports them), so the catalogue
contract and its durable implementation never drift.

`registry-mem` is intentionally bounded by default: it refuses new `(RealmId, artifact_hash)` keys at
`DEFAULT_MAX_REGISTRY_ENTRIES` while still allowing re-publish of an existing key. `with_max_entries(0)`
is the explicit opt-out for demos or labs that accept unbounded in-memory catalog growth. Its
full-artifact `ListEntries` anti-entropy snapshot is separately capped by total artifact bytes before
the source clones entries into a reply; `with_max_snapshot_artifact_bytes(0)` is the explicit opt-out.

- **Keyed by `(RealmId, artifact_hash)`.** `artifact_hash` is `sha256(artifact_bytes)`. Two
  creatures with identical bytes in different Realms are distinct entries by construction — Realm
  grain is load-bearing, not cosmetic.
- **Ops are JSON in the envelope payload.** `Publish` / `Fetch` / `FetchMetadata` each carry an
  optional `realm`: absent (the field elides from the wire) means the local Realm, `Some(r)` names a
  Realm explicitly. The reply always echoes the resolved Realm.
  Legacy full fetch carries artifact bytes in the reply for compatibility. The preferred ship path is
  `FetchGxPlan` / `FetchGxPlanInRealm` followed by `FetchGxChunk` / `FetchGxChunkInRealm`: the
  registry replies with a manifest plus GX transfer plan, and the requester pulls bounded
  `gawdxfer` chunks on the `transport.gx.chunk` lane at its own pace. Each chunk request echoes the
  plan's `transfer_id`, `chunk_size`, and `chunk_index`; the registry derives the plan's whole-file
  hash from its `(realm, artifact_hash)` key, so plan creation and chunk serving do not re-hash the
  whole artifact per request and do not trust redundant caller-supplied hash metadata. GX fetch
  plan/chunk-pull path clamps requested chunk sizes to the shared GX min/max bounds, preserving valid
  sizes below the default (for example sctl's 64 KiB flaky-link setting) rather than forcing every
  request to 256 KiB. The compatibility push shortcut clamps tiny chunks up to the default, because
  it emits every chunk into one `Outcome` and must not let one request create a dispatch flood. All
  fetch-family lookup variants reject malformed lookup metadata before touching the store:
  `artifact_hash` must be exactly lowercase SHA-256 hex, and chunk pulls also validate that the GX
  `transfer_id` has the registry-issued `registry.{artifact_hash}.{chunk_size}.{seq}.{corr}` shape
  and belongs to that artifact's returned plan and chunk-size policy, because the general registry op
  payload cap is large enough for legacy artifact publish bodies.
  `FetchGx` / `FetchGxInRealm` remain compatibility push shortcuts that return the same plan and then
  stream every chunk. Metadata fetch carries only the catalog row plus artifact length for
  operator/control lookups. Artifact bytes that still ride inside JSON are **hex-encoded**, not as a
  serde number array — the latter expands ~4× and parses orders of magnitude slower, enough to blow a
  publish RPC's timeout on a multi-megabyte `.so`.
- **The `Entry` carries two optional slots** beyond `(manifest, artifact)`: a `reputation`
  (`ReputationScore`) and a reversible `quarantine` (`QuarantineNotice`). Both default to `None`, so
  the wire bytes of a slot-less entry are unchanged. A (re)publish of a `(realm, artifact_hash)`
  resets both — the registry-layer form of reversibility.
- **Signal-only metadata is separately shape-capped.** Registry op payloads allow large
  hex-encoded artifacts, but reputation/quarantine keys, provenance labels, signatures, reasons, and
  attesting-peer lists are short audit/control metadata. The shared `bestiary` wire contract owns
  those caps, and both registry fillings reject malformed signal markers before retention or
  persistence.

**Publish never grants trust.** The registry stores and retrieves; it does not authorize. Every byte
arriving via `fetch` runs the *receiver's* full admission gate (provenance signature + artifact-bytes
hash + injected policy) before it can load. The Bestiary's job is *availability*, not *authorization* —
which is exactly what lets an operator swap registry implementations without touching admission.

The two reputation/quarantine slots have two kinds of producer. A **local** promotion is *signed*: a
fitness selector signs the `(artifact_hash, realm, score, attesting_realm)` claim with its Abode key
and stamps `signed_by` + `signature`, so an admission policy can verify it. A **federated** peer
reputation is *unsigned* in the slot — its provenance is the `attesting_realm` tag, because the
observer signed the SEER *delta* (a different payload), verified by the federator at ingest. Both
live in the one slot without retrofit, distinguishable by provenance.

### The durable Bestiary

`bestiary-daemon` is the registry made **durable, replicated, and curated**, while serving every
existing `RegistryOp` byte-for-byte — so any creature that consults `Role::REGISTRY` over the bus
works against it unchanged. Its new capability rides an additive `bestiary.op` schema
(`ProveEntry` / `Compact` / `PushEntries`), so the legacy wire is untouched.

- **On-disk, integrity-first.** The reference `FsBestiaryStore` lays an artifact out as a
  content-addressed, deduplicated blob (`<root>/blobs/<artifact_hash>`, atomic temp-then-rename) and a
  per-Realm **tamper-evident signed log** (`<root>/log/<realm_hash>.jsonl`). Each `LogRecord` chains to
  the prior record's hash and is signed by the daemon's Abode key, so a flipped log byte or a spliced
  entry is caught on replay. Blob reads are bounded by the configured artifact cap (or, for snapshots,
  by the remaining snapshot byte budget) and recompute the content address before returning full
  artifact bytes; GX chunk serving uses bounded range reads instead of re-reading and re-hashing the
  whole blob per chunk, with the transfer plan and receiver final hash check preserving admission
  integrity. A later publish of the same content rewrites a corrupt existing blob rather than trusting
  the filename as valid dedupe. The Realm name is **only ever hashed**, never path-joined — a
  `RealmId` from the wire may contain `/` or `..`, so joining it into a path would be a remote
  arbitrary-file-write primitive; hashing closes it.
- **A self-owned journal.** `recover()` replays the log at bind and **rejects any record not authored by
  the daemon's own key** (`ForeignAuthor`). The on-disk log is a self-owned journal, not a federation
  inbox: peer entries never arrive as foreign records replayed at bind. Imports arrive through
  validated daemon operations (`PushEntries`, or ordinary `Publish` when a federator uses the daemon
  as its local registry) and are **re-signed under the local identity** on ingest.
- **Bounded by default, like the in-memory registry.** The durable store retains at most **1,024**
  distinct `(RealmId, artifact_hash)` keys across live entries and permanent tombstones
  (`DEFAULT_MAX_BESTIARY_ENTRIES`), rejects an artifact above the **128 MiB** ceiling, caps unique
  physical blob files (including orphans) to that same 1,024-file ceiling and **4 GiB** aggregate
  bytes (`DEFAULT_MAX_BESTIARY_BLOB_BYTES`), and caps durable JSONL across all Realms at **256 MiB**
  (`DEFAULT_MAX_BESTIARY_LOG_BYTES`); each limit has an explicit `0` opt-out
  (`with_max_entries` / `with_max_artifact_bytes` / `with_max_blob_bytes` /
  `with_max_log_bytes`). Published manifests are also re-run through `Manifest::validate`, whose
  metadata strings and lists are capped before the store retains them. The nonzero retained-key cap
  also bounds physical blob-file count, including orphans, so tiny content cannot bypass the byte
  budget through inode/metadata exhaustion. `recover()` fails closed if the retained-key,
  physical-blob-count, aggregate-blob, or aggregate-journal cap is exceeded, and rejects symlink,
  special, or otherwise unaccountable blob-directory entries. Each JSONL record is also capped before
  append, compaction rewrite, and recovery line allocation; compaction dry-runs every Realm against
  the planned aggregate before its first replacement and grows only one Realm buffer geometrically
  at a time. Startup removes only exact regular Bestiary atomic-temp names.
  Steady-state aggregate caps exclude atomic temps: a write can transiently require one additional
  artifact (128 MiB by default) and compaction one additional rewritten Realm chain. An uncertain
  append or partial compaction latches the store unhealthy; no reads, writes, compaction, or
  replication proceed until a complete recovery re-establishes the catalog and chain heads. The
  advisory `.head` tip hint is read under a small cap and ignored if malformed; artifacts live in
  blobs, never in log lines. The legacy
  `ListEntries` full-artifact
  anti-entropy reply, the daemon's autonomous `PushEntries` snapshot, and the curator's artifact-byte
  snapshot are also capped by total artifact bytes before the store reads/clones blobs into the
  payload. A `PushEntries` batch is count-capped before the daemon iterates entries or calls the store;
  the autonomous outbound batch uses the same count cap before blob stats/reads. Metadata lookup stays
  byte-light for catalog visibility, but fetch/GX planning separately proves the backing blob is under
  the active artifact cap before advertising bytes or chunks. The retained replication-peer list is
  also capped and shape-checked at daemon construction; `0` in that constructor's peer-limit
  parameter is the explicit unbounded opt-out. A publish past the entry cap is a
  wire-honest error (not a false `Published`); a federation `PushEntries` of a *new* key into a full
  catalogue is skipped (best-effort lattice merge) rather than failing the whole batch.
  Quarantine markers use the same shared shape caps, and the durable store refuses a sticky
  attesting-peer union that would grow beyond the peer cap.
  The opt-in `alpha node --functions` composition retains the local no-replication posture and runs
  compaction only when the store became dirty, at most once per hour. It does not wake hourly to
  rewrite an unchanged catalogue or silently invent federation peers.
- **Verifiable entry proofs.** `ProveEntry` returns a standalone `EntryProof` — the daemon signs
  `(realm, artifact_hash, manifest_hash, first_seen, attester)` with its Abode key. Anyone verifies it
  with the attester's pubkey, and because it commits to the compaction-stable `first_seen` rather than a
  chain position, it **survives compaction** (which rewrites a fresh genesis chain). `Compact`
  garbage-collects orphaned blobs across *all* Realms at once (a blob deduped by hash but referenced
  per-Realm), preserving each survivor's `first_seen` verbatim.
- **Replication is a monotonic lattice, not last-write-wins.** A `PushEntries` merge unions membership,
  takes the **verified-greater** signed reputation (a bare push can't clobber a locally-higher signed
  score), and treats quarantine as **sticky** — a re-put never clears it; only an explicit signed
  `Unquarantine` does (preserving reversibility while killing the silent safety-signal drop). A
  `Tombstone` federates as a *permanent* eviction for a regretted artifact, complementing reversible
  quarantine. Membership converges to the union idempotently; mutable signals converge by the lattice —
  no wall-clock arrival-order assumption, because the substrate ships no clock.
- **Curator-injected; optionally model-backed.** An injected `Curator` decides `Keep` / `Promote` /
  `Demote` / `Quarantine` / `Gc`
  per entry. The reference `DeterministicCurator` is **safe-by-default** — it never collects an entry it
  hasn't ruled on, and disables GC entirely until configured. An `AICurator` consults an injected
  `mind::Model` over each entry's *manifest + artifact bytes* for content-aware near-duplicate and
  anomaly judgments the deterministic one cannot make; the model call runs on the daemon's own
  anti-entropy thread, off the synchronous catalogue path, so it never blocks a fetch. Its prompt,
  completion parser, and retained decision cache are bounded by default; overflowing the cache fails
  safe to `Keep`, with `with_max_cache_entries(0)` as the explicit lab/demo opt-out. (`SeerTopic::
  Curation` reserves the seam for an *external* curator creature consulted over the bus.)

**Publish still grants no trust** here either: the durable store makes a creature *available and
provable*, never *authorized*. Every fetched byte runs the receiver's full admission gate on load, so a
forged `Put` smuggled past at-rest integrity is still refused at the creature-load signature/calls
gate. Durability is at-rest hardening; admission stays the choke point.

Pull-based federation applies the same content-address discipline before it writes locally: an
`omega-federator` merge pins entries to the requested Realm, rejects a pulled row whose
`artifact_hash` is not canonical lowercase SHA-256 or does not match `sha256(artifact_bytes)`, and
only then emits a realm-scoped `Publish` plus any reputation/quarantine re-apply ops. A malformed peer catalog
therefore cannot use anti-entropy to smuggle an inconsistent registry row into the local Bestiary.

The Bestiary is also the durable **deployment artifact** plane for typed Functions: an explicit
deployment references one immutable manifest content address, entrypoint, and artifact hash, and may
carry an `EntryProof`. It is deliberately **not** the mutable Job database. Bestiary operations form a
catalogue/curation lattice and foreign sync entries are verified then re-signed into the local
journal; a Job needs ordered attempts, cancellation races, and preservation of the executor's original
foreign signed receipt. Those facts live in the function home/executor ledgers described in
[`functions-and-jobs.md`](functions-and-jobs.md#two-ledgers-one-authority-for-each-fact).

## Function resolution, placement, and location

A typed Function adds three separate questions; collapsing them would let a model silently rewrite
identity:

1. **Definition:** `function-resolver` maps an exact
   `(Realm, name, version, entrypoint)` alias to one immutable
   `FunctionId { manifest_content_address, entrypoint }` and artifact hash from Bestiary metadata. It
   collapses identical replicated rows and rejects zero or multiple distinct matches. It does not rank
   by reputation, freshness, price, or fitness.
2. **Deployment/attempt placement:** a creature bound to `function-policy` selects among admissible
   live deployment receipts and decides retries, cost/data locality, priority, and workflow. The
   reference `policy-job-basic` is deterministic and bounded; an AI-authored scheduler can replace it.
   The selected alias resolution and deployment are pinned in the accepted Job before any grant, so a
   later alias update cannot change a running Job.
3. **Home location:** `function-locator` verifies signed `HomeLeaseV1` observations. A higher custody
   epoch supersedes a lower one. Within an epoch, only a strictly higher-sequence coordinator refresh
   may replace a lease when Home, epoch, Realm/node, authority, custody/handoff, checkpoint, and time
   observations are identical. Every other divergence is `Conflict`; sequence never permits a
   location or authority rewrite. Discovery/gossip and expiry policy remain replaceable.

Current Omega routing still needs a configured Realm gateway and explicit inner creature/role target;
it is not a universal `HomeId → Address` service. The locator role and
`gawd.function.locate.v1` schema make that future mechanism composable without adding a router case.

## Embodiment and placement: the Distributor

An `Address::Intent` names a *desired outcome plus requirements* and no creature. Resolving it to a
concrete creature on a fitting body is the **Distributor**, the role that places work — GAWD's third
governing loop.
It is itself an injected creature bound to `Role::DISTRIBUTOR`; the kernel never picks.

Placement is a **consult-and-reconcile** conversation over the SEER bus, on the `placement` topic.
Two creatures play it:

- **`distributor-requirements`** binds `Role::DISTRIBUTOR`. Every `Intent` envelope hits its inbox.
  It carries `Intent.requirements` as placement **predicate strings**, fires a SEER `Query` on the
  `placement` topic to **every** known advertiser (local + peer) under a fresh consult `corr`, using
  one `query_id` per advertiser, parks the Intent, and accumulates `Answer`s. Intent outcome and
  requirement strings are shape-bounded before fan-out, so an oversized address header becomes a
  bounded `IntentShapeRejected` no-provider reply instead of many large SEER queries. Duplicate or
  out-of-range `query_id`s are dropped, so one responder cannot be counted twice. Answer bodies are
  also shape-gated before retention: per-answer match count is capped, route node ids must be
  bounded/canonical for transport, and free-form embodiment labels are byte-bounded; malformed
  offers are ignored, while an over-cap answer does not consume its `query_id`. When the expected
  answers are in (or, under `FirstFit`, on the first non-empty match), it reconciles and dispatches
  the original Intent payload to the chosen target — `reply_to` / `corr` preserved.
- **`embodiment-advertiser`** answers placement Queries. One per Sanctum, configured with the
  Sanctum's `NodeId` and a list of `(CreatureId, Embodiment)` *offers* — the targets the operator
  chose to expose. For each Query it checks each offer against every predicate and answers with the
  matching `EmbodimentOffer`s, capped to the shared placement answer limit. Its retained offer table
  is also bounded by default and sanitized at construction: malformed offers are dropped up front,
  valid offers beyond the default cap are not retained, and `0` is the explicit lab/demo opt-out.
  It shape-checks direct Queries against the same requirement/outcome bounds the distributor uses
  before parsing predicates. It does not introspect the kernel, does not rank, does not time out.

### Requirements as a predicate language

`Intent.requirements` carries a minimal, reserved predicate vocabulary — the *authoring* form is a
human string, parsed on receipt into a structured `Predicate` that then travels on the wire:

- `cpu >= N` — embodiment cores ≥ N
- `mem >= N` — embodiment `mem_bytes` ≥ N
- `accelerator contains X` — case-insensitive match against the embodiment's accelerators
- `jurisdiction in {a,b,c}` — embodiment's jurisdiction is one of the named set
- `connectivity = X` — embodiment's connectivity equals X exactly

An unspecified embodiment field never matches a predicate that demands it (a `None` jurisdiction is
"no claim," not "any") — the safe default; an operator who wants permissive matching writes broader
predicates. The language is deliberately small: an operator extends it by binding a richer advertiser
whose own matching is opaque to substrate, or by adding a predicate arm. A garbage predicate is
dropped, never fatal; advertisers match the surviving subset.

### Local-vs-remote pick

Each `EmbodimentOffer` carries the advertiser's `node` and a `creature_id`. On reconcile the
distributor collapses the address by node: an offer whose `node == self_node` becomes
`Address::Creature(id)` (same-Sanctum delivery); any other becomes `Address::Node(peer, id)` (routed
off-node via the `transport` socket). The same envelope shape either way — "route off-node" is one
more delivery case, not a new subsystem.

### Reconciliation is an injected model

The picker is a `PickModel`, swappable:

- **`FirstFit`** — first matching offer wins; reconciliation fires on the first non-empty answer.
- **`RoundRobin`** — wait for every expected answer, then cycle across the flattened match list.

Best-fit-by-headroom, weighted-vote, and a **verifiable-die** tie-break are natural further models —
each a one-arm addition on the *same* consult shape, never a new bus contract.

**The consult fires even for a single local advertiser.** This is structural: the distributor always
emits a SEER Query, even when there is exactly one local offer, and the traffic is observable on the
bus journal. Wiring the consult early means cross-Realm or fitness-weighted placement lands as a new
`PickModel`, never as a synchronous local code path retrofitted into placement later.

**A failed consult is structured and retained state is bounded.** When every advertiser answers empty
(or there are none, an abort steer arrives, or the pending table must evict the oldest consult at its
default cap), the distributor emits a `NoProviderReply` to the Intent's `reply_to` with a tagged
reason — never a panic, never a silent drop. `with_max_pending(0)` is the explicit lab/demo opt-out
for unbounded parked consults. A distinct schema (`distributor.no_provider`) from the SEER topic lets
an orchestrator bind the consult-reply path separately from the Intent-reply path.

## Realm: a trust domain

A **Realm** is a mesh of peer Sanctums that have chosen to trust one another — the grain at which
membership, peering, and shared policy are reasoned about above any single body. The `realm` crate
owns the routing **seam** and **mechanism** for the `Address::Realm` grain; the routing *decision* is
injected.

- **`realm::GATEWAY_ROLE`** is `Role::REALM_GATEWAY`. `Address::Realm` envelopes route to whoever
  binds it.
- **`realm::RealmRouting`** is a decision-only trait: given a `RealmId` and the inner `target`,
  return a `RealmResolution` — `Forward(NodeId)` to a peer Sanctum, or `NoRoute(reason)`. A pure
  function: no bus handle, no I/O.
- **`realm::serve(impl RealmRouting)`** wraps a routing policy into a loadable gateway creature and
  owns the invariant *mechanism*: it rewrites `Realm(R, Creature(m)) → Node(peer, m)` while
  preserving `reply_to`, `corr`, `commitment`, `schema`, and the payload bytes **byte-for-byte** —
  only the destination grain changes. Dropping the `commitment` slot during that rewrite is a real
  bug class the `serve` mechanism exists to make impossible (a Realm envelope may carry a
  commit-and-reveal payload the receiving Realm must verify). A non-Realm envelope, or a `Forward` on
  a non-creature target, is a defensive no-op, never a crash.

A failure produces a structured `realm.no_route` reply (`UnmappedRealm` or `UnsupportedTarget`) owned
by the `realm` crate, so a consumer parses it without depending on any one gateway example. The
gateway *policy* stays a creature — the reference `realm-gateway` is a single-peer-per-Realm
`HashMap<RealmId, NodeId>`; a richer multi-peer, partition-tolerant, jurisdiction-matched policy is
another creature on the same socket, and the substrate is none the wiser.

The grain rule: **a Realm deals with its Sanctums; the Omega deals with Realms.** Placement *across
the Sanctums inside* one Realm is that Realm's own distributor; admitting a Sanctum into a Realm is
that Realm's gate. Cross-Realm placement rides the unchanged distributor over the Node grain
(transport peering) — it does *not* relay through the Ω gateway.

## Omega: the Ω membrane and cross-Realm federation

The **Omega** is Ω — the set-of-Realms, the outermost authority that provides common services to the
Realms beneath it. GAWD's cosmology is a closed membrane: `alpha` is α, the front door through which
every stimulus enters and every product leaves; `omega` is the ceiling. Everything that exists,
exists between α and Ω; the only things outside are stimuli (inputs) and products (outputs).

The `omega` crate is lean and real: it owns the gateway socket and a wire contract, and it *reserves*
the future Ω authority rather than bolting it on later.

- **`omega::GATEWAY_ROLE`** is `Role::OMEGA_GATEWAY`. `Address::Omega` envelopes route to whoever
  binds it. Unlike `realm`, `omega` defines **no** routing-seam trait: its gateways diverge at the
  root — a stub that defers every address vs. a federator that runs stateful anti-entropy — so there
  is no single per-envelope `resolve` worth lifting to the crate. Each gateway owns its own routing.
- **`omega::OmegaServices`** is the reserved seam for Ω-level authority, stated at **Realm grain**:
  `realms()` (the set-of-sets membership) and `admits(realm)` (which whole *Realms* belong to the
  federation, distinct from a Realm's gate over which *Sanctums* join it). It is shape-only — an
  object-safe trait with no implementation yet — so the authority arrives as an implementation of an
  existing concept, never as a new top-level layer. Reserved services name what no single Realm
  should own: cross-Realm placement (which *Realm* hosts an Abode), Realm gating, cross-Realm
  custody, and self-containment.

### Federation: pull anti-entropy, signed reputation, quarantine

`creatures/omega-federator` fills `Role::OMEGA_GATEWAY` as the real federation creature, riding
existing wire — registry ops for catalog sync, the SEER `consensus` topic for reputation. It does
four things, each with its own route, shape, signature, or injected-model checks; artifact admission
remains the later load-time choke point:

1. **Cross-Realm routing.** An `Omega { realm, target: Creature(m) }` envelope resolves `realm → peer`
   and re-routes `Node(peer, m)`. Exact `Node(peer, m)` and `NodeRole(peer, role)` targets are also
   admitted when `peer` is that Realm's mapped gateway Sanctum; the latter stays `NodeRole` so the
   receiving attesting transport resolves only an explicitly remote-exposed host binding. Every form
   preserves `reply_to` / `corr` / `schema` / `payload` / `commitment` byte-for-byte — the same
   composition-by-depth as the realm gateway. An unmapped Realm, a bare ambient capability, or a
   target on a different Sanctum yields a structured `omega.no_route` reply.
2. **Pull-based anti-entropy.** A `PullFrom` control op sends `RegistryOp::ListEntries` to a peer's
   registry and merges the returned catalog into the *local* registry through the existing
   realm-scoped `Publish` write path. The merge is **pinned to the requested Realm**, not the Realm a peer
   tags on each entry — a scoped pull of Realm X can only ever write Realm X locally, so a peer
   cannot smuggle entries into a Realm that was not pulled. Pull, not gossip: a pull happens when an
   operator or scheduler sends `PullFrom`; the substrate ships no clock. Unanswered pulls are parked
   under a bounded default pending table, with an explicit `0` opt-out for lab/demo deployments that
   accept unbounded in-flight pull state.
3. **Signed reputation.** A `FederateReputation` op signs a `ReputationDelta` with the **observer's**
   Abode key and ships it as a SEER `consensus` `Answer`. The receiver verifies the signature — an
   unsigned or invalid delta never touches the registry — applies the **injected**
   `ReputationWeigher` (the operator's "how much does Realm X's word count?"), and writes
   `AttestFitness` tagged with the attesting Realm; the stored score is `observed_score × weight`. A
   non-finite score or weight is dropped and surfaced on a proprioception event, so a peer spraying
   junk attestations is observable; oversized, NUL-bearing, or invalid delta identity fields are
   dropped as malformed without echoing attacker-sized audit strings. Pulled registry reputation
   slots are re-checked for bounded, NUL-free shape before the federator forwards them back into the
   local registry.
4. **Cross-Realm quarantine.** A `FederateQuarantine` op ships a `QuarantineNotice` to a peer
   federator, which writes a reversible `MarkQuarantine` into its local registry. The federation
   carries the *path*; a federator-targeted notice is shape-checked but not `QuarantineTrust`-gated.
   Operators that do not grant a peer direct registry-flagging power route notices to
   `immune-response`, whose injected trust model gates the write. In either posture the marker is
   reversible and affects loading only if the operator's admission policy consults it. Outbound,
   inbound, and pulled notices are shape-checked for bounded, NUL-free short fields before a
   federator ships, stores, or forwards them.

**Admission stays the only choke point.** Federation moves *bytes* into registries; loading any
artifact still runs the operator's admission policy. A forged-signer artifact pulled from a peer is
refused on load.

## Proof of trust and verifiable randomness

With no central authority to vouch for anything, trust cannot be granted from above — it must be
*derivable from primitives* each party checks for itself. The envelope and the journal carry the
primitives; the *models* over them are injected per deployment.

| Primitive | Answers | Carried by |
|---|---|---|
| **time** | when, in what unfolding | `stamp` (prefer logical/causal over a wall clock) |
| **order / sequence** | who acted first; causality | envelope `seq`; explicit signed hash-chained application logs where durability is required |
| **weight** | how much a party counts | reputation earned over history (the registry slot) |
| **consensus** | what we agree is true | the SEER `consensus` topic |
| **permission** | who authorized; is it them | `sig` — provenance + signature |
| **history** | the honest record of before | registry lineage and durable application ledgers; the router journal is only a bounded diagnostic window |
| **verifiable randomness** | is a "random" value truly random | the `commitment` slot |

GAWD makes these *expressible*; it dictates none of their meaning. No measure of time is mandated, no
definition of trust, no threshold of "enough" consensus — those are models an operator adopts, swaps,
or runs against each other, and an operator may *reveal or conceal* a decision (including whether it
decided at all) via the same commit-and-reveal machinery.

### The verifiable die

`creatures/verifiable-die` (schema `verifiable.die`) consumes the `commitment` slot to make a fair
pick among `n` options that **any peer can audit**. It is two-phase, so *neither* party alone steers
the outcome:

1. **Commit.** A requester asks the die to roll among `n` for a `round`. The die draws a secret
   `seed` from its **injected** `EntropySource`, computes `commitment = sha256(round ‖ n ‖ seed)`, and
   replies with the commitment **also in the reply envelope's `commitment` slot** — so a relay or
   live observer carries it without parsing the body. The metadata-only router journal does not
   retain payloads or commitments. The seed stays hidden; the commitment binds it to
   `(round, n)`.
2. **Reveal.** The requester supplies a `nonce`, chosen *without* knowing the seed. The die discloses
   the seed; the result is `pick = sha256(seed ‖ nonce) mod n`.

Anyone — the requester, a skeptical peer, or an auditor with the captured application envelopes —
calls `verify_roll` with the commitment, the revealed seed, and the nonce: it recomputes
`sha256(round ‖ n ‖ seed)`, confirms
it equals the commitment (the die did not swap the seed after seeing the nonce), and returns the
recomputed `pick` (the honest function of the agreed inputs). A swapped seed, a tampered commitment,
or a wrong `(round, n)` returns `None` — provable cheating. The die has no privileged verification
path; the math is public.

The **scheme and the entropy are injected**, never substrate. The scheme is sha256 commit-reveal; a
real ECVRF or threshold-VRF is the same shape (commit a proof, reveal, anyone verifies) and slots in
as a different `verify_roll` / `EntropySource` pair on the same socket. The entropy source is
operator code: `OsEntropy` (the OS CSPRNG, production) or `FixedEntropy` (deterministic, references
and tests only — a predictable seed lets a requester pre-compute a favouring nonce).

A `verifiable-die` is the canonical injected tie-break a Distributor consults when it must fairly
break a tie among matching candidates: it puts the commitment on the Intent envelope, so the
placement decision is auditable. The die binds the *value*; it does not bind *liveness* — revealing
last, it can selectively abort an unfavourable round by withholding the reveal (a ~1-bit bias). Plain
two-party commit-reveal does not close that; an operator mitigates at the policy layer
(deadline-forfeit, reputation penalty), and a VRF closes it — a later pair on the same socket, the
shape unchanged. The reference die still has a resource floor: commit/reveal messages are capped
before JSON decode, reveal nonces are separately capped before a pending round is consumed, rejected
reason text is bounded before reply, and committed-but-unrevealed rounds are capped by default, with an
explicit `0` opt-out for lab/demo deployments that accept unbounded pending state.
