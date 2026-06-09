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
    Kernel,                        // the kernel's own control surface
    Topic(Topic),                  // fan-out to every subscriber of a topic
    Role(Role),                    // capability: whoever is bound to this IoC socket
    Intent(Intent),                // capability: the Distributor hook — resolve + place this work
    Realm { realm: RealmId, target: Box<Address> },   // a target in some other mesh of Sanctums
    Omega { realm: RealmId, target: Box<Address> },   // a target reached across the Ω membrane
}
```

Two modes coexist. **Identity addressing** (`Creature` / `Node` / `Kernel` / `Topic`) names *this*
creature or node. **Capability addressing** (`Role` / `Intent`) names *whoever* is bound to fill a
concern — the IoC socket. Both are the same envelope, resolved differently by the router; an unbound
capability address returns `NoProvider`, exactly as an unbound gateway does.

**`Realm` and `Omega` wrap an inner `target`.** Because the inner target is itself an `Address`, a
Realm envelope can name any destination — a creature, a role, an intent, a topic — *inside* the
named Realm. The gateway unwraps one layer and re-routes; `transport-tcp` never learns what a Realm
is, because it only ever sees `Node(peer, m)` after the unwrap. This is the same composition-by-depth
trick `Intent` and `Role` already use for capability addressing, lifted to federation depth.

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
`creatures/bestiary-daemon`, a **durable, distributed, AI-curated** store. Both speak the *same* op
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
- **Ops are JSON in the envelope payload.** `Publish` / `Fetch` / `FetchMetadata` operate in the
  local Realm; `PublishInRealm` / `FetchInRealm` / `FetchMetadataInRealm` name a Realm explicitly.
  Full fetch carries artifact bytes for load/replication paths. Metadata fetch carries only the
  catalog row plus artifact length for operator/control lookups. Artifact bytes ride **hex-encoded**,
  not as a serde number array — the latter expands ~4× and parses orders of magnitude slower, enough
  to blow a publish RPC's timeout on a multi-megabyte `.so`.
- **The `Entry` carries two optional slots** beyond `(manifest, artifact)`: a `reputation`
  (`ReputationScore`) and a reversible `quarantine` (`QuarantineNotice`). Both default to `None`, so
  the wire bytes of a slot-less entry are unchanged. A (re)publish of a `(realm, artifact_hash)`
  resets both — the registry-layer form of reversibility.
- **Signal-only metadata is separately shape-capped.** Registry op payloads allow large
  hex-encoded artifacts, but `MarkQuarantine` keys, reasons, and attesting-peer lists are short
  audit/control metadata. The shared `bestiary` wire contract owns those caps, and both registry
  fillings reject malformed quarantine markers before retention or persistence.

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
  the prior record's hash and is signed by the daemon's Abode key, so a flipped byte or a spliced entry
  is caught on replay. The Realm name is **only ever hashed**, never path-joined — a `RealmId` from the
  wire may contain `/` or `..`, so joining it into a path would be a remote arbitrary-file-write
  primitive; hashing closes it.
- **A self-owned journal.** `recover()` replays the log at bind and **rejects any record not authored by
  the daemon's own key** (`ForeignAuthor`). The on-disk log is a self-owned journal, not a federation
  inbox: peer entries never arrive as foreign records replayed at bind — they arrive only through
  `PushEntries`, verified and **re-signed under the local identity** on ingest.
- **Bounded by default, like the in-memory registry.** The durable store refuses new
  `(RealmId, artifact_hash)` keys past `DEFAULT_MAX_BESTIARY_ENTRIES` and rejects an artifact above the
  128 MiB ceiling, with `0` the explicit unbounded opt-out (`with_max_entries` / `with_max_artifact_bytes`);
  `recover()` replays an existing catalogue even above the current cap. The JSONL journal itself is
  capped per record before append, compaction rewrite, and recovery line allocation; the advisory
  `.head` tip hint is also read under a small cap and ignored if malformed; artifacts live in blobs,
  never in log lines. The legacy `ListEntries` full-artifact anti-entropy reply is also capped by
  total artifact bytes before the store reads/clones blobs into the snapshot. A `PushEntries` batch is
  count-capped before the daemon iterates entries or calls the store; `0` in daemon config is the
  explicit unbounded opt-out. A publish past the entry cap is a wire-honest error (not a false
  `Published`); a federation `PushEntries` of a *new* key into a full catalogue is skipped
  (best-effort lattice merge) rather than failing the whole batch.
  Quarantine markers use the same shared shape caps, and the durable store refuses a sticky
  attesting-peer union that would grow beyond the peer cap.
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
- **AI-curated.** An injected `Curator` decides `Keep` / `Promote` / `Demote` / `Quarantine` / `Gc`
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
  matching `EmbodimentOffer`s, capped to the shared placement answer limit. It shape-checks direct
  Queries against the same requirement/outcome bounds the distributor uses before parsing predicates.
  It does not introspect the kernel, does not rank, does not time out.

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

**A failed consult is structured.** When every advertiser answers empty (or there are none, or an
abort steer arrives), the distributor emits a `NoProviderReply` to the Intent's `reply_to` with a
tagged reason — never a panic, never a silent drop. A distinct schema (`distributor.no_provider`)
from the SEER topic lets an orchestrator bind the consult-reply path separately from the Intent-reply
path.

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
four things, and admission gates them all:

1. **Cross-Realm routing.** An `Omega { realm, target: Creature(m) }` envelope resolves `realm → peer`
   and re-routes `Node(peer, m)`, preserving `reply_to` / `corr` / `schema` / `payload` /
   `commitment` byte-for-byte — the same composition-by-depth as the realm gateway. An unmapped Realm
   or non-creature target yields a structured `omega.no_route` reply.
2. **Pull-based anti-entropy.** A `PullFrom` control op sends `RegistryOp::ListEntries` to a peer's
   registry and merges the returned catalog into the *local* registry through the existing
   `PublishInRealm` write path. The merge is **pinned to the requested Realm**, not the Realm a peer
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
   junk attestations is observable; oversized delta identity fields are dropped as malformed without
   echoing attacker-sized audit strings.
4. **Cross-Realm quarantine.** A `FederateQuarantine` op ships a `QuarantineNotice` to a peer
   federator, which writes a reversible `MarkQuarantine` into its local registry. The federation
   carries the *path*; what triggers a notice and how a Sanctum reacts is the immune-response
   creature's call, gated by an injected trust model (a peer cannot quarantine your creatures unless
   you trust it). Outbound, inbound, and pulled quarantine notices are shape-checked before the
   federator ships or forwards them.

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
| **order / sequence** | who acted first; causality | `seq` / `causal`, the hash-chained journal |
| **weight** | how much a party counts | reputation earned over history (the registry slot) |
| **consensus** | what we agree is true | the SEER `consensus` topic |
| **permission** | who authorized; is it them | `sig` — provenance + signature |
| **history** | the honest record of before | the registry lineage + the journal |
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
   replies with the commitment **also in the reply envelope's `commitment` slot** — so a relay or the
   journal carries it without parsing the body. The seed stays hidden; the commitment binds it to
   `(round, n)`.
2. **Reveal.** The requester supplies a `nonce`, chosen *without* knowing the seed. The die discloses
   the seed; the result is `pick = sha256(seed ‖ nonce) mod n`.

Anyone — the requester, a skeptical peer, an auditor reading the journal — calls `verify_roll` with
the commitment, the revealed seed, and the nonce: it recomputes `sha256(round ‖ n ‖ seed)`, confirms
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
