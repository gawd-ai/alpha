# The distributed self and evolution

An operator spread across many Sanctums is **one self in many bodies**. The continuity that makes a
mesh act as one mind — a stable identity, the memory and goals it accumulates, the creatures acting on
its behalf — is the **Abode**. And because the substrate is built to *be* an evolutionary system
rather than merely host one, that self lives inside running loops: it **varies** (authors), it is
**selected** (rewarded), it is **defended** (the immune system), and it spends resources against a
**gradient**, not a hard bank.

Two disciplines run through everything below. **Fabric, not model:** the substrate ships the *socket*,
the *signal*, and the integrity primitives; the *judgment* — which keys to trust, what counts as fit,
which peers to honor, how to merge a state, when to grant grace — is an **injected creature** (sockets,
not strategies). And **one bus, three-job kernel:** every mechanism here is ordinary `Envelope` traffic
on the existing wire; the kernel does lifecycle + routing + admission and gains no new job for any of it.

## The Abode: a portable self

An Abode is a signed **identity** (an authorship keypair — the *self*, distinct from any Sanctum's
transport key), an addressable **state** (content-addressed, portable), and the **creatures** acting on
its behalf. It is the substrate's **ontogenetic** layer: the seat of what an operator *learns within its
lifetime* — memory, adapted models, learned defenses — as distinct from the **instinct** every node
inherits (the substrate primitives, the manifest contract, innate immunity). A learned behavior that
proves broadly fit can be **promoted** into a signed, published creature — turning learning into
heritable instinct (a deliberate Baldwin effect; see *Evolution as loops*).

The Abode **migrates** (follows the work), **forks** (acts in parallel), **merges** (reconciles
divergent forks), and **re-instantiates** after a node is lost. None of this is new machinery:
re-instantiation rides the load path, portability rides content-addressing, identity rides the keypair.
The Abode is a *composition* of existing primitives, not a new substrate.

### The snapshot and its gates

The unit that carries a self between bodies is the `AbodeSnapshot` (in `abode`):

- `abode_key` — the authorship public key, the *self*-identity.
- `state_hash` — `sha256:<hex>` over `payload_bytes`; a receiver re-derives and asserts it.
- `payload_bytes` — the portable state, **opaque to the substrate**. The snapshotting Abode chooses
  the encoding (CBOR, bincode, an LLM context dump). The fabric ships the envelope and the integrity
  hash, never a state model.
- `requires` — the `Requirements` a receiving Sanctum must satisfy for the restored self to function.
  Same shape as a creature manifest's `requirements`, so the matching language is unified across
  creature load and Abode restore; placement pairs it against a candidate body's advertised
  embodiment.
- `realm` — an optional Realm assertion, so a receiver can refuse a self from an un-peered Realm
  before doing any hash or signature work.
- `signature` — a hex ed25519 signature over the snapshot's signing payload (the struct with
  `signature` cleared), produced with the private key matching `abode_key`.

Field order is part of the signed wire format. A determinism tripwire
(`signing_payload_hash_is_locked_to_a_known_fixture`) pins the byte layout, so no later edit can
silently reorder a field and invalidate every signed snapshot in flight.

Three **substrate-shipped gates** guard every inbound snapshot, run **in order, fail-closed at the
first failure**, *before* any operator policy:

1. **size** (`assert_payload_size`) — `payload_bytes` must fit under a ceiling (default 8 MiB). The
   fabric-integrity floor: a peer cannot make a receiver admit an enormous snapshot just by knowing a
   migrator's address. Checked before any restore-into-state work.
2. **integrity** (`assert_integrity`) — `sha256(payload_bytes)` must equal `state_hash`. A bit-flipped
   snapshot dies here, before any signature work.
3. **signature** (`verify_signature`) — when signatures are required (the default), the signature must
   verify under `abode_key`. The verifier is **root-blind**: it confirms the signature is valid for
   the *declared* key; it never decides *which* keys are trusted. That decision is the injected policy's.

These three are the substrate's only judgment about a self in flight: the bytes add up, the size is
bounded, the signature verifies. Everything past them — does *this* key earn a restore on *this* body
— is operator code.

## Migration reference: acknowledged hand-off, not durable authority

The shipped portable-state reference is `abode-migrator`, bound to `Role::ABODE_MIGRATOR` (one per
Sanctum). It
speaks one wire schema (`"abode.migrator"`) carrying a `kind`-tagged message enum, and holds at most
one Abode through a three-state **in-memory** machine:

```
   Empty ──SetState / RestoreRequest{ok}──► Authoritative{payload} ──Migrate{ok}──► Migrated{to}
                                                                                     (sealed)
```

Migrator messages are bounded before JSON decode. The default cap allows one max-sized state/snapshot
payload at worst-case JSON `Vec<u8>` expansion plus metadata overhead, and `SetState` rejects local
state whose `v3.0`-wrapped snapshot would exceed this migrator's configured snapshot ceiling. The
migrator also applies field-level bounds before parking or echoing control metadata: node ids must
fit the same ASCII shape used by the transport membership gate, challenges/ed25519 witness fields
must fit their hex shapes, notes are capped, and human-readable refusal reasons are truncated before
being relayed to peers or operators.

A `Migrate { destination_node, destination_migrator }` op orchestrates the hand-off: take a snapshot →
wrap it with the migrator's own version-magic (`b"v3.0"`) → sign with the Abode key → ship a
`RestoreRequest` carrying an **unguessable per-migration challenge** → await the matching
`RestoreResponse`. On `admitted: true` the source transitions `Authoritative → Migrated { to }` and is
sealed against further mutation. This demonstrates cross-node snapshot validation and a signed
witness, but it is deliberately **not** a crash-safe single-authority protocol: state and the pending
handoff exist only in RAM; the destination installs `Authoritative` before emitting its response; and
the source seals only after receiving and verifying that response. A lost response or crash can leave
the destination active while the source still holds authoritative state. The pending flag blocks some
source mutations while the process lives, but it is neither durable nor an epoch fence.

The **responder** (the destination migrator) admits an inbound `RestoreRequest` only through, in order:

1. **serialized-message bound** — the request must fit the migrator's pre-parse cap before JSON
   decoding.
2. **fork-window** — the migrator must be `Empty`. An `Authoritative` migrator refuses and points the
   caller at the reconciler (fork/merge is a separate path, not a silent second active fork); a
   `Migrated` migrator refuses because it is sealed.
3. **substrate gates** — size → integrity → signature, the three above.
4. **schema dispatch** — `payload_bytes` must carry the `v3.0` magic; an unknown prefix is refused
   structurally (the bytes are opaque to the fabric, so the migrator owns this dispatch — a richer
   migrator using another encoding ships its own prefix and the substrate's gates are unchanged).
5. **injected `RestorePolicy`** — the operator's final say: `fn admit(&self, &AbodeSnapshot) ->
   Result<(), String>`. The substrate ships none; `policy-abode-allowlist` is the reference (admit
   when `abode_key` is on an allowlist). A bounded prefix of the reason rides in the reply so the
   originator can audit and reissue without turning policy prose into an unbounded wire field.

Matching `corr` alone never seals a migration. Transport reseals the envelope's `from` to the local
transport creature's id, so the origin node is not trustworthy there; the source instead requires the
`RestoreResponse` to echo the per-migration challenge (only a migrator that actually received the
request knows it) **and** assert in-band that it is the destination node shipped to. Either mismatch
means a misrouted or spoofed reply: the source refuses it, stays authoritative, and re-parks the
pending so a genuine later reply can still complete — a self is never lost to a spoofed ack.

The challenge echo proves *liveness* (someone received this request), but not that the responder
actually **ran the admission gates**. So a responder that admits a self also returns a **cryptographic
witness**: having passed all six gates, it signs `(source abode_key ‖ state_hash ‖ challenge ‖
responder_node ‖ responder_pubkey)` with its *own* Abode key and attaches the signature plus that
pubkey to the `RestoreResponse`. The source verifies the signature under the responder's pubkey, then
binds that pubkey to a pre-shared **trust anchor** — an `expected_responder_pubkey` pinned on the
`Migrate` op and parked alongside the pending migration. The witness is reconstructed from the source's
*own* parked state, never from the response body, so a spoofer cannot supply both the claim and its
proof. By default a signed witness is **required**: a missing witness, a signature that fails to
verify, or a pubkey that differs from the pinned anchor each keeps the source authoritative and
re-parks the pending (a builder, `with_unsigned_responder_allowed`, opts out for a legacy or lab peer).
A determinism tripwire pins the witness byte layout, so no later edit can silently invalidate
in-flight responder signatures. The honest residuals: the anchor is distributed out of band (the
operator pins the destination's key when it issues the migration), and the witness binds *identity*,
not *liveness or non-equivocation* — a destination cannot later disavow having admitted the self, but
the path does not by itself prevent a trusted destination from misbehaving after admission.

There is a second identity limitation: `AbodeSnapshot.abode_key` describes the stable self, but the
reference destination retains the key with which its migrator was constructed; restore transfers only
payload bytes. Identity continuity therefore requires both bodies to be provisioned with the same
private key out of band. Some local demos do that; the cross-node reference test intentionally permits
different keys. A durable portable home must not infer key continuity from this V1 snapshot shape.

## Durable Job homes: the stricter v0.4.4 authority protocol

A Job home uses Abode identity and portability vocabulary, but **does not reuse the current migrator
state machine**. It needs a fail-closed, fsynced, signed, hash-chained ledger and monotone authority
epochs. The implemented protocol is [`ADR-0048`](../adr/ADR-0048-home-authority-moves-by-fenced-handoff.md):

1. The source takes its exclusive write gate, materializes the checkpoint and sealed-value
   inventory, then appends and fsyncs `Frozen` with the exact grant and checkpoint. That `Frozen`
   fsync is the irreversible fence: recovery after it is frozen, never active, and silence never
   thaws it. Only after that fence succeeds does the source sign `CustodyPreparedV1` and append
   `Prepared`; if that proof append is missing, recovery remains frozen and an exact retry completes
   preparation.
2. The destination verifies the grant, ledger tip, checkpoint, all referenced content-addressed
   ciphertext, and every contract-declared inline recipient wrap; installs them durably; then appends
   and fsyncs `CustodyActivated`/`HomeActivated` before serving writes.
3. The destination returns a signed activation lease/receipt. If the acknowledgement is lost, it
   returns the same proof on replay; the source stays frozen and redirects once it has verified proof.

The Abode root authority signing key anchors `HomeId` and monotone epoch grants and stays in an
HSM/KMS/offline trusted boundary. A per-home, per-epoch destination operational signer writes the
ledger under that grant. Application sealing/DEK keys are separate: migration carries ciphertext
hashes and contract-declared recipient wraps, never root material or plaintext. v1 does not infer a
destination-local KMS/enclave rewrap merely because custody moved. When the root grant explicitly
declares signed source and destination recipient bindings, source Prepared commits the exact bounded
sealed-value inventory, the destination epoch signs its request, and Staged persists the adapter's
complete proof-key-signed receipt before activation. An omitted declaration preserves the no-rewrap
path and grants no destination decryption authority. Data custody may replicate read-only encrypted
backups; only write authority must be exclusive.

This ordering chooses safety over liveness. A signed, durably recorded refusal can permit an abort;
timeout or partition cannot. Strict non-equivocation under partition ultimately requires an injected
root/quorum/lease service that durably issues exactly one next epoch. Running attempts are not moved:
their grants cross the checkpoint and their signed results are accepted or forwarded under the new
home, while only new grants use the new epoch. Full details are in
[`functions-and-jobs.md`](functions-and-jobs.md#the-abode-home-and-custody).

## Fork and merge: a CRDT reconciler on an injected lattice

Generic snapshot hand-off covers a useful reference case. The hard case is **two bodies of the same self that both kept running
and diverged** — a healed partition, a returning offline fork, a deliberate parallel exploration that
rejoined. Reconciling them needs a **conflict-free merge** (a CRDT), and the merge semantics depend on
what the Abode's state *is* — which is opaque to the substrate. So the substrate cannot ship the merge;
it ships the socket and the verify/sign envelope, and the **lattice is injected**.

`abode-reconciler` (schema `"abode.reconciler"`, bound to `Role::ABODE_RECONCILER`) handles a
`Reconcile { fork_a, fork_b }` by:

1. **bounding the reconcile message before JSON decode**; the default cap allows two max-sized fork
   payloads at worst-case JSON `Vec<u8>` expansion plus metadata overhead. Snapshot metadata is also
   shape-capped before signature-payload construction: Abode keys, state hashes, signatures,
   requirements, and Realm assertions must fit bounded wire forms.
2. **gating both forks** through the same substrate snapshot primitives — size (a tighter per-fork
   ceiling, since a reconcile admits several forks at once), signature, integrity. A failed gate is a
   `Rejected { reason }`, never a panic.
3. **confirming same-self** — both forks carry the same `abode_key`, equal to the reconciler's own
   pubkey (it holds that self's key). Merging two *different* selves is refused; that is not a fork.
4. **unwrapping** the `v3.0` framing so the merge model sees pure state, running
   `MergeModel::merge(state_a, state_b)`, and **re-wrapping** the result.
5. **re-signing** the merged snapshot with the Abode key (carrying `requires` + `realm` forward) and
   replying `Reconciled { merged }` — a fresh authoritative snapshot that re-enters the
   migration/restore path unchanged. Because those metadata fields are outside the injected state
   lattice, the two forks must agree on `requires` and `realm`; otherwise the reconciler rejects
   instead of letting argument order choose signed metadata.

The injected lattice is `MergeModel::merge(a, b) -> Result<Vec<u8>, String>`. Its obligation, stated
in the trait docs: it **must** be commutative, associative, and idempotent — a CRDT — or
reconciliation does not converge regardless of order or repetition. The substrate ships none;
`merge-lww-map` is the reference: an **LWW-Element-Map** over a JSON object `{key: {v, ts}}` — the
union of keys, the higher `ts` winning per key, ties broken deterministically by the serialized value
so the merge stays commutative. Its `ts` is a **logical clock** the operator advances (time is a
change of state, never a wall clock the substrate reads), and its unit tests assert the three laws
directly. Operators with other state shapes bind their own (OR-Set, RGA for collaborative text, a
bespoke join-semilattice) on the same socket.

The honest limit: convergence rests on the *injected* model actually being a CRDT, which the substrate
cannot prove for arbitrary operator code. A non-CRDT merge bound here diverges — the operator's bug,
caught by the fabric-integrity floor (no panic) but not adjudicated (no model judgment), exactly like a
hostile `FitnessScorer` or a non-commutative weigher.

This generic CRDT path must **not** reconcile an authoritative Job ledger. Two divergent
`DispatchGranted` histories may merge as data after both side effects have already happened. A Job
home fork is a safety incident: preserve the signed evidence for audit and resolve authority through a
trusted epoch-recovery policy/quorum, never LWW.

With snapshot hand-off and reconcile both shipped, Alpha demonstrates that a generic distributed
self can *move* and can *rejoin after diverging*. The stricter durable-home acceptance proof is also
Green for v0.4.4 through the Function/Job suite; it remains a distinct protocol and is not a property
retroactively attributed to `abode-migrator`.

## Evolution as loops

The substrate is designed to be an evolutionary system — *mechanisms proven by nature are tested and
true*, and an open, adversarial substrate full of autonomous, possibly-foreign code is exactly where
evolved, decentralized defenses thrive and static engineered ones age badly. Evolution adds no new
primitive; it is what the core ones *do* at scale:

| Force | Mechanism | Realized as |
|---|---|---|
| **variation** | AI self-authoring; forking / recombining creatures | the authoring loop |
| **selection** | proprioception scores fitness; the fit are promoted | `fitness-selector` |
| **heredity** | provenance + content-addressing — a creature's genome | the registry (the Bestiary / gene pool) |
| **propagation** | transport + registry — gene flow | the federation loop |
| **defense** | self/non-self, anomaly sensing, herd rejection | `immune-response` |

### Variation — authoring

Variation is **authoring**: an AI brings a new creature into being, or forks and recombines existing
ones. A behavior is often born a *critter* (variation is cheapest there), promoted to a *beast* once it
proves fit and needs to travel, hardened into a *daemon* if it becomes trusted core — the maturation
ladder *is* the learning→instinct ratchet.

### Selection — signed promotion on an injected criterion

`fitness-selector` (bound to `Role::FITNESS_SELECTOR`, one per Sanctum) turns a sensed signal into a
durable judgment. The kernel emits a per-handle fitness signal on the `FITNESS` topic; the selector
holds a **watch map** (`CreatureId → (realm, artifact_hash)` — the operator's resolution, not a kernel
field, since the kernel is model-free and names only an id) and a per-creature `Observations` tally
(`handled`, `ok`, latency). On a `Tick` it evaluates each watched creature with observations:

- `score = scorer.score(&obs)` via an **injected** `FitnessScorer { fn score(&self, &Observations) ->
  f32 }`. The criterion is the operator's — success rate, latency, cost, a peer percentile, an LLM
  judge. The substrate ships none; references are `scorer-success-rate`, `scorer-latency`,
  `scorer-roundrobin`. A **non-finite** score is dropped before it reaches the registry (the scorer is
  untrusted operator code).
- if the score is finite and `>= threshold`, the selector **signs the promotion claim** — the
  `(artifact_hash, realm, score, attesting_realm)` tuple — with the Abode key and writes
  `RegistryOp::AttestFitness { …, signed_by, signature }` onto the registry's reputation slot.

Selector control messages are capped before JSON decode. The watch map and observation tally are
bounded by default (`DEFAULT_MAX_WATCHED_MODULES`, `DEFAULT_MAX_OBSERVED_MODULES`). At capacity, a new
watch is refused and a new creature id's observation is dropped while already-tracked ids keep
updating; `with_max_watched_modules(0)` / `with_max_obs(0)` are the explicit opt-outs for unbounded
replay or lab workloads. Registry fillings also shape-check reputation signal metadata before
retention: artifact hashes, Realm labels, provenance labels, and promotion signature fields are
bounded and NUL-free, and half-signed promotion markers are refused.

That signature **is heredity made checkable** — the Baldwin effect made concrete. A bare score is an
*assertion* anyone who can write the registry could fabricate; a *signed* promotion is a verifiable
fact. The shared payload shape and verify live in the registry (the mechanism), so signer and verifier
commit to identical bytes; binding `artifact_hash` + `realm` stops a signature being replayed onto
another entry. *Which key to trust* stays the policy's — the registry owns the payload shape, never the
trust root. An admission policy, `policy-prefer-promoted`, admits a creature only when its entry carries
a verified at-threshold promotion, and can be bound with a retained allowlist of trusted selector
Abode keys for production trust roots; its default constructor remains the historical lab posture that
accepts any valid promotion signer. Bind `AllowAll` instead and the same un-promoted manifest admits.
**Selection pressure is a policy choice, not a substrate gate.**

A selector **must not subscribe to `FITNESS`**: the kernel emits a fitness event after *every* handle,
including the selector's own, so a drain-thread consumer would feed on its own events — a 1-in-1-out
livelock. The selector is fed instead by a **passive relay** (a bare endpoint with no drain thread, so
it generates no fitness of its own) that re-addresses only *watched* events to the selector; the
selector additionally drops any event for its own id. Selection deliberately **only promotes** — it
never evicts, quarantines, or retires. Retiring the unfit is *defense*, a different signal on a
different role, so a slow creature is never mistaken for a hostile one.

### Diversity — anti-monoculture

Order with no disorder is brittle: a monoculture is one exploit from extinction. So the substrate keeps
**many implementations behind one interface** and varied builds — n-version polymorphism, the way
nature resists a pathogen. The capability layer admits *multiple satisfying implementations* rather than
pinning one; the registry is a gene pool, not a static index. Some efficiency is traded for diversity
and redundancy **on purpose** — that cost *is* the resilience.

### The immune system — reversible quarantine with an optional inbound trust gate

`immune-response` (bound to `Role::IMMUNE_RESPONSE`, one per Sanctum) is selection's **dual**: it
*quarantines*, never promotes. It closes the three immune mappings into running code — **innate**
(self/non-self via signing at admission), **adaptive** (anomaly sensing), **herd** (mesh-wide rejection
of a known-bad lineage).

Unlike the selector, it **can** subscribe directly to its sense stream. `PROPRIOCEPTION` also carries
origin, peer, build, and maintenance observations, but `immune-response` schema-filters and consumes
only **lifecycle** (`loaded` / `unloaded` / `unload_leaked_resources`) and **budget** triggers. Those
consumed events are tied to load/unload/breach, never to a plain handle, so handling one never
produces another. The two streams are duals: per-handle `FITNESS` self-feeds (so the selector needs a
relay), while the immune consumer's lifecycle/budget inputs do not. It quarantines a *watched*
creature's artifact on three triggers:

- a `budget_signal` event with `level == "hard"` (an apoptosis-level breach);
- a `proprioception` event with `event == "unload_leaked_resources"` (a specimen left state behind);
- an injected `Report { module, reason }` op (the path a fitness-failure relay, a panic detector, or an
  external monitor uses — defense does **not** subscribe to `FITNESS`, keeping slow distinct from
  hostile).

A quarantine writes `RegistryOp::MarkQuarantine { …, attesting_peers: [self_node] }` to the local
registry; if a `PropagationConfig` is wired, the same quarantine federates outward via the federation
wire (no edit to the federator). As defense-in-depth the creature drops any event naming its own id (a
creature is never its own immune trigger; self-apoptosis on budget is the budget policy's job, a
different role). Its own control payloads are bounded before JSON decode; watch fields, quarantine
reasons, inbound notice keys, and inbound notice attesting-peer lists are shape-capped and
NUL-rejected before retention, registry writes, federation writes, or trust-model calls. The lower
registry/federator path repeats the pressure guard: shared `QuarantineNotice` caps reject oversized
or malformed keys, reasons, and peer lists before a registry filling stores the marker or a federator
forwards it.

Two receiving postures are explicit. A `QuarantineNotice` addressed to the peer
`omega-federator` is shape-checked and written directly as a reversible registry marker; that path
does **not** invoke `QuarantineTrust`. An operator that does not grant a peer that flagging power
routes the notice to `immune-response` instead. That creature honors it only if the **injected**
`QuarantineTrust { fn honors(&self, attesting_peers, realm) -> bool }` returns true, otherwise it
drops the notice. References are `policy-quarantine-trust-all` (a non-production reference) and
`policy-quarantine-trust-realm` (a per-Realm trusted set, fail-closed for unknown Realms).
**Reversible:** both paths only ever *mark* — a re-publish of the same
`(realm, artifact_hash)` clears the marker. A marker is an input to admission policy, not an unload
or execution command, and the substrate never permanently blacklists.

A quarantine marker is also just a **policy input**, not a gate. `policy-quarantine-aware` checks the
quarantine slot *first* (reject if quarantined) and only then applies the promotion gate. So an entry
that is *both* a verified promotion *and* quarantined is **refused** by quarantine-aware and **admitted**
by prefer-promoted — same bytes, same registry, opposite verdict. **Defense overrides selection** — but
only because the operator bound a policy that says so. The substrate enforces neither.

## Budget as a gradient, not a bank

A limit shaped as a quota that depletes to zero forces zero-sum thinking: every budget is a bank, and
crossing zero is the end — a creature six lines from clean apoptosis is treated like one stuck in an
infinite loop. Real systems run on *trajectories*: rates, velocities, tolerance bands. The substrate
ships the **framework** for gradient strategies and **none of the policy**.

The signal is `BudgetSignal { level, kind, vector }`:

- **`level`** — `Warn` (advisory) or `Hard` (terminal). The wasm and script engines emit `Warn` after a
  *successful* handle that crosses the operator-declared `capabilities.budget_warn_at` percent; a budget
  trap emits `Hard`.
- **`kind`** — the dimension: `Fuel` (cpu), `Memory`, `Wall` (per-envelope wall time). Wall is
  engine-enforced for **beasts** through Wasmtime epoch interruption and for **critters** through the
  Rhai deadline; the trusted native tier has no fabric-enforced wall limit.
- **`vector`** — the raw scalars (`consumed`, `limit`, `dispatches_this_envelope`, `wall_ms_elapsed`,
  `envelopes_since_load`). The fabric ships **numerator and denominator**; any tolerance / velocity /
  curve / abuse-detection model lives entirely in an injected policy. A "last 1% hides 1000% of the work"
  detector reads the vector across calls and applies its own curve — the substrate never knows the curve.

The kernel publishes this as a `budget_signal`-schema `BudgetSignalEvent` on `PROPRIOCEPTION` whenever a
handle carries one (best-effort: a failed publish never stalls the drain). The gradient flows **both
ways**: a policy's reply to a `Warn` is `KernelControl::ExtendBudget { module, fuel?, mem_bytes?, wall_ms? }`,
which lifts the live ceiling so the creature's *next* handle runs with more rope. And a creature can ask
outward for grace itself by publishing `BudgetRequest { module, …, justification }` on `PROPRIOCEPTION`
— the resource analog of an authoring query; an injected policy weighs the justification and either
grants or ignores.

`ExtendBudget` is **honored**: the wasm tier exposes live per-handle **fuel, memory, and wall**
ceilings; the script tier exposes live **operation and wall** ceilings (its memory cap is structural
and fixed at load). `anima::BudgetControl` carries the shared atomics each instance reads, seeded from
the Manifest. The kernel keys it by creature id and `Kernel::extend_budget` lifts supported dimensions
on a grant. The reference `policy-budget` (`BudgetGraceful`) is the
first real consumer: it honors a creature's *first* fuel ask per creature (one-shot, so a creature
can't loop-beg unbounded budget) and observes the rest; a `Hard` signal still becomes an apoptosis
`Unload`.
Its per-module grace/decision tables are bounded by default (`DEFAULT_MAX_TRACKED_MODULES`); a new
module at capacity cannot receive untracked grace, while a `Hard` signal still unloads because the cap
only limits retained policy state.

This is **tier-honest**. The metering tiers expose only dimensions they actually control; the native
tier — trusted by admission, with no fuel, memory, or wall metering — exposes none. A requested
dimension that a tier cannot honor returns `Unenforceable`, never a silent lie: notably, critter
memory is a load-time structural cap and cannot be live-lifted. WASM honors fuel/memory/wall lifts;
Rhai honors operation/wall lifts. The **wire is the commitment**: the framework admits gradient
strategies without baking any, and richer engine behavior lands against the unchanged shape.

Anti-IoC discipline closes it: `Warn` is fire-and-forget and **never blocks on a policy reply**. A slow
policy's grant may lose the race to the next handle and the creature traps anyway — and that is correct.
The fabric never blocks on policy; slow policy simply means less grace.
