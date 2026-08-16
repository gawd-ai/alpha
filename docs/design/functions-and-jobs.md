# Typed functions and durable Jobs

> **v0.4.4 architecture.** The portable contract is `foundation/gawdfn`; Alpha supplies reference
> organs that consume it. A Function does not replace a creature, and a Job does not enter the Kernel.

Functions give a stable, typed name to capabilities creatures already expose. Jobs make invocation
asynchronous, durable, steerable, causally composable, and portable with an Abode home. The design is
deliberately a **foundation**, not a scheduler product: Alpha fixes identities, custody, receipts,
state transitions, and failure truth. An AI supplies the placement, retry, workflow, trust, retention,
and steering models as creatures.

Normative requirements are in [TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md). The three
irreversible decisions are [ADR-0046](../adr/ADR-0046-functions-are-typed-creature-entrypoints.md),
[ADR-0047](../adr/ADR-0047-jobs-have-home-and-execution-ledgers.md), and
[ADR-0048](../adr/ADR-0048-home-authority-moves-by-fenced-handoff.md).

## The grains

- A **creature** is still the only loadable, admissible, distributable, containable artifact.
- A **Function** is a named, typed entrypoint in that creature's signed Manifest.
- A **deployment** says an exact Function is loaded at an executor and proves the artifact/manifest
  facts used to load it.
- An **invocation** is one submitted call.
- A **Job** is the durable asynchronous record and handle for that invocation.
- An **attempt** is one durable execution authorization under the Job.
- A **Job home** is the single active Abode-bound authority over the Job graph and commands.

These grains do not collapse into each other. Unloading a creature retires its live Functions because
lifecycle remains at creature grain. Rebinding an alias does not mutate a Function or an accepted Job.
Moving a Job home does not move generic running code.

## Composition

```text
                         artifact + signed Manifest
                                  |
                         Registry / Bestiary
                                  |
          explicit deploy         v              durable attempt facts
ControlCore ----------------> function-executor -------------------------+
                                  |                                      |
                                  | gawd.function.call.v1                 |
                                  v                                      |
                          loaded creature                                |
                          handle(Envelope)                               |
                                                                         |
caller -> function-home -> resolver / locator / function-policy          |
             |   ^                    (replaceable models)                |
             |   +-------------------------------------------------------+
             |       signed progress / command / terminal receipts
             |
             +--> Job-home ledger + injected blob filling
                    (Abode-bound; checkpoints and moves by epoch)
```

The reference organs are ordinary creatures; blob storage is a direct injected adapter:

| Role / seam | Reference filling | Mechanism it supplies |
|---|---|---|
| `function-home` | `function-home` | submit/get/events, graph, grants, commands, verified observations, handoff |
| `function-executor` | `function-executor` | deployment table, injected exact-identity liveness, claim/dedup, dispatch, signed execution/refusal facts |
| `function-resolver` | `function-resolver` | deterministic selector/metadata resolution with ambiguity refusal |
| `function-locator` | `function-locator` | verified highest-epoch Home lease; same-epoch conflict detection |
| `function-policy` | `policy-job-basic` | bounded deterministic reference selection/retry policy |
| `BlobAvailability` + `CheckpointBlobStore` | `job-blob-fs` | content-addressed, size-bounded input/result/checkpoint bytes |

The role strings and message schema strings come from `gawdfn`, not from each implementation. A
production operator may replace any filling; storage is injected into the Home because this slice
does not yet define a blob-role wire. The Kernel only routes the role-based envelopes.

### Normal boot posture and the reference opt-in

An ordinary `alpha node` deliberately leaves all Function roles unbound. The verbs still exist on
REPL/MCP/HTTP because they are stable control vocabulary, but an unconfigured Function request fails
with no provider; Alpha does not silently invent a Home, trust roots, custody, or scheduling policy.
`omega serve` remains a gateway composition and also binds no Function role.

The smallest runnable reference composition is explicit at the Alpha boundary:

```sh
alpha node --node-id op --cluster-listen 127.0.0.1:9302 \
  --functions /secure/alpha/function-runtime.json
```

`--functions` is incompatible with `--minimal`. It loads `function-{resolver,executor,locator,home}`
and `policy-job-basic`, injects `job-blob-fs`, and replaces the normal in-memory Registry binding
with a recovered, signed, filesystem Bestiary shared by the resolver. The Home, executor, blob,
locator, and catalog state all live below the configured private `state_dir`. Recovery re-presents
queued/retry-pending work to the policy socket and queries exact executors; it does not make a new
scheduling decision in the composition root. Home and executor recovery each capture one finite
durable high-water sweep and emit at most 64 work dispatches per batch. A remaining tail continues
only through a private self-addressed poke whose origin must be local and whose sender and recipient
must both equal the organ's current `CreatureId`; an authenticated remote peer that happens to reuse
that numeric id cannot drive the sweep. The continuation visits the captured tail once rather than
turning an unacknowledged item into an unbounded retry loop.

Durable receipts do not pretend that process-local code survived a restart. Kernel creature
instances are not restored from the executor ledger: stale deployment rows are excluded from
lookup and refused before dispatch unless the exact creature id, Manifest content address, and
independently measured hash of the admitted artifact bytes are live again. An operator or authorized
caller must explicitly reload and re-register the artifact; a stale numeric id is never treated as
sufficient identity.

The version-1 config is public proof plus secret *references*:

```json
{
  "version": 1,
  "state_dir": "function-state",
  "realm": "crew",
  "node": "op",
  "authority": { "abode": "<signed AbodeKeyBindingV1>", "operational": "<signed OperationalKeyGrantV1>" },
  "historical_authorities": [],
  "home_operational_key_file": "keys/home-epoch.hex",
  "resolver": { "public_key": "<resolver-public-key>", "seed_file": "keys/resolver.hex" },
  "executor": { "public_key": "<executor-public-key>", "seed_file": "keys/executor.hex" },
  "policy": { "public_key": "<policy-public-key>", "seed_file": "keys/policy.hex" },
  "deployer": { "public_key": "<deployer-public-key>", "seed_file": "keys/deployer.hex" },
  "catalog": { "public_key": "<catalog-public-key>", "seed_file": "keys/catalog.hex" }
}
```

The two `authority` values above are schematic placeholders: the actual field is the ordinary
serialized `HomeAuthorityV1` object, with its complete root-signed records. A moved epoch additionally
carries the exact source-signed Prepared proof, which the source emits only after its durable
`Frozen` fence; the root grant for a destination key is not operational authority before that proof
exists. Relative paths resolve
against the config file. Each key file contains exactly one 32-byte Ed25519 seed as 64 hex
characters, must be a regular non-symlink file, and on Unix must be mode `0600` or stricter. Every
non-Home file must derive the adjacent explicitly configured public key; the Home file must derive
the operational identity in the root-signed authority. The six operational identities must be
distinct; any one equal to the Abode root identity refuses startup. The state directory must likewise
be private (`0700` or stricter on Unix). Corrupt durable state, the wrong journal key, a key/proof
mismatch, or a config/`--node-id` mismatch is fatal.

Before Alpha opens an operational seed or any durable Function store, it fully resolves that private
directory and takes a nonblocking exclusive OS advisory lock on its protected
`.alpha-functions.lock` file. The handle stays in `FunctionRuntime` for the runtime's lifetime, so a
second process (or a second composition in one process) fails startup instead of sharing journal
writers accidentally. This is a local state-ownership guard, not a distributed non-equivocation
proof: copying the directory creates another lock inode. Abode root/HSM/KMS or quorum custody and the
external trust proofs still govern whether such a cloned state tree has authority to act.

There is intentionally no `root_key_file`. The Abode root/HSM/quorum service constructs the public
Home authority and signs `ResolveRequestV1`, `DeploymentRequestV1`, `JobSubmitV1`, Job controls, and
custody grants without exporting its key. The node holds separately custodied operational signers,
each pinned to one composition responsibility. The bounded reference pins one local Home plus exact
resolver, executor, policy, and deployer identities and deliberately treats evidence as inert.
Proof-of-trust can inform a future replacement trust/admission/delegation creature, but never becomes
authority merely by being present. To expose the opt-in node over MCP, attach a remote-profile
`alpha mcp` hub to that node's ControlCore; remote mode requires `--target`, the hub's `--node-id` and
`--listen`, and at least one `--seed`. A separate local `alpha mcp` process is a different Sanctum.

## Typed entrypoints and immutable identity

`sigil::Entrypoint` retains its human-readable/free-form `signature` and gains an optional
`gawdfn::EntrypointContractV1`. Because that contract is inside the Manifest, it participates in both
the Manifest content address and signature. Different types or behavioral declarations mean a
different signed Function, even when the artifact bytes happen to match.

Canonical identity is deliberately small:

```text
FunctionId = (manifest_content_address, entrypoint)
```

The artifact hash is not part of `FunctionId`. It names executable bytes in the Registry/Bestiary,
while the Manifest content address names the full signed definition. A deployment receipt binds both,
plus Realm, executor, deployment id, and the load/admission proof. This follows the Bestiary's existing
distinction between artifact hash and manifest hash.

A `FunctionAlias` is a convenience such as `summarize/prod`, not an identity. Resolver output is a
signed/bounded `ResolvedFunctionV1`. The home resolves an alias **once**, before accepting a Job, and
stores that resolution and `DeploymentReceiptV1` in the submission event. Later alias changes only
affect later submissions.

Explicit deployment keeps authority legible:

1. resolve/select the exact artifact and entrypoint;
2. obtain the exact Manifest/artifact source (the current verb accepts node-local paths; a Registry
   adapter may use GX before this step);
3. prepare one exact representation: beast/critter paths are opened once into bounded bytes; native
   paths stream-copy/hash into a retained stage with O(1) memory and no local-path size cap, while
   byte-backed native code keeps the ordinary 128 MiB cap;
4. recompute Manifest identity, verify signature, and admit the exact staged artifact hash before
   `NativeEngine` dlopens that same retained capability and other engines consume the prepared bytes;
5. register the loaded `CreatureId` and signed deployment facts at the executor;
6. return the durable receipt; only then can a caller submit against it.

On Linux/Android the native capability is a write/grow/shrink-sealed memfd loaded through a unique
`/proc/self/fd` spelling; other targets use a random private/read-only tempfile without claiming
same-UID immutability. Native staging deliberately changes the loaded object's pathname and ELF
`$ORIGIN` to that descriptor pseudo-directory or fallback stage. Adjacent `$ORIGIN` dependencies are
not copied; native Functions that need them must use a reviewed system/absolute loader path or link
them into the daemon. This compatibility cost is the price of making the registered artifact hash
identify the bytes actually mapped rather than a mutable source pathname.

If registration cannot become durable, deployment fails and the just-loaded instance is rolled back.
Invocation never silently performs these steps.

Explicit retirement reverses only the live half, in a proof-preserving order:

1. the caller supplies a signed `UndeployRequestV1` and the exact signed deployment receipt;
2. the stable receipt-pinned executor key refuses while a nonterminal attempt exists or durably
   appends its tombstone before signing an `UndeployReceiptV1` over the exact `DeploymentId` and its
   current process-local executor route;
3. control authenticates that current role responder, verifies the stable executor signature and
   current-route binding, and treats silence, forgery, a wrong id/key/route, or any other reply as
   indeterminate, retaining the target; a recovered executor may therefore re-attest the durable
   tombstone after its CreatureId changes without trusting the stale route in the deployment receipt;
4. only an authenticated acknowledgement permits a Kernel unload, and then only if the live numeric
   creature id still holds the receipt's manifest content address and the independently measured
   hash of the bytes actually loaded.

An already-absent target completes as tombstoned. A reused id holding different code is deliberately
left alone. A bounded teardown timeout is reported as a tombstoned safe orphan, never disguised as a
clean unload. Generic `unload`, panic, and restart remain liveness facts rather than implicit policy:
they make durable rows inactive but do not invent a tombstone or automatically reload code.

## One application wire, no new runtime ABI

The contract owns eight signed application domains:

| Schema | Purpose |
|---|---|
| `gawd.function.deploy.v1` | deployment registration/receipt, durable retirement acknowledgement, and alias binding facts |
| `gawd.function.job.v1` | submit/get/events/steer/cancel/child operations |
| `gawd.function.execute.v1` | attempt grants, claim/progress/command/terminal receipts |
| `gawd.function.call.v1` | executor-to-target typed entrypoint dispatch |
| `gawd.function.home.v1` | checkpoint, source-Prepared proof, destination-Staged receipt, exact activation, and signed status |
| `gawd.function.locate.v1` | Home lease publication and lookup |
| `gawd.function.policy.v1` | replaceable placement and retry questions/decisions |
| `gawd.function.custody.rewrap.v1` | nested destination-epoch KMS request and aggregate proof receipt for one source-frozen sealed-value inventory |

The first seven are ordinary top-level `Envelope.payload` schemas. Custody rewrap is deliberately a
nested signature domain inside `gawd.function.home.v1`: the adapter has no independently addressable
bus role. The executor sends `gawd.function.call.v1` to the concrete loaded creature; a target/Forge
adapter checks the immutable Function ID and wire bounds, then dispatches by entrypoint name inside
`handle`. Forge's typed inline decoder validates a Rust target type, while a generated adapter or the
Function itself remains responsible for evaluating its signed JSON Schema in v1—advertising a schema
is not yet a generic substrate-side JSON Schema evaluator. Native, WASM, and Rhai therefore share the
same application wire. There is no `Address::Function`, fourth engine, direct symbol call, or dynamic
MCP catalog.

`corr` remains useful for one live request/reply, but it is not `JobId`. Likewise,
`Envelope.header.causal` is not the Job graph: current creature `Dispatch` cannot set it and the bus
seals it empty. Durable IDs and event hashes live in the application record.

Policy is a proof-bound consult, not a signing oracle. The Home signs every placement/retry question
with its root-authorized current epoch key. A policy first verifies that authority chain and outer
signature, then puts the canonical hash of the **complete signed question** in its signed decision.
Retry and Stop decisions also name the exact `JobHandleV1` and failed `AttemptId`. The Home
reconstructs the outstanding signed question from its durable Job/event state and requires an exact
hash, job, and attempt match in addition to its injected policy-signer trust check. Consequently an
old decision, altered evidence/candidate set, or a Stop replayed against another Job is inert;
`corr` is only a delivery hint and never selects the Job to mutate. Proof-of-trust references may
inform a replacement policy's choice, but remain signed input data rather than protocol authority.

## Two ledgers, one authority for each fact

### Home ledger

The function home is authoritative for:

- `JobEventKindV1::Submitted` and its request/input hash;
- immutable Function/deployment resolution;
- requested delivery mode;
- causal parent/child edges;
- attempt grants/revocations;
- steer/cancel commands;
- verified executor receipts and the derived Job state;
- checkpoint tip, Home epoch, and migration records.

The ledger is a signed hash chain with a global sequence (portable checkpoint order) and per-Job
sequence (query order). Every append compares the expected tip. A record binds Home, epoch, Job,
previous hash, event, signer, and authority grant. Large values live in the injected blob filling
(`job-blob-fs` in the reference composition); the event stores their digest, size, and
sealing-envelope hash.

Private snapshot/event reads nest the caller-signed request inside a relay signature that commits to
the exact Aether return address. Relay admission is injected trust. The Home compares the live
`reply_to` with that endorsement and signs the snapshot/page together with the canonical hash of the
complete relay record; changing only the envelope route therefore yields no private state, while a
captured response cannot satisfy another route or nonce. Omni verifies and returns the signed relay
request and signed outer response proof; the snapshot/page is read from the response payload and is
not duplicated into a convenience projection that could push a bounded page over the control cap.

### Execution journal

The executor is authoritative for:

- compare-and-set claim of `(JobId, AttemptId, request_hash)`;
- durable numbered-attempt claims;
- progress sequence and checkpoint digests;
- whether a steer/cancel was applied, rejected, unsupported, or late;
- success/failure/indeterminate result and result hash.

It signs receipts under its Realm/executor identity. Home verification applies injected trust; once
accepted, the original receipt is embedded verbatim. Re-signing it locally without preserving the
foreign record would prove only that the home wrote something, not that the executor did it.

The stores are durable for different reasons: the home follows the caller's self; the executor must
remember a claim even if the caller retries after a lost response. Neither can be replaced by the
Router's bounded in-memory journal or the Bestiary artifact log.

## Submission, state, and terminal truth

Submit is a short durable operation:

1. validate sizes/types/caller grant;
2. resolve and pin the Function/deployment;
3. place the input in the blob filling if it is not inline;
4. idempotently append `JobEventKindV1::Submitted` under the caller's key + request digest;
5. fsync; return `JobHandleV1` in `queued` state.

Execution is asynchronous. The minimum visible state machine is:

```text
queued -> blocked | dispatching(attempt) -> running(attempt) -> succeeded | failed
                         |                       |
                         +-> retry_pending ------+   (at-least-once only)
                         +-> indeterminate           (at-most-once ambiguity)

cancel_requested is an orthogonal recorded flag; a confirmed stop becomes cancelled
```

`blocked` may describe a cooperative Function parked for input/children, but it is not a built-in
workflow engine. Progress and steer are events around a state, not magic state transitions. A durable
terminal result wins; duplicate or late facts remain audit records and never reopen it.

## Caller-selected delivery modes

| Mode | Durable promise | Ambiguous crash/loss | Duplicate effects |
|---|---|---|---|
| at-most-once | one attempt grant; executor claims before call | `indeterminate`; no automatic new run/grant | zero or one run; result may be unknown |
| at-least-once | retry/recovery remains authorized within explicit bounds | home may append a later numbered attempt grant | possible and attributable |

A transport replay of the same attempt is not a new execution request: the executor returns the
existing claim/result when the digest matches and rejects a mismatch. In at-least-once mode, actual
re-execution after ambiguity is recorded separately. In at-most-once mode, corrupt/missing executor
state cannot degrade to “never seen”; recovery fails closed.

Executor restart draws the crash boundary at the durable `Started` record. A `Claimed`-only attempt
has not crossed that gate and may advance once to `Started` and its first call during the finite
recovery sweep. Any nonterminal attempt whose journal already contains `Started` is terminalized on
reopen: `Indeterminate` for at-most-once, or a retryable `Failed` receipt for at-least-once so policy
may authorize a new numbered attempt. Queued controls do not weaken that rule; they prove accepted
command intent, not that the old target incarnation did or did not observe either the call or command.

At-least-once is most useful for an idempotent Function, but the caller selects the semantic. If the
signed entrypoint contract does not declare idempotent effects, a surface/policy should require an
explicit acknowledgement that duplicate effects are allowed. Alpha still does not promise
exactly-once effects: only the application and its external sink can make one transaction cover both
work and side effect.

Queue order, retry delay, retry cap, alternate placement, and which failure deserves another attempt
are models. The reference policy is deterministic and bounded; a production AI policy can be much
smarter behind the same role. Both receive only Home-signed, exact questions, so replacing the model
does not weaken the proof rail around its answer.

## Causal child Jobs without a workflow engine

A Function can propose a child through its home. The outer proposal and exact nested child
submission are signed by the same owner or delegated controller; the Abode root therefore does not
need to leave its trusted boundary or sign every spawn. The child record binds:

```text
(root_job_id, parent_job_id, parent_attempt, parent_event_hash, spawn_id)
```

The home atomically appends `ChildSpawned` and the child's submission before dispatch. Replaying a
parent attempt with the same `spawn_id` yields the same child; changing its input/deployment digest is
a conflict. Because the parent event already exists in the same ordered ledger, the graph cannot form
a backward cycle.

That is all the mechanism decides. A parent may finish while children continue, explicitly wait, cancel
descendants, compensate, or ask an AI to reconcile them. Those behaviors belong in the Function or an
orchestrator/policy creature. A child delegated to another Home is a signed cross-home link, not a
record both homes pretend to own atomically.

## Progress, steer, and cancellation

Progress is an executor event with Job, attempt, progress sequence, stage, optional fraction/note, and
signature. The home stores a bounded/sampled history and current summary. `events(after_seq)` is the
durable API; a local surface may project new events over SEER/WebSocket for immediacy.

The reference rails retain at most 256 progress/checkpoint observations per Attempt independently in
the executor and Home. Both persist count plus progress/checkpoint high-water state through replay;
the executor indexes observation sequences instead of rescanning retained receipts. Saturation refuses
another observation but reserves capacity for a terminal result. Event pagination accounts for the
encoded signed response size and returns the last included Home sequence as its continuation cursor.

Steer is a command with stable id, expected Home epoch, kind, and bounded typed or opaque payload. The
Home appends `JobEventKindV1::ControlRequested` before sending it; that durable event retains the
complete caller-signed record, attribution, and selected `AttemptId`. A recovering Home can therefore
continue the exact accepted intent after a crash between fsync and send. A Steer is refused before a
current attempt reaches `Dispatching` or `Running`; Cancel and AccessUpdate retain their independent
semantics. The executor first
records `ExecutionStageV1::ControlQueued`, an honest replayable send intent rather than a claim that a
send occurred. While the same target incarnation remains live, an exact duplicate pending command may
be re-forwarded until the target returns a durable `ControlAcknowledged`; after that an exact retry
returns the acknowledgement and never sends the command again.
The Function-side `Control` carries the original execution grant, the current Home endorsement, and a
distinct stable-executor-signed `ExecutorControlDispatchV1` binding both hashes to the current executor
and target routes. Forge verifies that full chain plus the Envelope sender and recipient before target
code sees it. `ControlResult` echoes the exact `AttemptId` + `ControlId`, which remains the target's
stable deduplication key. Before every initial or recovery forward, the executor also rechecks that the
exact registered deployment identity is live; a reused numeric target receives nothing.

If custody moves while a control is pending, the old Home-signed `ControlRequested` event remains its
immutable acceptance proof. The current root-authorized Home signs a new `ExecutionControlV1` around
that same event, the original grant hash, and its current epoch, monotone Home route sequence, and
Realm/node/coordinator route. The executor atomically persists that endorsement while advancing its
Home fence, routes queued and later terminal receipts to the newest signed route, and rejects an older
epoch, a lower same-epoch route sequence, or a same-sequence divergent route. It does not require the
current Home authority to equal the attempt's older grant authority.

Recovery replays durable receipts in per-attempt receipt-sequence order, not lexical `ControlId`
order. An executor does not forward a queued command to a fresh target incarnation after reopening a
`Started` attempt: the attempt first becomes terminal ambiguity. The queued/unacknowledged command
remains bounded audit evidence with capacity reserved for a genuine late target acknowledgement; the
executor does not synthesize `TooLate`, because the old incarnation may have applied the command before
the crash while its acknowledgement was lost. Existing SEER conventions remain useful — `abort`,
`amend`, `info` — but their meaning is still the Function's model.

Unique cooperative controls are similarly finite: 256 per Job at Home and 256 per Attempt at the
executor. An exact ControlId/body retry still resolves to its durable record at the cap, and a terminal
acknowledgement updates an already-retained control without consuming a new control slot.

Acceptance back to the caller is proof-bound too: `ControlAccepted` carries the canonical hash of the
complete signed `JobControlV1` plus the Home-signed event. Omni verifies the hash, handle, Home epoch,
and the exact expected event form (nested request, access-update hash, or causal-child fields) before
reporting success. Its persistent control worker also carries one monotone internal correlation cursor
across queued verbs; timeout never resets it, and `u64` exhaustion is a permanent fail-closed state, so
a late reply cannot become eligible for the next command merely because a short-lived context reused
its correlation.

`Creature::handle` is serial and synchronous. A one-shot target that blocks inside `handle` cannot
consume another envelope midway through that call. Genuine progress/steer therefore requires a
cooperative Function adapter that parks/resumes over envelopes or a managed worker that polls shared
state. Non-cooperative code reports `unsupported`; cancellation stops future attempts and may report
`execution_may_continue = true`. “Cancel requested” is not a fabricated proof of preemption.

## The Abode home and custody

The Job home is an **Abode facet**, not a new Kernel service. Its stable `HomeId` is rooted in Abode
authority; its mutable location and operational key advance by epoch. This is stricter than the
reference v0.4.3 in-memory handoff because Jobs make authority externally consequential.

Three key domains must not be mixed:

1. **root authority signing key** — anchors Home identity and monotone epoch grants; remains in a
   trusted HSM/KMS/offline/quorum boundary;
2. **epoch operational signer** — destination-local key authorized for one Home/epoch; signs ledger,
   command, lease, and activation facts;
3. **application data sealing keys** — encrypt Job inputs/results/checkpoints; never derived from or
   wrapped by the root signing key.

Encrypted data custody may replicate. Exclusive write authority may not.

### Fenced handoff

```text
source active(e)
    |
    | fsync Frozen; then sign Prepared(exact grant + checkpoint)
    v
source frozen(e) ---- GX checkpoint/ciphertext ----> bound destination Home (inactive)
    |                                                   |
    |                            install + fsync; sign Staged(exact Prepared/location)
    |                                                   |
    |                          Activate(exact Staged); fsync Activated(e+1)
    |                                                   v
    +<---------- signed lease + redirect -------- destination Home active(e+1)
```

The Frozen fsync precedes and authorizes the portable source-signed `CustodyPreparedV1`; that fsync
is the source fence. Every moved `HomeAuthorityV1` embeds that exact Prepared record, so a root-signed
destination operational grant/key cannot validate leases, execution grants/queries/controls, events,
or snapshots before the source fence. The proof is public and persisted at the destination; no Abode
root private key moves. `CustodyStagedV1` is signed by the root-authorized destination epoch key only
after the exact archive and every referenced blob are installed durably. `Activate` must carry that
exact staging receipt, so a raw request, a valid-but-unpersisted receipt shape, or a receipt from a
different destination cannot activate. After the fence, restart recovers Frozen and no new submission,
child, grant, steer, or cancel command is authored at epoch `e`. The destination serves writes only
after all required checkpoint bytes, ciphertext and contract-declared key envelopes, authority grant, and its first
next-epoch activation record are durable.

In v1, key wraps are bounded inline `RecipientKeyWrapV1` values inside the signed `SealedValueV1`,
not independently fetched blobs. Inputs may be end-to-end sealed for principals other than the Home;
migration therefore cannot invent a requirement that the destination decrypt them. A nonempty
`JobSpecV1.result_recipients` is an explicit declaration: a terminal success must be sealed and carry
a wrap for every named Home, and replay/staging rechecks that fact.

A root grant may separately declare a `CustodyRewrapRequirementV1` containing exact root-signed
source and destination recipient bindings. After the source Frozen fsync, Prepared commits a sorted,
bounded inventory of every unique sealed value with an effective wrap addressed to that Home. The
destination epoch key signs `CustodyRewrapRequestV1` over the exact Prepared/grant/checkpoint,
requirement, inventory hash, and count. The injected KMS/enclave sees only that public request plus
source ciphertext envelopes; it returns one destination wrap per exact inventory entry under its
dedicated proof key. `CustodyStagedV1` embeds the verified aggregate receipt, and activation requires
that exact receipt to have been durably staged. A valid receipt-shaped record that was never staged
is inert. Restart recovers the same receipt without repeating KMS work, and later checkpoints carry
the verified wrap overlay so another move can rotate from the current binding without rewriting the
immutable signed Job specification. If the grant omits the requirement, all rewrap fields remain
serde-elided and the legacy custody bytes/behavior remain unchanged; omission never implies
destination decryption authority.

The destination is bound before staging and remains the Job Home at that numeric CreatureId through
activation; the signed lease never points at `auto` or a transient transfer helper. After a process
restart changes the CreatureId, bind first fsyncs a higher-sequence coordinator-only lease revision,
then republishes it to the locator and source redirect while recovering the active Job API. Genesis
Homes use the same durable monotone route sequence even though their epoch remains 1. New grants,
queries, and control endorsements bind that sequence, so an executor can distinguish a legitimate
same-epoch route refresh from rollback or equivocation. Activation and restart also re-emit durable
placement/retry/executor reconciliation through the injected sockets.

If the activation reply is lost, the destination remains Active and the source remains Frozen; the
source queries the idempotent handoff. Silence never authorizes rollback. A safe abort requires a
durable destination rejection tombstone. If the destination is permanently lost, selecting authority
again requires the root/quorum epoch service: two hosts cannot solve partitioned non-equivocation by
locally incrementing integers.

The source may retain an encrypted, read-only checkpoint and a signed redirect. The destination
publishes a higher-epoch `HomeLeaseV1`; `function-locator` accepts a verified higher epoch, rejects
stale lower-epoch leases, and accepts a same-epoch higher sequence only when the coordinator is the
sole changed field. The same signer cannot rewrite Realm/node, authority, custody/handoff, checkpoint,
or time observations by incrementing `lease_sequence`; that divergence is conflict. Only a new
fenced, root-authorized epoch can supersede those bindings. Stable Job identity is `(HomeId, JobId)`;
location is only a refreshable hint. v0.4.4 does not claim a globally available locator when the old
Realm and caller's updated lease are both lost.

Running attempts stay at their executors. The destination or same-epoch rebound Home recovers their
attempt pins and sends signed `Query` messages through `recovery_dispatches`. For a nonterminal
attempt, the executor fsyncs the query's higher `(epoch, route_sequence)` Home fence before replying;
all later target results, observations, control outcomes, and restart replays then use that current
queried route rather than the older grant callback. A lower sequence or same-sequence divergent route
is rejected. A query or re-endorsed control never advances that callback route without a durable
fence—even for a terminal attempt. If the finite journal has no unreserved slot, the executor returns
`Capacity` while retaining the terminal/ack fact; the operator may increase the cap and reopen before
the current Home pulls it. Exact queries at the already-durable route remain idempotent. Queued work
may be re-placed by policy.
Migrating arbitrary running creature memory would require an entrypoint-specific checkpoint/resume
protocol and is not part of this system.

The generic `abode-reconciler` also does not merge active Job-home authority. A CRDT can union data,
but it cannot undo two grants that already executed. A detected fork is preserved as signed audit
evidence and resolved by trusted epoch recovery, never by a generic LWW map.

## Cross-Realm proof

Omega and transport relays may reseal the outer Envelope, so authority lives inside the application
payload. Deployment receipts, custody grants, leases, attempt grants, executor events, and terminal
receipts bind the relevant Realm/node/key, immutable Function/deployment, Job/attempt, Home epoch,
request/result digest, and prior proof hash.

`Header.origin` is useful supplemental evidence about the authenticated immediate peer, but it is not
the end-to-end caller, Home, or executor identity after arbitrary relays. Trust in receipt signers and
Realm anchors remains an injected policy.

The Omega federator forwards explicit creatures or an exact node-scoped role on a mapped Realm
gateway. A remote role is not ambient discovery: the destination composition must opt that binding in
with `Kernel::bind_remote_role`, and only the boot-attested transport may resolve it after
authenticating the immediate peer. Function Homes derive the exact node and Realm from the signed
deployment receipt; Home location still uses the signed locator protocol.

On the Home's own Sanctum, execution recovery does not reuse the deployment receipt's process-local
executor id: grants, queries, and controls go to the current `function-executor` role binding. The
recipient must still prove the receipt-pinned stable executor key and exact durable deployment, and
each typed call carries a stable-key-signed `ExecutorDispatchV1` binding the current executor route,
target, deployment, grant hash, and attempt. This makes a changed executor `CreatureId` restart-safe
without turning the role binding itself into end-to-end authority.

For an executor on another Sanctum, the Home wraps `Address::NodeRole(node,
function-executor)` in the exact Realm/Omega grain. The destination exposes only that role; transport
resolves its current binding without shedding authenticated origin evidence. The executor still must
hold the receipt-pinned stable key and exact durable deployment.

The v0.4.4 acceptance proof is suite-compositional. The exhaustive in-process two-Realm harness
occupies a stale numeric executor id, reopens the stable-key executor at a different id, and proves the
source Home's first grant crosses Omega/`NodeRole` to that incarnation; it also covers locator
conflicts, root-declared KMS rewrap, store boundaries, and full reopen. The real-process harness adds
two child PIDs over boot-attested TCP/Omega. B loads the signed checked-in `typed-add-one` Rhai source
through `Kernel::load`, independently measures the admitted artifact, and durably registers it before
the changed-id restart. A distinct blocking daemon parent emits authenticated progress and, after
release, returns the exact cross-Realm Steer disposition `TooLate`. The moved-Home client parses the
signed epoch-2 lease coordinator into its route; the same progress proof anchors one deduplicated
causal child whose deployed target is the typed critter and whose terminal result is `{answer: 8}`.
Real GX chunk frames carry the checkpoint and dependency blob, with one dropped chunk and one corrupt
chunk producing an exact in-memory gap set that is retried before CAS commit and Stage. After a hard
restart of both A and B, a role-addressed Query reconciles the original lost parent terminal and the
moved Home retains byte-identical progress, Steer, and child proofs without another invocation.

That bounded claim matters: the process test does not exercise a locator, the typed critter does not
emit the parent progress or handle its Steer, and the harness does not crash during the unfinished GX
transfer. It proves exact faulted gap retry in memory and hard process cuts at durable protocol
boundaries. Dedicated suites separately supply full R3 undeploy and R8 unacknowledged-control restart
recovery.

## Storage boundaries

- **Bestiary:** creature Manifest/artifact availability and `EntryProof`; not Job status, commands, or
  result storage. Durable deployment recovery requires a durable Bestiary filling, not `registry-mem`.
- **Home store:** canonical signed Job graph/control/observations and portable checkpoint.
- **Executor store:** durable claims and signed execution facts.
- **Job blob store:** content-addressed bounded input/result/checkpoint ciphertext. Key wraps are
  bounded inline signed fields in v1; GX moves the large ciphertext values.
- **Router journal:** bounded observability window only.

Filesystem stores copy the useful Bestiary pattern — content hashes, signed chain, temp file, file
fsync, atomic rename, directory fsync, verified recovery — but strengthen the semantics: fsync failures
propagate and corrupt authority recovery fails closed. Serving an empty store after a bad recovery would
silently invalidate at-most-once and epoch fencing.

Count caps alone are insufficient when every safety transition shares an append-only journal. The
Home therefore maintains recovered O(1) reservations for one future terminal receipt per nonterminal
Job and one acknowledgement per forwarded control; the executor does the same per nonterminal attempt
and unacknowledged control. Progress, metadata, and other nonterminal appends refuse early when they
would consume those slots. The custody journal likewise reserves the mandatory tail of each phase:
genesis or active route updates cannot consume the source `Frozen`/`Prepared` capacity, and destination
stage/receipt/activation records retain the capacity needed to reach an active fenced state.

Authority is never served from a possibly stale in-memory prefix. A post-durability append failure
makes the Home or executor inert until reopen establishes the signed disk prefix; a frozen source
rejects Job writes, exact duplicate Submit/control/receipt fast paths, recovery dispatch, checkpoints,
and private snapshots or event pages (while its proof-bearing custody status and exact handoff
reconciliation remain available). An uncertain locator lookup returns bounded unavailability rather
than its last cached lease. These fail-closed gates prevent a stale source or stale route from signing
apparently current proofs.

## What Alpha fixes and what AIs replace

| Fixed mechanism/contract | Replaceable policy/model creature |
|---|---|
| Function/deployment/Home/Job/attempt identities and hashes | alias naming and approval |
| legal state transitions and compare-tip/claim operations | queue order, priority, retry timing/budget |
| caller-selected delivery semantics | target/placement choice within those semantics |
| causal edge integrity and spawn dedup | parent/child join, workflow, compensation |
| signed progress/command/result/activation receipts | progress interpretation and steer behavior |
| epoch fencing and proof verification | migration destination, trust roots, recovery quorum |
| exact rewrap inventory/request/receipt validation | KMS/enclave implementation and key custody |
| byte/count caps and fail-closed recovery | retention/GC and blob-store implementation |

This is the line that keeps v0.4.4 Alpha rather than a fixed serverless platform: the fabric makes
work nameable, durable, movable, and provable; creatures decide what work ought to happen.

## Deliberate limits

v0.4.4 does not claim exactly-once effects, hard cancellation of arbitrary code, generic live-process
migration, active-Home fork/merge, dynamic MCP tool export, a global queue, cron, a DAG language, or a
partition-solving locator/consensus service. Each can be built as a consumer or later authority seam;
none is smuggled into the Kernel under the word “function.”
