# TRD-006 — Typed functions, durable jobs, and portable home custody

- **Status:** Met (v0.4.4)
- **Theme:** Function execution foundation
- **Spawns:** [ADR-0046](../adr/ADR-0046-functions-are-typed-creature-entrypoints.md),
  [ADR-0047](../adr/ADR-0047-jobs-have-home-and-execution-ledgers.md),
  [ADR-0048](../adr/ADR-0048-home-authority-moves-by-fenced-handoff.md)
- **Invariants in play:** one loadable unit; explicit immutable identity; fabric, not model;
  proof before authority; bounded and fail-closed durability.

## Scope

v0.4.4 adds the reusable mechanism an AI needs to deploy and call a named, typed capability without
turning Alpha into a fixed scheduler or workflow product. A **Function** is a signed entrypoint of a
creature. A **Job** is the asynchronous, durable record of one submitted invocation. The creature
remains the only artifact Alpha loads, admits, contains, distributes, and unloads.

The exact cross-system wire lives in `foundation/gawdfn`. That placement is intentional: Alpha
consumes the contract, but another GAWD system can use the same identifiers, receipts, and schemas
verbatim. Runtime organs and policies remain Alpha creatures under `cosmos/creatures/`.

This TRD specifies the foundation and its reference composition. It does **not** prescribe a queueing
algorithm, workflow language, retry backoff, placement model, trust root, or blob-store product. Those
are injected creatures and policies.

## Required vocabulary and ownership

| Term | Required meaning | Owner |
|---|---|---|
| `FunctionId` | Immutable `{ manifest_content_address, entrypoint }` identity | `gawdfn` contract |
| `FunctionAlias` | Friendly mutable name; never canonical identity | resolver filling |
| deployment | Explicitly loaded Function plus a signed deployment receipt | control/deployment mechanism |
| Job | Durable asynchronous invocation rooted at a `HomeId` | function home |
| attempt | One execution authorization for a Job | home grants; executor claims |
| home ledger | Canonical job graph, commands, and verified observations | one active Abode home |
| execution journal | Durable claim/dedup and signed facts for attempts at one executor | execution Realm |
| policy | Placement, retry cadence, retention, workflow, trust, or steering choice | injected creature/model |

The two ledgers are complementary, not replicas. The home alone authors job intent and control; the
executor alone proves what it claimed and ran. A home event may preserve a foreign executor receipt
verbatim, but may not replace its provenance with a local assertion.

## Requirements

- **R1 — A Function is a typed creature entrypoint, never a fourth tier.** `sigil::Entrypoint` MUST
  gain an additive, optional `gawdfn::EntrypointContractV1`; the legacy `signature: String` remains.
  Invocation MUST ride an ordinary `Envelope` to the creature's existing `handle` boundary. No
  `Address::Function`, engine ABI, or `gawd_creature_v1` change is permitted.
- **R2 — Canonical identity is immutable and alias resolution is pinned.** `FunctionId` MUST be the
  manifest content address plus entrypoint. The byte artifact hash remains a separate deployment
  fact because the Bestiary fetches bytes by artifact hash. A Job submitted by alias MUST durably
  record the exact `ResolvedFunctionV1` / deployment receipt before dispatch; later alias changes
  MUST NOT alter the Job.
- **R3 — Deployment is explicit and precedes invocation.** Deploy MUST fetch or accept a signed
  manifest + artifact, validate content-address self-consistency and the named contract, admit/load
  through the existing Kernel path, then durably register a `DeploymentReceiptV1`. Call MUST refuse
  an unresolved or inactive deployment; it MUST NOT hide fetch/load/placement inside invocation.
  Explicit undeploy MUST durably tombstone at the stable receipt-pinned executor identity before any
  Kernel unload. Its acknowledgement MUST be signed by that stable executor key and bind the
  current authenticated executor role route, so recovery may change a process-local CreatureId
  without weakening continuity. Control MUST unload only when the currently loaded numeric target
  still has the receipt's exact manifest content address and the independently measured hash of the
  bytes actually loaded. A refusal, timeout, unauthenticated or wrong acknowledgement, absent target,
  reused numeric id, or bounded unload failure MUST be reported
  honestly without touching a different live identity.
- **R4 — Acceptance is asynchronous and durable.** Submit MUST return a `JobHandleV1` after the input
  reference and `JobSubmitted` record are durable, never after the function finishes. `get` and
  `events` MUST recover status/result/progress after process restart. A private read MUST carry a
  caller-signed handle/nonce inside an admitted relay signature binding one exact Aether return route;
  the Home MUST compare the live reply route and sign its response over the complete relay-record hash,
  and a surface MUST verify that exact request/response binding. A Frozen Home or a Home whose durable
  prefix is uncertain MUST refuse Job writes, duplicate Submit/control/receipt fast paths, recovery,
  and reads rather than sign from stale Job state; proof-bearing custody reconciliation remains a
  separate fenced path. Router journals, `corr`, and the Omni worker queue are not job storage.
- **R5 — Delivery semantics are caller-selected and truthfully named.** `DeliveryModeV1` MUST include
  at-most-once and at-least-once. At-most-once durably grants one attempt; an ambiguous crash becomes
  `Indeterminate`, never an automatic second execution. At-least-once MAY create
  attributable repeated runs/attempts until a signed terminal receipt, cancellation, or bounded retry
  policy stops it. On executor reopen, a `Claimed`-only attempt MAY cross `Started` and make its first
  call; any already-`Started` nonterminal attempt MUST become an ambiguity terminal even when controls
  were queued. Neither mode may be described as exactly-once.
- **R6 — Attempt claims are durable and idempotent.** An executor MUST compare-and-set claim
  `(JobId, AttemptId, request_hash)` before calling code. Same identity + same digest returns the
  existing claim/result; same identity + different digest is a conflict. Corrupt or unverifiable
  recovery, including an uncertain post-fsync append, MUST fail closed rather than serve an empty or
  stale journal.
- **R7 — Causal child Jobs are explicit ledger edges.** A child MUST record root Job, parent Job,
  parent attempt, stable spawn id, and parent-event hash. `(parent, attempt, spawn_id)` replay MUST
  resolve to one child or a digest conflict. `Envelope.header.causal` and `corr` MUST NOT substitute
  for this application identity. The mechanism records lineage; a function/orchestrator creature
  decides whether to join, detach, compensate, cancel, or steer children.
- **R8 — Progress and steer are durable, bounded, and honest.** Progress MUST carry Job/attempt and
  monotone event identity before it is projected live. Steer/cancel MUST have a stable command id and
  a durable `issued` record containing the exact signed caller and selected attempt before delivery.
  Executor persistence before send MUST be described as queued intent, and an unacknowledged exact
  `(AttemptId, ControlId)` intent and queued fact MUST remain recoverable across Home and executor
  restart; delivery replay additionally requires a proven-live target incarnation and a nonterminal
  attempt. A terminal target reply closes command replay and MUST distinguish `applied`, `rejected`,
  `unsupported`, and `too_late`. A Home acceptance reply MUST bind the canonical hash of the complete
  caller-signed command to the exact signed durable event, and a surface MUST verify its
  command-specific event shape. After an already-`Started` attempt becomes terminal during reopen, a
  queued command MUST NOT be forwarded to a new target incarnation and MUST remain bounded audit
  evidence with capacity for a genuine late acknowledgement; the executor MUST NOT invent a target
  disposition from silence.
  Generic `handle` is synchronous, so non-cooperative functions MUST NOT claim hard preemption. SEER
  may carry a live projection, but is not the source of truth.
- **R9 — The Job home is an Abode facet with exclusive write authority.** The canonical home ledger
  MUST move with a stable `HomeId`; running execution does not generically migrate. Active attempts
  remain at their executors and reconcile by signed receipt after the home moves. A generic Abode CRDT
  MUST NOT LWW-merge competing job grants into apparent safety.
- **R10 — Home handoff is epoch-fenced and crash-safe.** Source MUST durably freeze at a signed
  prepared tip before a destination may activate. Destination MUST durably install the checkpoint,
  required blob envelopes, authority grant, and first next-epoch activation record before replying.
  Silence MUST NOT thaw the source. Home callback routes MUST carry a durable monotone sequence within
  an epoch. An executor MUST persist a higher queried `(epoch, route_sequence)` before sending future
  nonterminal receipts to that route and MUST reject rollback or same-sequence divergence. A stale
  epoch or route MUST be rejected by homes, executors, and locators; an uncertain locator MUST return
  unavailability rather than cached authority.
- **R11 — Signing authority and data custody are separate.** The Abode root signing key anchors
  `HomeId` and monotone epoch grants and MUST NOT ride inside a checkpoint. A destination-local epoch
  signer authors operational records under `CustodyGrantV1`. Application data-encryption keys are a
  third concern: never derive them from or wrap them with the root signing key. Ledger records bind
  ciphertext/content hashes and sealing-envelope hashes. When—and only when—the root grant declares
  exact source and destination recipient bindings, the source Prepared proof MUST commit a bounded,
  canonical inventory of every unique sealed value addressed to that Home. The destination epoch key
  MUST sign an exact request for that inventory; an injected KMS/enclave MUST return complete
  destination-wrap coverage under the destination binding's separate proof key, and Staged MUST
  persist that verified aggregate receipt before activation. An absent declaration MUST preserve the
  legacy no-rewrap wire and MUST NOT imply destination decryption authority.
- **R12 — Cross-Realm lifecycle proof is application-signed.** Deployment, grant, activation,
  progress, command, and terminal receipts MUST bind Realm, node/executor, immutable function,
  request/result hashes, Job/attempt, and relevant epoch. Foreign receipts remain embedded verbatim.
  Transport `Origin` is useful hop evidence, not end-to-end Job authority.
- **R13 — Every retained surface is bounded.** Inputs, results, event records, event count, attempts,
  child fan-out, progress history, commands, aliases, deployments, Jobs, checkpoints, and blob bytes
  MUST have a default cap and a defined refusal/compaction behavior. Any `0 = unbounded` escape hatch
  follows [ADR-0042](../adr/ADR-0042-escape-hatch-policy.md).
  The v1 reference caps progress+checkpoint observations at 256 per Attempt independently in Home and
  executor, caps unique controls at 256 per Job/Home and Attempt/executor, preserves terminal/ack
  capacity with dynamic recovered reservations for every nonterminal Job/attempt and unacknowledged
  control, preserves the mandatory tail of each custody phase, paginates signed events by encoded
  bytes, and reserves 64 KiB of the 1 MiB private-read wire ceiling for the route-bound proof and
  surface wrapper around either a snapshot or page. Route advancement always requires a durable
  append; an exhausted journal retains its reserved terminal/ack facts but returns `Capacity` until
  reopened with sufficient finite capacity. Reopen MUST reject a reduced configured cap that no
  longer contains the recovered safety reservations.
- **R14 — Mechanism and policy stay separate.** `function-home`, `function-executor`,
  `function-resolver`, and `function-locator` are role mechanisms; blob availability/checkpoint
  storage is an injected adapter mechanism. Selection, retry
  cadence, priority, retention, trust, migration destination, child orchestration, and interpretation
  of progress/steer are replaceable policy creatures; `policy-job-basic` is a reference, not
  kernel behavior.
- **R15 — Every external surface preserves async semantics.** REPL, MCP, and HTTP MUST expose the same
  eight operations—resolve, deploy, deployments, undeploy, submit, get, events, and control—with the
  same gating. Control carries steer, cancel, and access changes. Submit returns a handle; no surface
  holds the single control worker until terminal completion. Streaming is an optional projection over
  durable `events`, never the only way to recover progress.

## Contract and socket register

`foundation/gawdfn` owns the versioned schema names:

- `gawd.function.deploy.v1`
- `gawd.function.job.v1`
- `gawd.function.execute.v1`
- `gawd.function.call.v1`
- `gawd.function.home.v1`
- `gawd.function.locate.v1`
- `gawd.function.policy.v1`
- `gawd.function.custody.rewrap.v1` (nested signed request/receipt domain inside the Home protocol)

It also owns the role strings `function-home`, `function-executor`, `function-resolver`,
`function-locator`, and `function-policy`. Contract-owned constants prevent each organ from
inventing a near-match. `BlobAvailability` and `CheckpointBlobStore` are direct storage injection
seams; v1 does not reserve a role that has no application message schema.

Reference Alpha fillings are `function-home`, `function-executor`, `function-locator`,
`function-resolver`, `job-blob-fs`, and `policy-job-basic`. Alternative AIs may author and bind role
fillings or inject different storage implementations without changing the wire or kernel.

## Required state transitions

The contract MUST preserve at least these distinctions; implementations may expose more detail:

```text
Job:      queued -> blocked | dispatching -> running -> succeeded | failed
                                   |              |
                                   +-> retry_pending (at-least-once only)
                                   +-> indeterminate (at-most-once ambiguity)
          cancel_requested is an orthogonal flag; confirmed stop -> cancelled

Attempt:  granted -> claimed (durable) -> running -> succeeded | failed | indeterminate

Home:     active(e) -> prepared/frozen(e) -> retired(e)
                                      destination: installing -> active(e+1)
```

Progress and steer are events, not secret state transitions. A terminal record never reopens; late
receipts remain attributable audit evidence.

Home and executor recovery MUST be finite and bounded per Outcome. The reference organs capture one
durable high-water sweep, emit no more than 64 work dispatches per batch, and continue only through an
origin-less self-poke whose exact sender and recipient are the organ's current local `CreatureId`.
Each captured item is visited once; this mechanism does not silently create an infinite retry policy.

## Acceptance

Release acceptance requires every proof below. These bullets define the target bar; the following
status table records what the current tree actually proves.

- Manifest fixtures prove a missing optional entrypoint contract serializes exactly as v0.4.3, and a
  present contract changes the manifest content address/signature as intended.
- Local tests prove explicit deploy then alias-pinned submit, durable acceptance, typed input/output,
  progress, steer outcome, causal child dedup, terminal result, and restart recovery.
- Delivery tests prove duplicate request handling, body conflict, at-most-once ambiguity without a
  second run, and attributable at-least-once repetition.
- Store tests crash/reopen at every append/checkpoint/activation boundary and reject corrupt chain,
  wrong key, stale epoch, oversized record, and missing required ciphertext/key envelope.
- A real two-Realm mesh test deploys in one Realm, submits from another, observes progress/child work,
  migrates the home while execution remains remote, follows the signed location/epoch, and verifies a
  terminal foreign receipt after both processes restart.
- Surface-parity tests pin the exact REPL/MCP/HTTP operation set and gating. No tool or route waits for
  terminal execution on the control worker.

### Current proof status

Every acceptance bullet is Green in the current tree. The result is **suite-compositional**: no single
test is claimed to prove every requirement, and the real-process row below names the separate-process
evidence that completes the same-process, store, delivery, deployment, and surface proofs.

| Acceptance item | Status | Evidence |
|---|---|---|
| Manifest compatibility | ✅ Green | `sigil` pins byte-identical legacy entrypoints and proves a structured contract changes signed identity. |
| Local composed lifecycle | ✅ Green | `cosmos/sanctum/tests/function_jobs.rs` proves alias pinning, durable Accepted-before-call, typed result, terminal provenance, duplicate submit, and Home/executor restart recovery on a real Kernel; it also loses a durable first grant, deliberately occupies the receipt's stale executor id with another creature, recovers the stable executor at a different id, and proves the Home's exact grant replay reaches the current role while the typed target accepts only its stable-key-signed/current-route `ExecutorDispatchV1`. Its target is the checked-in `typed-add-one` Rhai artifact loaded through `Kernel::load` and the real `ScriptEngine`, not an in-process test creature. `function_job_behaviors.rs` adds target-authenticated progress, exact Home-endorsed steer with an `Applied` outcome, and an atomically accepted/deduplicated child that inherits its root and is dispatched to success, all through real Kernel organs. The dedicated `cosmos/omni/tests/function_deploy.rs` suite supplies the complete R3 deployment-retirement proof: explicit load/register plus rollback and indeterminate registration, stable executor-signed/current-route-bound undeploy acknowledgement, tombstone-before-unload ordering, refusal/ambiguity retention, exact manifest/actual-artifact liveness, stale numeric-id safety, and honest bounded-unload orphan reporting. Executor recovery tests prove a durable tombstone can be re-attested under a new process-local route without changing its stable key. |
| Delivery semantics | ✅ Green | Home/executor tests cover same-body dedup, changed-body conflict, at-most-once recovery ambiguity without a second run, and attempt bounds. Dedicated Home/executor recovery tests supply the full R8 crash window: an exact signed control accepted and fsynced before send is recovered after Home reopen; an executor-persisted queued intent and queued receipt survive reopen; only a proven-live nonterminal incarnation may receive replay; receipt order, terminalization, and genuine late acknowledgement remain bounded and honest. Reopen tests also prove only a `Claimed`-only attempt may make its first call; an already-`Started` attempt terminalizes even with queued controls and never forwards those controls to a new incarnation. `function_job_behaviors.rs` proves an injected policy's signed retry decision advances from attributable attempt/run 1 to attempt/run 2 and preserves the second grant's terminal receipt; Accepted remains earlier than the first call. |
| Store crash/recovery matrix | ✅ Green | Filesystem-backed tests cut and reopen every low-level signed-journal append boundary (before write through post-directory-fsync), force the source fence closed on every uncertain result, and retry destination metadata, Staged-marker, installed-snapshot, staging-receipt, and every activation-append cut. They also prove stale-head repair, torn/corrupt/non-prefix/wrong-key/oversized refusal, Frozen and uncertain Home refusal across duplicate/read/recovery/checkpoint paths, executor and locator stale/uncertain fail-closed behavior, locator/blob parent-directory-fsync uncertainty, blob temp-collision preservation, missing sealed ciphertext, declared result-recipient key-wrap refusal, append-before-apply preflight with byte/tip preservation, recovery-stable observation/control caps, dynamic Home/executor terminal and control-ack reservations, custody-phase reservations, cap-reduction refusal on reopen, fail-closed full-journal route advancement, cap-aware canonical checkpoint encoding without a whole-chain clone, and byte-aware event cursors. Rewrap contract/runtime tests additionally bind the root-declared source/destination recipient identities, canonical bounded inventory, destination request, complete proof-key receipt, and inherited checkpoint overlay; unavailable, mismatched, incomplete, or wrongly signed adapters fail closed. `function_home_custody.rs` proves the exact receipt over the real Kernel bus, rejects a contract-valid but unpersisted forged Staged record, and recovers the same proof-bearing status without repeating KMS work. `function_jobs_cross_realm.rs` carries one Home-addressed sealed value and its destination wrap through authenticated migration and full Kernel/store reopen. |
| Real two-Realm migration lifecycle | ✅ Green | This row is suite-compositional. `cosmos/sanctum/tests/function_jobs_cross_realm.rs` supplies exhaustive same-process protocol assertions for proof-bound KMS rewrap, lease/locator conflict handling, Home fencing, and full-store reopen. `cosmos/sanctum/tests/function_jobs_cross_realm_process.rs` supplies the real-process conjunct on the legacy no-rewrap branch: two child PIDs communicate through boot-attested TCP and Omega across two Realms; B loads the signed checked-in `typed-add-one` Rhai artifact through `Kernel::load`, independently measures the admitted bytes, and durably registers its deployment. A hard B restart changes the executor's numeric id while the stable executor key and explicitly exposed `NodeRole` carry the original grant. A separate blocking daemon parent emits executor-authenticated progress; after signed Stage/Activate migration, the client parses the signed epoch-2 lease coordinator into the moved-Home route. A cross-Realm Steer is durably accepted and returns the parent's exact honest `TooLate` outcome. The same signed progress event anchors a deduplicated causal child whose target is the deployed typed critter and whose `{answer: 8}` terminal proof preserves root, parent, attempt, and event hash. Real GX chunk frames transfer the checkpoint and dependent blob; one dropped chunk and one corrupted chunk produce the exact in-memory missing set, which is retried before CAS commit and Stage. The tests hard-restart B to prove changed-id deployment/executor recovery, then hard-restart both A and B after durable terminal facts; the moved Home recovers the byte-identical progress, Steer outcome, causal-child terminal, and lost parent terminal without another invocation. The harness deliberately does not claim crash-resume inside an unfinished GX transfer: its faulted transfer resumes exact gaps in memory and hard cuts occur only at durable protocol boundaries. It also does not attribute parent progress or Steer handling to the typed critter, and it does not claim the process test exercises a locator. |
| Surface parity and async semantics | ✅ Green | MCP pins its exact tool/gating set and maps structured Submit proofs to the shared `Verb::JobSubmit`; HTTP pins the corresponding route set (minus watch). Omni pins the exact eight-operation Function/Job REPL set and each operation's gate posture. `alpha/tests/function_surface_async.rs` boots the real opt-in runtime with a correctly signed but deliberately unreachable executor, drives HTTP Submit under a three-second response budget, verifies the exact Home-signed `Submitted` acceptance, hard-restarts the process and reopens the signed non-terminal snapshot, then drives the same durable acceptance through the REPL `--exec` grammar. MCP and HTTP both terminate at the same capability-bound `control_verb`/`ControlCore` worker seam; `control_on_bus` proves inline and worker replies echo the one-use request capability, while `control_over_mesh` proves that binding survives authenticated transport. Thus the MCP translator has no separate execution-wait path to diverge. Forged-reply regressions prove a guessed `corr` cannot consume either surface's waiter. `cosmos/omni/tests/function_private_reads.rs` proves Omni rejects a valid Home response bound to another relay hash, while Home/gawdfn tests reject a changed live return route or nonce and byte-cap tests retain the complete two-signature proof without duplicating a near-limit page. |

The control-path proof also pins exact acceptance rather than trusting a well-shaped reply:
`foundation/gawdfn/src/tests.rs::job_control_acceptance_binds_the_exact_request_and_durable_event`
and `cosmos/omni/tests/function_private_reads.rs::omni_rejects_a_home_event_bound_to_the_wrong_control_request_hash`
cover substitution, while `cosmos/omni/tests/control_on_bus.rs::late_timed_out_reply_cannot_satisfy_the_next_worker_job`
and Omni's `correlation_cursor_exhaustion_is_permanent_and_never_wraps` cover late-reply isolation and
permanent fail-closed correlation exhaustion.

Recovery-pressure tests exceed both 64-dispatch batch limits and prove that only exact local
self-pokes drain the captured tail; a remote origin with the same numeric creature id is inert. The
executor replay is ordered by receipt sequence, including queued and acknowledged control facts,
before any reopen-synthesized ambiguity terminal.

Route-fence tests prove that genesis and moved Homes persist monotone same-epoch route revisions;
grants, queries, and control endorsements bind them; and executors reject lower or same-sequence
divergent routes across reopen. Once a higher signed query is durable, later target receipts use that
queried Home route. At the exact journal cap, a newer route fails closed with `Capacity`; the durable
receipt remains queryable after a finite cap increase and reopen, while the old durable route is never
silently superseded. The cross-Sanctum test above separately proves that the same stable executor can
reopen at a changed process-local id and still serve a Home recovery Query through its explicitly
exposed, authenticated node-scoped role.

Resolver-specific R13 coverage pins exact alias and `FunctionId` success, ambiguous/stale/unstructured
refusal, and a hard 1,024-row catalog snapshot ceiling before candidate iteration.

The opt-in Alpha composition canonicalizes its private state directory and acquires a nonblocking,
process-lifetime exclusive lock before opening any operational seed or durable Function store. The
lock prevents accidental concurrent writers to that exact local state tree; it is not a cross-host
lease or proof against a copied directory, so Home epoch/root-or-quorum authority remains the
non-equivocation boundary.

Execution now fails closed across stale deployment rows: the injected liveness mechanism compares the
currently loaded target's manifest content address and independently measured admitted-artifact hash
with the signed deployment
before first Claim and again before Started/call; lookup omits absent or identity-mismatched rows, and
a refusal is an executor-signed durable Failed receipt rather than an unattributed protocol error.
Explicit operator retirement now closes the local R3 tombstone-to-Kernel join: all surfaces require
an `UndeployRequestV1` plus the exact signed `DeploymentReceiptV1`; Omni authenticates the current
executor role origin and verifies an executor-signed `UndeployReceiptV1` whose stable key matches the
deployment and whose current CreatureId matches that responder. It then compares the currently loaded
manifest content address and independently measured artifact hash before unload. Ambiguous
outcomes retain the target, stale/reused ids are never unloaded, and a bounded teardown failure is
reported as a durable tombstone plus safe orphan. A narrower reconciliation gap remains: ordinary
generic `unload`, panic self-deregistration, or process restart does not automatically author an
executor tombstone or reload a durable deployment. The liveness filter keeps those rows inactive;
an injected supervisor/reconciler must decide retirement or redeployment policy.

## Explicit non-goals for v0.4.4

- a fourth loadable tier or direct exported-function engine ABI;
- exactly-once external side effects;
- generic checkpoint/migration of running creature execution;
- a built-in DAG/workflow language, cron, global queue, or fixed scheduler;
- dynamic per-function MCP tool export (generic fixed tools call immutable Function IDs);
- a global always-available Home locator or partition-solving consensus service;
- fork/CRDT merge of active Job-home write authority;
- pretending `registry-mem` makes deployment durable.
