# ADR-0047 — Jobs have home and execution ledgers

- **Status:** Implemented (v0.4.4)
- **Drives:** [TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md) R4–R8, R12–R15
- **Date:** 2026-08-16

## Context

An asynchronous invocation needs more than a `corr`: it must survive a reply loss, process restart,
home migration, executor restart, and transport replay while retaining causal children, progress,
commands, and a verifiable result. Existing retained surfaces do not provide that:

- `corr` matches one conversation; it is neither globally unique nor durable;
- the Router journal is a bounded in-memory observation window;
- Omni's internal worker `Job` is only one queued control verb;
- Registry/Bestiary state describes creature artifacts, not invocations;
- Abode snapshots carry opaque portable state but are not a job database;
- transport deliberately leaves cross-session exactly-once to the application.

Putting all state at the caller loses durable executor dedup. Putting it all at the executor makes a
Job's control/history stop following its Abode. Mirroring one mutable record at both creates two
authorities. The correct separation is two ledgers that own different facts.

## Decision

1. The **function home** owns the canonical Job ledger: submission, immutable deployment pin, requested
   delivery mode, attempt grants/revocations, causal graph, steer/cancel commands, and verified
   observations. Its identity is `(HomeId, JobId)` and moves with the Abode home.
2. The **function executor** owns a Realm-local execution journal: durable attempt claim/dedup, run
   state, sequenced progress, command outcome, and terminal result receipt. It signs its facts; the
   home embeds foreign receipts verbatim.
3. Submit returns `JobHandleV1` only after the input/blob reference and submission event are fsynced.
   Get/events read the durable ledger. No control call waits for terminal execution.
4. Caller-selected `DeliveryModeV1` has two truthful modes:
   - **at-most-once:** exactly one durable attempt grant. Same grant may be retransmitted only to a
     fail-closed executor that deduplicates it. Ambiguous execution becomes `Indeterminate`; it is
     never automatically re-granted.
   - **at-least-once:** retransmission of one grant is deduplicated, while a home policy may durably
     grant a later numbered `AttemptId`. Duplicated effects remain possible. Bounds/cancellation may
     stop retries.
5. No exactly-once claim is made. A transactional/idempotent external sink is outside Alpha's generic
   execution contract.
6. A causal child records root Job, parent Job, parent attempt, parent-event hash, and stable spawn id.
   The home atomically appends the edge and child submission before dispatch. Replay resolves to the
   same child or a digest conflict. Parent/child join, compensation, propagation, and workflow logic
   are creature policy.
7. Progress is a signed, sequenced executor fact appended or summarized under explicit caps. Live SEER
   and WebSocket output is a projection; durable `events(after_seq)` is the recovery API.
8. Steer and cancel are durable home commands with stable ids and expected Job version. Executors
   report `applied`, `rejected`, `unsupported`, or `too_late`. A generic synchronous `handle` cannot be
   hard-preempted; non-cooperative Functions say so. The Home's acceptance reply carries the canonical
   hash of the complete caller-signed command plus the signed durable event, and the control surface
   verifies that the event has the exact command-specific shape before reporting acceptance.
9. Private `get` / `events` are not bearer reads. The caller signs the Job handle and nonce; an
   admitted relay signs that complete request plus one exact Aether return route; the Home compares
   the live `reply_to` with the endorsement and signs its snapshot/page over the canonical hash of the
   complete relay record. A surface verifies both signatures and the exact response/request binding.
10. Progress/checkpoint observations and unique cooperative controls are finite independently of the
   general ledger cap. The v1 reference retains at most 256 observations per Attempt and 256 controls
   per Job/Home and per Attempt/executor; terminal receipts and acknowledgements of already-retained
   controls remain possible at saturation, and exact retries still deduplicate.
11. All stores fail closed on corrupt chain, unknown signing authority, digest conflict, missing required
   blob, or recovery failure. A memory filling is for tests; the durability claim requires a durable
   filling.

## Consequences

- Home migration does not lose Job identity/control, while remote executors retain enough fact to
  reconcile callbacks lost during the move.
- At-most-once has honest ambiguity instead of hidden duplicate work; at-least-once has attributable
  duplication instead of an impossible exactly-once promise.
- Two durable stores are required, but they do not replicate the same authority.
- Progress history, results, and causal graphs can grow; explicit caps/compaction and a separate blob
  store are mandatory.
- A captured authorized read request cannot redirect private state, and a captured response cannot
  satisfy another route or nonce. Relay admission remains injected trust, not a new kernel ACL.
- A policy creature may become a sophisticated AI scheduler or workflow author without changing any
  state or receipt shape.

## Implementation sketch

- **Files:** `foundation/gawdfn` owns Job/attempt/event/delivery types and canonical signing/hash
  helpers. `function-home` + its injected store own canonical state; `function-executor` + its store own
  attempt facts; `job-blob-fs` is the reference content-addressed payload filling;
  `policy-job-basic` is a bounded deterministic reference policy. Filesystem implementations copy
  Bestiary's atomic-write/hash-chain discipline, but propagate directory-fsync failures and fail closed
  rather than serving empty after corrupt recovery.
- **Wire-additivity:** all traffic uses new `gawd.function.job.v1`, `execute.v1`, and `call.v1`
  application schemas. Envelope, Registry, SEER, and creature ABI formats are unchanged. A SEER live
  projection uses existing moves and is explicitly non-authoritative.
- **Test:** restart/dedup/conflict tests; at-most crash ambiguity never executes a second run;
  at-least recovery attributes repetitions; causal spawn replay creates one child; progress survives
  restart; finite observation/control indices recover at their caps while terminal/ack capacity
  remains; steer reports unsupported/too-late honestly; command-acceptance substitutions fail;
  wrong-route private reads and response/request substitutions fail; tampered foreign receipt/result
  hash fails.

## Related

[ADR-0040](ADR-0040-replay-guard-reconnect.md) (transport replay boundary),
[ADR-0046](ADR-0046-functions-are-typed-creature-entrypoints.md),
[ADR-0048](ADR-0048-home-authority-moves-by-fenced-handoff.md),
[TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md).
