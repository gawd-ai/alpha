# ADR-0048 — Home authority moves by fenced handoff

- **Status:** Implemented (v0.4.4)
- **Drives:** [TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md) R9–R13
- **Date:** 2026-08-16

## Context

The v0.4.3 `AbodeSnapshot` correctly defines portable, signed, hash-bound opaque state and admission
gates, but explicitly supplies neither persistence nor a checkpoint scheduler. Its reference migrator
holds payload and pending handoff in memory. More importantly, the destination marks itself
`Authoritative` before its response reaches the source; a lost response leaves the destination active
while the source's only fence is a RAM flag. That is useful handoff demonstration, not a crash-safe
write-authority protocol for durable Jobs.

Identity custody is also underspecified for a moving writer. `AbodeSnapshot.abode_key` is the stable
self, but the cross-node reference destination is constructed with a different local key and does not
receive or derive authority to sign future state as the source. Copying the root private key into every
body would make the demo continue, but creates an operational non-equivocation and secret-custody
problem.

A portable Job home therefore needs an explicit authority epoch and a fail-closed transfer ordering.
It must move *control and history*, not pretend the generic Creature ABI can checkpoint a running call.

## Decision

1. `HomeId` is anchored by an Abode root authority key. The root key stays in an HSM/KMS/offline trusted
   boundary and issues monotone `CustodyGrantV1` values; it never rides in a checkpoint.
2. Each active home uses a destination-local, per-home/per-epoch operational signer authorized by the
   grant. Ledger, lease, activation, and command records bind that grant. A root/quorum authority must
   durably remember the highest issued epoch and issue at most one next grant; freely re-delegating an
   old host key does not prevent partitioned equivocation.
3. Application data encryption is a third key domain. Data-encryption/sealing keys are never derived
   from or wrapped by the root signing key. Migration carries ciphertext/content-addressed references
   plus the contract-declared recipient key-wrap envelopes; records bind ciphertext and seal-envelope
   hashes. A destination-local KMS/enclave rewrap occurs only when the root grant explicitly carries
   distinct, root-signed source and destination recipient bindings. The source Prepared proof commits
   the bounded canonical inventory of every unique sealed value addressed to that Home. The
   destination epoch key signs an exact rewrap request; an injected adapter returns one complete
   aggregate receipt signed by the destination binding's separate proof key. Staged persists that
   receipt before activation. If the grant omits the declaration, migration infers no decryption
   authority and preserves the legacy no-rewrap path.
4. Home authority moves in this order:
   1. source takes the exclusive write gate, finishes/checkpoints the ledger, append+fsyncs its
      irreversible Frozen marker, and only then signs a self-contained `CustodyPreparedV1` over the
      exact root grant, checkpoint, log tip, and source return route;
   2. that successful fsync is the irreversible source fence: recovery is Frozen and issues no new
      submit, child, steer, cancel, or attempt grant. The resulting exact Prepared record completes
      the next epoch's `HomeAuthorityV1`; its root grant alone remains inert;
   3. GX transfers the checkpoint/log and required ciphertext/key envelopes; the already-bound
      destination Home verifies and durably stages them, then signs `CustodyStagedV1` over the exact
      Prepared/grant/checkpoint hashes and its Realm/node/coordinator;
   4. `Activate` must name that exact staging receipt. The destination append+fsyncs
      `HomeActivated(e+1, prepared_tip, ...)` as the unique continuation;
      only then may it serve writes or return a signed activation receipt;
   5. source verifies the receipt and stores a read-only redirect/retirement record. It does not append
      a competing canonical record after the prepared tip. The bound destination CreatureId
      transitions from custody-only to the active Job API and is the coordinator signed in the lease;
      after restart, a new CreatureId is fsynced and published as a coordinator-only lease revision.
5. Crash behavior is fail-closed: before Prepared fsync source may recover Active; afterward it only
   recovers Frozen. A partial destination install is inactive. After Activated fsync destination is
   Active even if its acknowledgement was lost; source queries/retries the same handoff id.
6. Silence/timeout never proves non-activation and never auto-thaws the source. Abort is safe only after
   a destination durably records a permanent signed rejection tombstone for that handoff. Permanent
   destination loss requires the trusted epoch/quorum recovery policy and is explicitly outside a
   two-node protocol.
7. `HomeLeaseV1` separates stable `(HomeId, JobId)` from mutable `HomeLocation`. A locator accepts a
   higher valid epoch and rejects stale lower epochs. In the same epoch it accepts only a strictly
   higher-sequence coordinator refresh over an otherwise identical signed lease; location, authority,
   custody/handoff, checkpoint, or time divergence is conflict. v0.4.4 callers retain the migration
   receipt/update or follow reachable signed redirects; a globally available Ω locator is future
   authority work.
8. Running execution remains where it was granted. The destination Home sends a signed recovery
   query or re-endorsed control carrying its monotone `(epoch, route_sequence)` and exact return
   location. The executor durably fences that higher route before replying; all later results,
   observations, control outcomes, and restart replays use it. If the finite journal cannot append
   the fence, it returns `Capacity` and the old durable route remains authoritative until cap growth
   and reopen. Generic running-computation migration is out of scope.
9. The active Job-home facet is single-writer and is not merged through the generic Abode CRDT/LWW
   reconciler. A detected fork may union signed evidence for audit, but authority selection requires
   the trusted epoch recovery policy.

The current v1 wire realizes sealing envelopes as bounded inline `RecipientKeyWrapV1` records and
can require wraps for an explicit `JobSpecV1.result_recipients` set. Custody rewrap is an independent,
opt-in proof chain: `CustodyRewrapRequirementV1` → source-frozen inventory commitment →
destination-signed `CustodyRewrapRequestV1` → proof-key-signed `CustodyRewrapReceiptV1` embedded in
`CustodyStagedV1`. The adapter receives no root, epoch, proof, or recipient private key from the
contract. Staging verifies exact inventory coverage and destination binding, while destination
placement by itself remains no claim that the Home can decrypt arbitrary end-to-end ciphertext.

## Consequences

- Safety is chosen over availability during an ambiguous transfer; this is the only honest outcome
  without consensus/shared leases.
- Encrypted backups may remain on the source or replicate widely because data custody is not write
  authority. Only the active epoch signer is exclusive.
- Root authority is operational infrastructure, not a secret copied into every creature or snapshot.
- Home migration can complete while remote attempts run; it does not require an impossible universal
  process checkpoint.
- A global Home locator and partition-recovery quorum remain future Ω/Realm services, with a portable
  lease/grant proof ready to index.

## Implementation sketch

- **Files:** `foundation/gawdfn` owns `HomeCheckpointV1`, `CustodyGrantV1`, `HomeLeaseV1`, canonical
  hashes/signing bytes, and `gawd.function.{home,locate}.v1`. `function-home` owns the exclusive store
  gate and handoff handlers; `function-locator` stores verified highest-epoch leases. GX moves large
  checkpoints/blobs. The existing `AbodeSnapshot` v1 stays a generic opaque-state contract; do not
  smuggle a growing ledger or root secret through `SetState`. Alpha's opt-in composition resolves its
  private state directory and holds an exclusive advisory lock on one protected lock inode for the
  process lifetime before opening keys or stores. That prevents accidental concurrent writers to the
  same local tree; it is not distributed fencing, and a copied directory has a different inode.
- **Wire-additivity:** new versioned application schemas, no mutation of the signed
  `AbodeSnapshot` v1 layout. Old nodes do not accidentally accept an authority shape they cannot
  verify. Envelope/transport relays preserve the signed application payload.
- **Test:** crash/restart at every fsync boundary; lost activation acknowledgement and idempotent status
  recovery; delayed duplicate transfer; stale/same-epoch conflicting lease; corrupted checkpoint/grant;
  missing ciphertext/key envelope; unavailable/mismatched KMS binding or incomplete receipt; a valid
  but unpersisted staging proof cannot activate; old home refuses writes; cross-Realm migration of a
  Home-addressed sealed value while a remote attempt finishes; forked grants are detected, never
  LWW-merged.

The implementation proof is suite-compositional. The in-process two-Realm harness exhaustively checks
fenced handoff, root-declared KMS rewrap, lease/locator conflicts, and full-store reopen. The separate
process harness adds two real child PIDs over boot-attested TCP/Omega, real GX chunk transfer with one
dropped and one corrupted chunk followed by exact in-memory gap retry, changed-id `NodeRole` executor
recovery, and dual hard restart. It parses the signed epoch-2 lease coordinator into the moved-Home
route, preserves blocking-parent progress and an exact cross-Realm `TooLate` Steer outcome, executes a
typed-critter causal child, and recovers the foreign terminal proof without another invocation. Hard
cuts occur at durable protocol boundaries; the suite does not claim crash-resume inside an unfinished
GX transfer, a locator lookup in the process harness, or that the typed critter emitted the parent
progress or handled its Steer.

## Related

[ADR-0038](ADR-0038-origin-stays-hop-by-hop.md) (application signatures survive relays),
[ADR-0047](ADR-0047-jobs-have-home-and-execution-ledgers.md),
[TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md),
[`distributed-self-and-evolution`](../design/distributed-self-and-evolution.md).
