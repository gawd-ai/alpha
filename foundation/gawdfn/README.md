# gawdfn

`gawdfn` is the transport-neutral GAWD contract for typed creature entrypoints and asynchronous,
durable Jobs. It defines identities, bounded JSON/blob references, delivery semantics, signed Job
records, execution grants and receipts, and home-custody/location records. It contains mechanism,
not scheduling, trust, retry, placement, retention, or workflow policy.

The runtime still invokes a creature through its single `handle(Envelope)` boundary. These types are
versioned application payloads carried by that boundary, so daemon, beast, and critter remain equal
execution tiers and no engine ABI is added.

## Frozen seams

The eight signed application domains are
`gawd.function.{deploy,job,execute,call,home,locate,policy}.v1` plus
`gawd.function.custody.rewrap.v1`. The first seven are top-level Envelope schemas whose message
unions are exported as `FunctionDeployMessageV1`, `JobMessageV1`, `ExecuteMessageV1`,
`FunctionCallMessageV1`, `HomeMessageV1`, `LocateMessageV1`, and `PolicyMessageV1`; custody rewrap is
a nested request/receipt signature domain carried by the Home protocol, not another bus role.
`UndeployReceiptV1` separates the executor's stable signing identity from its current process-local
CreatureId: a recovered executor can re-attest an already-durable tombstone on its new route, while a
controller verifies both the original deployment key and the current authenticated responder.
`ExecutorDispatchV1` similarly binds a typed call's exact grant, attempt, deployment, current executor
CreatureId, and target under that stable executor key; adapters also compare the authenticated local
envelope `from` / `to`. `ControlAccepted` responses bind the canonical hash of the complete signed
caller command to its exact Home-signed durable event before a surface reports acceptance.

The replaceable bus roles are `function-home`, `function-executor`, `function-resolver`,
`function-locator`, and `function-policy`. Constants for every spelling live in this crate so organs
do not invent near-matching private seams. Blob storage is currently a direct injected
`BlobAvailability` / `CheckpointBlobStore` adapter, not a declared role without a wire protocol.

`HomeId` is the Abode root public key. A `HomeAuthorityV1` proves an epoch operational key descends
from that root. Epoch 1 needs the self-binding and root grant; every moved epoch also embeds the
source-signed `CustodyPreparedV1`, which exists only after the source Frozen fsync and binds the exact
handoff, destination location/key, and checkpoint. A raw next-epoch root grant is therefore inert.
`verify_execution_grant` and `verify_home_lease` validate this full chain and the outer operational
signature. Evidence references remain bounded policy inputs and cannot authorize anything on their
own. Only a higher epoch supersedes authority/location. Within one epoch, a strictly higher sequence
may refresh only the process-local coordinator while every other signed field remains identical;
all binding divergence is conflict.

Function-policy questions are themselves `SignedRecordV1` values signed by the question's
root-authorized Home epoch key. Placement and retry decisions carry the canonical hash of that
complete signed question; retry/Stop decisions additionally carry the explicit Job and failed
attempt. This makes evidence, candidate, and cross-Job changes detectable and leaves Envelope
correlation as routing metadata rather than authority. A Home still applies its injected trust model
to the decision signer and accepts only the exact outstanding question reconstructed from durable
state.

Custody is a two-proof fence: the source signs `CustodyPreparedV1` only after its Frozen marker is
fsynced, and the destination signs `CustodyStagedV1` only after the exact archive and referenced
blobs are durable. `Activate` names that exact staging receipt. `HomeCustodyStatusV1` returns the
self-contained signed proof appropriate to Active, Frozen, or Staged; hop-level Envelope identity is
never substituted for Home authority. When the root grant explicitly declares recipient-key
rotation, Prepared also commits the bounded canonical inventory of every unique Home-addressed sealed
value. The destination epoch signer binds that inventory into a `CustodyRewrapRequestV1`; an injected
KMS/enclave returns a complete proof-key-signed `CustodyRewrapReceiptV1`, and Staged persists that
exact receipt before activation. Omission preserves the legacy no-rewrap path and never implies that
the destination can decrypt end-to-end ciphertext for other principals.

Inline JSON/schema values are bounded at 64 KiB and full messages at 1 MiB. Larger or binary values
use a SHA-256 `BlobRefV1` and move through an injected blob store/GX. Input schemas use JSON Schema Draft
2020-12 and declare an object root; output and error schemas may describe any JSON value.

Private Job reads are two signatures, not bearer requests. The caller signs `JobGetV1` or the
nonce-bearing `EventQueryV1`; a trusted relay then signs that complete record together with one exact
Aether `reply_to`. The Home admits the relay through injected trust, requires the live envelope route
to equal the endorsement, and signs a response containing the canonical hash of the complete relay
record. `verify_job_snapshot_response_for` and `verify_event_page_response_for` enforce that binding
for every consumer; page verification additionally enforces the signed query's item limit, exact
post-cursor sequence, and continuation cursor.

Retained observation pressure is finite independently at both authorities: at most 256 progress plus
checkpoint receipts per Attempt at the executor and Home, and at most 256 unique cooperative controls
per Job at Home / per Attempt at the executor. Exact retries remain idempotent at the cap, and terminal
results or acknowledgements of already-retained controls do not consume another slot. Event pages
are cut by encoded bytes, not merely row count, and every signed private-read response stops 64 KiB
below the 1 MiB ceiling so the complete relay proof and control/surface wrapper remain transportable.

`SealedValueV1` keeps ciphertext content-addressed and carries a nonempty, bounded set of inline
`RecipientKeyWrapV1` envelopes. A Home need not be one of an input's recipients: callers and Functions
may use end-to-end sealing that the Home cannot decrypt. `JobSubmitV1.result_recipients` is an explicit
requirement, however, so a successful result for such a Job must be sealed and contain a wrap for every
declared recipient. A custody destination must receive a new destination-local KMS wrap only when the
root grant explicitly supplies the source and destination recipient bindings. When it does, staging
requires the exact bounded request/receipt chain described above; migration alone still grants no
decryption authority.
