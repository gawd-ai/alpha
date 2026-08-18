# Security Policy

## Project maturity — read this first

Alpha is a **pre-1.0 research substrate** at walking-skeleton maturity. It is built around a
deliberate, explicit security model (below), but it has **not** been through an external audit and
is **not** hardened for hostile production deployment. Treat it accordingly:

- Run **untrusted or foreign code only in a sandboxed tier**: `beast` (WASM) when you need byte-exact
  memory limits, or `critter` (script) when Rhai's structural memory caps are enough. The substrate
  can verify and policy-gate a native artifact, but native is not a sandbox; do not configure policy
  to admit foreign native artifacts unless you are willing to trust them as host code.
- The native `daemon` tier is **trusted-by-admission**: in-process native code cannot be fully
  contained, so you load only native creatures you vouch for. This is a stated limit, not a bug.
- The `critter` (script) tier is a **sandboxed Rhai interpreter**: contained by
  construction (no filesystem/network/script-visible clock/rand; one capability-gated outward
  `emit`) and metered by a per-envelope **operation budget** (`cpu_ms`) plus an optional live
  progress-hook deadline (`wall_ms`). Its bounded JSON, Function-proof, and instance-local memory
  helpers add no ambient authority. One honest limit: `mem_bytes` is **best-effort** (Rhai structural
  caps fixed at load), not the byte-exact memory limiter the `beast` tier has — a critter that must be
  memory-capped exactly should run as a beast.

## Live-model acceptance and retained evidence

The v0.5.0 `dialogue --live` path is a release-acceptance harness, not a hardened agent
service. The authoritative product ceremony is the protected
[`v0.5 live acceptance`](.github/workflows/v05-live-acceptance.yml) workflow after successful push CI
for the exact candidate SHA; a local run is exploratory unless it reproduces every protected control
in the [release checklist](RELEASE.md#additional-v050-live-acceptance-gate). Treat provider
endpoints, prompts/completions, API keys, evidence, packaging keys, and the operator seal key as
sensitive:

- **Use HTTPS or exact loopback, with no URL credentials.** Live mode rejects non-loopback plain HTTP
  and rejects URL user-info even when no bearer key is configured. The inter-Realm demo transport is
  mutually authenticated but not encrypted, so its prompt-carrying TCP topology is intentionally
  loopback. Authentication alone is not prompt confidentiality.
- **Keep credentials out of evidence.** Prefer each role's `_API_KEY_FILE` over an inline environment
  value and protect it according to the provider's policy. Evidence retains only the configured
  normalized endpoint origin, requested/reported model labels, bounded prompts/completions, usage,
  and receipt metadata; path/query/fragment and API credentials are never serialized. Inspect
  retained prompts/completions before sharing them: absence of API keys does not make their content
  non-sensitive. The protected workflow does not reference or materialize provider/operator secrets
  until the exact binary has built and been copied outside the checkout; it then uses private `0600`
  files and disables shell tracing for the live step.
- **Provider receipts are claims by the endpoint.** Response/request IDs, reported model, finish
  reason, token usage, and `store_requested=false` improve traceability. They are not cryptographic
  proof of the provider, model weights, training data, or inference process. The stock adapter asks
  the provider not to store the call, but enforcement remains provider-side.
- **The evidence directory is private and create-new.** Live mode requires an absolute new path
  outside the worktree, refuses symlinks/reuse, writes private files, hashes every payload into an
  index, and re-verifies that index. Preserve the complete directory with its sibling seal; copying
  only a summary discards the audit chain. Store or transmit the bundle through an access-controlled
  or encrypted channel appropriate to its prompt content.
- **Verify from retained bytes, not the successful process's claim.** The standalone
  `dialogue verify-live` command takes the operator-pinned seal public key, exact candidate SHA,
  packaged dialogue binary, evidence directory, signed seal, and every prior accepted semantic
  digest. It runs offline from providers, Git, mutable stores, running Sanctums, and private keys. It
  verifies the sealed file set, source/binary identity, seven calls and exact replay, four signed
  causal turns, novelty and approved IR, three sources/manifests/artifacts/Bestiary proofs, six signed
  Job bundles, all result/summary hash links, and the three requested-model labels it reports from the
  sealed calls. Supplying the seal's self-declared key—or trusting only the configured model
  variables instead of that verified report—is not sufficient.
- **A valid signature is not authorization.** The external seal binds the evidence-index root to the
  public key corresponding to the supplied operator seed. The seed must be an absolute canonical
  non-symlink file, contain exactly 32 bytes as 64 hex characters, and be mode `0600` or stricter.
  Keep it separate from provider keys and the worktree. The demo verifies the signature, but release
  policy must independently decide that the recorded public key is an authorized attester; a
  self-chosen signing key is not automatically trusted.
- **Commit/binary provenance is bounded.** A qualifying live binary embeds the explicitly supplied
  `ALPHA_DIALOGUE_BUILD_COMMIT`, refuses a clean runtime HEAD mismatch, and records its own SHA-256
  and toolchain in the sealed summary. Retain those exact bytes. This detects substitution relative
  to the release ceremony. The protected workflow also requests GitHub artifact attestations for the
  copied binary and both output packages. Those attestations bind workflow provenance to exact
  subjects; they complement the Ed25519 evidence seal and offline verifier, but are not a
  reproducible-build proof and do not attest provider/model weights.
- **Plaintext raw evidence never leaves the private runner area.** The workflow packages complete
  prompts/completions and evidence only into an OpenPGP-encrypted raw archive. Its separate
  disclosure-safe pack is allowlisted to the exact binary, index, signed seal, acceptance manifest,
  verifier report, and hashes. GitHub's 90-day Actions artifacts are temporary staging, not durable
  release evidence. Before tagging, move the ciphertext, safe pack, attestations, and run metadata to
  an access-controlled immutable store retained for the supported release lifetime, checking every
  digest in transit. Never upload the plaintext raw archive.
- **Novelty state is external and append-only.** A protected JSON registry supplies every previously
  accepted semantic digest to both generation and offline verification. Append the newly verified
  digest and its exact commit/run/index/binary/package/retention references only after acceptance;
  never edit the proven source commit to record it before tagging.
- **Trusted lowering limits executable authority.** The accepted v0.5 profile lets live models return
  only strict source-free `affine_i32_v1` decisions and implementation records. Host code validates
  the complete finite truth table and renders audited Rust, no-import WAT, and Rhai templates. This
  is constrained typed synthesis, not arbitrary-code generation or general agency. The resulting
  daemon is still native, in-process, and trusted-by-admission even though its source came from a
  trusted renderer; signatures and evidence do not sandbox it.

The credential-free `--fixture` run and recorded replay are regression tools only. They do not prove
that a live model participated and cannot satisfy the v0.5 product gate. See
[TRD-007](docs/trd/TRD-007-cross-mesh-model-collaboration.md) and [the release checklist](RELEASE.md).

## The control plane (HTTP/WS + MCP surfaces)

`alpha node` can expose an HTTP + WebSocket control plane (`--listen`, the loadable `surface-http`
creature), and `alpha mcp` runs the MCP control-hub; both drive the node's `Role::CONTROL` over the bus.
The Ω server `omega serve` exposes the **same** `--listen` control plane with the **same** auth posture
(off by default, one Bearer key, the off-by-default `--allow-ai` gate) — everything below applies to it
equally, except that `omega serve` has no authoring organ, so its surface cannot author (it can still
hot-load and drive). This surface **can author and hot-load native code**, so treat it as privileged:

- **Off by default.** No API exists unless you pass `--listen <addr>` (which has no default). Bind a
  **localhost** address (e.g. `127.0.0.1:7777`) to keep it host-local; exposing it beyond the host
  means binding a routable address explicitly or fronting it with a reverse proxy — there is **no TLS
  termination in `alpha node`** (a reverse proxy's job).
- **Bearer auth, constant-time compare.** One key, from `--api-key` / `SANCTUM_API_KEY` /
  auto-generated + printed once at boot. There is **no per-identity or per-role auth** — one key, one
  trust level. Only `GET /api/health` is unauthenticated; `/api/ws` uses `?token=` because browser
  WebSocket upgrades cannot set `Authorization`.
- **Allow-AI gate, off by default.** A remote front-end (MCP/HTTP) cannot run a *mutating* verb until
  a human grants it at the local REPL (`allow-ai on`) or at boot (`--allow-ai`). Read-only HTTP verbs
  still require the Bearer key; read-only MCP tools require access to the spawned hub and, in remote
  mode, its mesh identity. Neither read path is blocked by the allow-AI gate; the local REPL is never
  gated; the gate is node-level, not per-creature.
- **Bus replies are request-bound.** `corr` is predictable correlation, not authentication. HTTP and
  MCP attach a fresh 256-bit OS-random reply capability to each `control_verb`; `ControlCore` echoes
  it through the existing envelope `commitment`, including across authenticated transport, and the
  surface accepts a `control_result` only on the exact `(corr, capability)` pair. A local creature
  cannot complete another caller's pending surface request merely by guessing its correlation id.
  This is an anti-spoof bearer challenge within trusted authenticated Realm relays, not end-to-end
  responder authentication against a relay that can read the capability.
- **Internal control replies are not reused across worker jobs.** The persistent orchestration worker
  carries one monotone internal `corr` cursor across queued verbs; a timeout does not reset it, and
  exhaustion fails closed permanently instead of wrapping. A late inner Function/Job reply therefore
  cannot satisfy the next worker job by colliding with a fresh per-command context.
- **DEV posture is disclosed, not assumed away.** The boot banner, the MCP `serverInfo`/instructions,
  and this file all state that the bundled dev policy admits everything. A non-clustered local-dev
  Sanctum uses a stub bus signer; a clustered node, remote MCP hub, or Omega gateway signs with the
  same real ed25519 identity its transport authenticates. Verified node attribution does not turn the
  permissive dev admission policy into a hardened multi-tenant deployment.

## Opt-in Function/Job state and private reads

Typed Functions and durable Jobs are a v0.4.4 opt-in composition. Ordinary `alpha node`
and `omega serve` bind none of their roles. `alpha node --functions <config>` accepts public Home
authority proof plus paths to separately protected operational seed files; it has no Abode-root-key
field and refuses root/operational key reuse, signer mismatches, weak Unix permissions, corrupt store
recovery, and node/config mismatch.

Before opening any operational seed or Function store, the composition canonicalizes its private
state directory and takes a nonblocking exclusive advisory lock on a protected inode for the process
lifetime. That prevents two local runtimes from accidentally writing the exact same tree. It is not a
distributed lease: copying the directory creates another inode, so root/HSM/quorum custody and signed
Home epochs remain the non-equivocation boundary.

Job `get` and `events` are private proof-bearing reads, distinct from the control-result bearer
challenge above. An authorized caller signs the Job handle plus a nonce; an admitted relay signs that
complete request and exact Aether return route. The Home requires the live `reply_to` to match and
signs the snapshot/page over the canonical hash of the complete relay record; Omni verifies both
signatures and that exact response/request binding. This prevents route substitution and response
reuse for another nonce or route. Relay admission is still injected trust, and a relay authorized to
perform the read can observe the returned state; this is not end-to-end encryption from that relay.

Attempt recovery addresses the current executor role after its numeric CreatureId changes, while a
stable-executor-signed dispatch binds a typed call to that current route and exact target. Across a
node boundary, this is an explicitly exposed `NodeRole`: only the boot-attested transport resolves it
after authenticating the peer, and the executor must still prove the receipt-pinned stable key and
deployment. TRD-006's real-process proof runs two child PIDs over that TCP/Omega path, loads and
independently measures the signed checked-in typed critter through `Kernel::load`, durably registers
it, and recovers a changed-id executor. A separate blocking daemon parent supplies authenticated
progress and the exact `TooLate` Steer result; its progress anchors the typed-critter causal child.
Fenced Home movement verifies the signed lease, real GX frames retry one dropped and one corrupted
chunk as an exact in-memory gap set, and a hard restart of both processes recovers the foreign
terminal facts without another invocation. The complementary in-process custody proof verifies the
optional root-declared KMS rewrap chain; the process harness deliberately uses the legacy no-rewrap
branch. This is not a claim of crash-resume inside an unfinished GX transfer, nor of ambient
remote-role trust: hard cuts occur at durable boundaries and the application proofs remain mandatory.

## Cross-node origin & relay integrity (clustered nodes)

A clustered node (`alpha node --cluster-listen`, or any `omega serve` gateway) authenticates every peer
link with an ed25519 handshake and verifies each inbound frame's signature against the
connection-authenticated key. Two properties are deliberately specified, not silently assumed:

- **Origin verdicts are published, not enforced (ADR-0041).** For every inbound frame the transport
  computes an `OriginVerdict` (`Verified` / `BadSig` / `Unresolved`) and **publishes** it on
  `PROPRIOCEPTION` — it does **not** drop a `BadSig` frame. Peer eviction is an injected topic-consumer
  decision, keeping the kernel model-free (R5/R6). **Consequence:** a clustered node with no such
  consumer admits forged-signature frames to inboxes. Subscribe the reference `policy-origin`
  creature (`cosmos/creatures/prototypes/policies/policy-origin`) to `PROPRIOCEPTION`, or inject an
  equivalent policy, as the recommended clustered baseline. `immune-response` is a different loop:
  it quarantines watched local artifacts and does not consume `OriginVerdict`. The stock clustered
  compositions install neither policy by default and print a one-line origin-defense warning — heed
  it.
- **Origin is hop-by-hop; end-to-end agent identity is application-signed (ADR-0038).** The transport
  `Origin` attributes the *immediate authenticated peer* and does **not** survive a relay. A component
  that needs to prove *which agent* produced a multi-hop reply (cross-Realm dialogue) signs the message
  body itself (the SEER `dialogue` answer carries optional `signer_pubkey` + `signature` over
  `(corr, prompt, reply)`), and the relay/requester verifies that — authenticity becomes a property of
  the message, not the transport path.
- **The replay guard is session-scoped, not cross-session (ADR-0040).** The per-`(peer, sender)` `seq`
  high-water mark prevents replay *within* an authenticated link session and is reset by a fresh
  handshake (so a legitimately restarted `seq` stream is not mistaken for a replay). The bus does **not**
  promise exactly-once delivery across reconnects — a peer that crashes and reconnects can re-present a
  previous-session frame. Components needing exactly-once dedup at the application layer on `corr` (the
  SEER/dialogue reduction theorem already keys on `corr`).

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

Only the latest minor release receives security fixes while the project is pre-1.0.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately by email to **hello@gawd.ai**. Include:

- a description of the issue and the component (`aether`, `sanctum`, `anima`, a transport or
  registry creature, …);
- steps to reproduce, ideally a minimal test or envelope/manifest that triggers it;
- the impact you believe it has against the model below.

You can expect an acknowledgement within a few days. Coordinated disclosure is appreciated — we will
work with you on a fix and a disclosure timeline before any public write-up.

## The security model (what counts as a vulnerability)

Alpha's substrate "takes no side among the players" — it does not adjudicate whether creatures lie,
collude, or act at random; that is left to selection (the immune loop). **But the board must not be
flippable.** Two bounds are mandatory and always-on:

- **The fabric-integrity floor (R9).** No creature may crash, hang, OOM, deadlock, or corrupt the
  kernel, the bus, or another creature's isolation *through the fabric's own surfaces*. Enforced by
  construction: bounded inboxes with backpressure, no-trust parsing of every envelope/manifest
  (malformed input errors, never panics the kernel), and creature-fault isolation (a panic in
  `handle` is caught at the boundary and routed to that creature's unload, never fatal to the node).
- **The life-safety floor.** The substrate must not be hostile to human/earthly life.

A reproducible way to make the **kernel or bus** panic, hang, leak unboundedly, or violate another
creature's isolation from *within the fabric's surfaces* (a crafted envelope, manifest, or a
sandboxed beast escaping its limits) is a **vulnerability** — report it.

What is **out of scope** (by design, not by oversight):
- A native `daemon` doing harm — native is trusted-by-admission (see above).
- Creatures deceiving or out-competing each other at the application level — that is the arms race
  the immune and selection loops exist for, not a fabric flaw.

The model is specified in the design notes: the capability & sandbox model in
[the substrate note](docs/design/substrate.md), and the proof-of-trust primitives and
taking-no-side stance in [the addressing, placement & federation note](docs/design/addressing-placement-federation.md).
