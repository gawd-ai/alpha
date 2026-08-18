# Demos

Runnable, narrated Alpha walkthroughs of the GAWD substrate against **live kernels** — the
substrate's most striking properties, out of `#[test]` and into your terminal. Each demo drives only
the public APIs an operator would use; there is no demo-only back door into the kernel, and each one
rides code paths the integration tests prove.

`alpha demo list` is the authoritative registry — every demo below appears there. Single-process
demos launch with `alpha demo run <name>`; the multi-process **cluster** runbook is listed tagged
`(manual runbook)` and `alpha demo run cluster` prints its step sequence rather than launching it.

| Demo | Run | What it shows | Proven in |
|---|---|---|---|
| [**walkthrough**](walkthrough/) | `cargo run -p walkthrough` | **One node's loop.** A deterministic reference authoring agent turns an English request into a creature → compiles → ed25519-signs → admits → hot-loads → runs it (native *and* critter tiers), then a running self performs a signed **two-body hand-off inside one Sanctum**. The separate integration proof covers the cross-Sanctum transport variant. | `m3_authoring_loop.rs`, `critter_examples.rs`, `abode_migrate_local.rs`, `abode_migrate_cross_node.rs` |
| [**federation**](federation/) | `cargo run -p federation` | **Many nodes, many Realms.** Several Sanctums across 2–3 Realms wired over real ed25519-authenticated TCP (loopback): a within-Realm cross-node fetch, then cross-Realm pull anti-entropy, **signed reputation**, **quarantine** propagation, and **Omega-addressed routing** (Loop 5, Acculturate). | `omega_federation_cross_node.rs`, `m2_two_node.rs`, `distributor_cross_node.rs` |
| [**dialogue**](dialogue/) | `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo run --locked -p dialogue -- --fixture` | **Regression for the v0.5 live composition.** Three scripted, signing role models exercise four strict causal decisions, host validation/trusted lowering of one bounded affine IR into all tiers, durable publication, and six local/cross-Realm Jobs. This default run is hermetic regression only, not product acceptance; an exploratory local `--live` command and the authoritative protected release gate are below. | `dialogue` CI regression, `agent_mind_authoring_loop.rs`, `build-beast/src/lib.rs`, `anima/src/wasm.rs`, `function_jobs{,_cross_realm}.rs` |
| [**distribute**](distribute/) | `cargo run -p distribute` | **Cross-node artifact transfer.** Two Sanctums over ed25519-authenticated TCP (loopback): A publishes a creature; B performs a loss-free pull in **bounded GX chunks**, then admits + runs it with one `registry fetch-load` command. Per-chunk and whole-file SHA-256 integrity, missing-chunk retry, and tamper refusal are separately pinned by tests. | `m2_two_node.rs`, `fetch_load_verb.rs`, `gawdxfer/src/tests.rs`, `function_jobs_cross_realm_process.rs` |
| [**bestiary-live**](bestiary-live/) | `alpha demo run bestiary-live` | **A real model into a durable Bestiary.** A live LLM authors a sandboxed critter with bounded compile-error retry; Alpha signs, hot-loads, runs, and publishes it using the safe deterministic curator. The demo verifies an `EntryProof`, replays the signed journal through a fresh store handle, and exercises store-level monotonic convergence. Cross-node `PushEntries` replication and optional AI curation are separate injectable/tested seams. **Opt-in / key-gated; the runner enables `openai`.** | `agent_mind_authoring_loop.rs`, `bestiary_durable_local.rs`, `bestiary_replication_cross_node.rs` |
| [**cluster**](cluster/) | `cd demos/cluster && ./00-build.sh && ./01-boot.sh …` | **Three real Sanctum processes across both poles** (the deployable thing, not one process): node A an **`omega serve`** server, B/C **`alpha node`** operators. They form a **dynamic many-to-many mesh** from one seed via gossip, then **cross-execute** over it (author on an α operator, run from the Ω server) and prove a pre-admitted remote MCP hub can read B's live graph — all through fail-closed shell + HTTP + MCP steps. | `cluster_gossip_mesh.rs`, `omega_serve_federation.rs`, `m2_two_node.rs` |

## Notes

- **walkthrough** is the fastest way to "get" Alpha's slice of the GAWD substrate. Its deterministic
  reference authoring step shells out to a real `cargo build`, so the *first* run is slow (a minute or two while the dependency
  cache warms); later runs finish in seconds. It is gated in CI so it can never silently rot.
- **federation** is configurable: `cargo run -p federation -- --realms 3 --sanctums 2`
  (each bounded to `1..=3`, default `2 2`, so the loopback mesh stays reliable). With one Realm or one
  Sanctum it gracefully narrates what to add to see the next layer. Set **`ALPHA_DURABLE_BESTIARY=1`**
  to run the whole scenario on the on-disk `bestiary-daemon` instead of the in-memory stub — the
  fastest way to watch federation drive a *durable* registry (hermetic, no model needed). These are
  minimal demo Sanctums rather than full `alpha node` / `omega serve` compositions; each Realm
  gateway binds its `omega-federator` through `omega::serve::boot_federator`, the same organ recipe
  the server uses.
- **dialogue** has two intentionally different postures. Default/`--fixture` uses three strict
  scripted `mind::Model`s to regression-test the entire mechanism and exact replay without provider
  credentials. It can never satisfy v0.5 product acceptance. `--live` uses distinct Builder,
  Reviewer, and Contract Tester Model injections for seven calls: the Builder drafts and finally
  approves; Reviewer materially narrows both input bounds; Contract Tester selects the actual ordered
  boundary/interior cases; then the same Builder confirms one digest-bound implementation record for
  daemon, beast, and critter. Every decision is strict JSON, unknown-field rejecting, bounded, hashed,
  and causally linked. The admitted program is exactly a finite-domain `affine_i32_v1` transform.
  Models never supply Rust, WAT, Rhai, dependencies, or authority in this path: host validation
  recomputes the exhaustive truth table and trusted templates lower it into all three backends before
  the builders sign it. This is constrained typed synthesis, not arbitrary-code generation or
  general agency.

  The authoritative v0.5 product gate is the protected exact-SHA workflow in
  [`RELEASE.md`](../RELEASE.md#additional-v050-live-acceptance-gate), not a local command. For an
  exploratory retained run, start from a clean exact Git commit and use three absolute paths outside
  the worktree: `EVIDENCE_DIR` must be a new path whose existing parent is trusted,
  `EVIDENCE_SIGNING_KEY_FILE` must be a canonical, non-symlink regular file containing exactly one
  32-byte Ed25519 seed as 64 hexadecimal characters with mode `0600` or stricter, and
  `PACKAGED_DIALOGUE_BIN` must not exist. Configure each role's required `_MODEL` and provider
  credential, independently pin the authorized signer public key, then run:

  ```sh
  export ALPHA_DIALOGUE_BUILDER_MODEL="provider-model-id"
  export ALPHA_DIALOGUE_REVIEWER_MODEL="provider-model-id"
  export ALPHA_DIALOGUE_CONTRACT_TESTER_MODEL="provider-model-id"
  EVIDENCE_DIR=/absolute/new/alpha-v05-evidence
  EVIDENCE_SIGNING_KEY_FILE=/absolute/private/operator-evidence-seed.hex
  PACKAGED_DIALOGUE_BIN=/absolute/private/dialogue-candidate
  EXPECTED_EVIDENCE_SIGNER=0123456789abcdef... # exact authorized 64-hex public key
  release_commit="$(git rev-parse HEAD)"
  test -z "$(git status --porcelain=v1 --untracked-files=normal)"
  allowed="$(taskset -pc $$ | sed 's/^.*: //')"
  ALPHA_RELEASE_CPU="${allowed%%[-,]*}"
  test -n "$ALPHA_RELEASE_CPU"
  taskset --cpu-list "$ALPHA_RELEASE_CPU" true

  test ! -e "$EVIDENCE_DIR"
  test -f "$EVIDENCE_SIGNING_KEY_FILE"
  test ! -e "$PACKAGED_DIALOGUE_BIN"

  ALPHA_DIALOGUE_BUILD_COMMIT="$release_commit" \
    CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
    taskset --cpu-list "$ALPHA_RELEASE_CPU" nice -n 10 \
    timeout --signal=TERM --kill-after=30s 900s \
    cargo build --locked -p dialogue --features openai

  DIALOGUE_BIN="$(git rev-parse --show-toplevel)/target/debug/dialogue"
  install -m 0500 "$DIALOGUE_BIN" "$PACKAGED_DIALOGUE_BIN"
  set --
  # For each prior accepted digest, add:
  # set -- "$@" --forbid-semantic 0123456789abcdef...<64 lowercase hex total>
  taskset --cpu-list "$ALPHA_RELEASE_CPU" nice -n 10 \
    timeout --signal=TERM --kill-after=30s 1800s \
    "$PACKAGED_DIALOGUE_BIN" \
      --live \
      --evidence-dir "$EVIDENCE_DIR" \
      --evidence-signing-key-file "$EVIDENCE_SIGNING_KEY_FILE" \
      "$@"

  INDEX_SHA256="$(sha256sum "$EVIDENCE_DIR/evidence-index.v1.json" | awk '{print $1}')"
  SEAL_FILE="$(dirname "$EVIDENCE_DIR")/evidence-seal-${INDEX_SHA256}.v1.json"
  "$PACKAGED_DIALOGUE_BIN" verify-live \
    --expected-seal-signer "$EXPECTED_EVIDENCE_SIGNER" \
    --candidate-sha "$release_commit" \
    --packaged-binary "$PACKAGED_DIALOGUE_BIN" \
    --evidence-dir "$EVIDENCE_DIR" \
    --signed-seal "$SEAL_FILE" \
    "$@"
  ```

  Confirm no other compiler is using this checkout before the build. A one-off self-chosen key is not
  release authority unless a separate operator ceremony authorizes its public key. Repeat
  `--forbid-semantic` for every digest in the operator's external append-only prior-live semantic
  registry; omit it only when that registry is empty. The fixture semantic digest is always rejected.
  `verify-live` runs from the exact copied candidate bytes and independently pins the candidate SHA,
  authorized signer, signed seal, evidence directory, and the same prior semantics. It performs no
  provider calls and consults no Git, running Sanctum, mutable Bestiary, or private key.
  `ALPHA_DIALOGUE_BUILD_COMMIT` is captured at compile time, and live preflight requires it to equal
  the clean runtime HEAD. The sealed summary also hashes the running binary; retaining that exact
  binary lets the external acceptance record bind the embedded commit and observed bytes. This is
  provenance evidence, not a reproducible-build proof.
  For each `ALPHA_DIALOGUE_{BUILDER,REVIEWER,CONTRACT_TESTER}` prefix, `_BASE_URL` defaults to exact
  loopback `http://localhost:11434/v1`, `_TIMEOUT_SECS` defaults to 60 and is restricted to `1..=120`,
  and `_API_KEY_FILE` takes precedence over `_API_KEY`. Live evidence accepts HTTPS origins or exact
  loopback HTTP only and rejects URL user-info. The registry entry stays feature-lean, so
  `alpha demo run dialogue --live` is not a substitute for the explicit OpenAI-feature command.

  On success the new private directory retains sanitized endpoint origins (never keys), exact prompts
  and completions, provider-reported response/request IDs and model/finish metadata, replay records,
  four signed Dialogue turns, all decisions, trusted-lowered sources, signed manifests/artifacts,
  Bestiary proofs, and six per-Job bundles. Each Job bundle retains the caller-signed submission,
  Home-signed `Submitted`/`DispatchGranted`/terminal events and terminal snapshot, full contiguous
  event log, signed execution grant, exact `FunctionCall` with executor-signed route, deployment
  receipt, and terminal execution receipt. A result record hashes all six bundles and the final run
  summary anchors that record alongside exact commit/binary/toolchain identity. This proves the
  signed intended Home/deployment topology and one-attempt history, not packet-level traversal. A verified
  `evidence-index.v1.json` hashes every payload; a create-new `evidence-seal-<digest>.v1.json` sibling
  binds that root to the operator key. Provider receipts improve traceability but do not prove which
  weights produced a completion; trust in the seal signer is operator policy. Retain the directory
  and sibling seal together. A release-qualifying ceremony uses the protected workflow's
  build-before-secret boundary, encrypts the raw prompt-bearing bundle before upload, produces a
  disclosure-safe pack, and attests the exact binary and both staged packages. Before tagging, the
  release operator must move those 90-day Actions objects into immutable supported-lifetime storage
  and append the result/new semantic to an external signed acceptance registry. GitHub attestations
  complement the verifier and seal; they do
  not prove provider weights or reproducible compilation. Editing TRD-007 before tagging would change
  the proven commit; link that external record only in a later post-tag documentation commit. TCP
  authenticates peers but does not encrypt prompt content, so the demo's inter-Realm mesh remains
  loopback.

  Both modes use two in-process Kernel nodes, not three deployed processes. They preserve pairwise
  Dialogue rather than adding broadcast/group chat, arbitrary-N orchestration, quorum/consensus, or a
  durable group transcript. One native build runs in the bounded shared authoring cache;
  beast/critter builds invoke no Cargo and neither Job world rebuilds.
  Keep the dedicated authoring cache between runs to avoid recompiling dependencies. If its disk must
  be reclaimed, first confirm no authoring build is active, then clean only that cache with
  `cargo clean --target-dir target/gawd-build-cache`.
- **distribute** is hermetic (no model, no network beyond loopback): it boots two real Sanctums and
  shows the loss-free `registry fetch-load` path pulling an artifact cross-node in bounded, windowed
  GX chunks and verifying per-chunk/whole-file GX integrity before admission. Missing-chunk
  re-request and tamper refusal are protocol
  guarantees exercised by the cited contract/process tests, not faults injected by this narrated run.
- **bestiary-live** is **opt-in and key-gated**: it needs a model and the `openai` feature. Set
  `ALPHA_LLM_MODEL` (and `ALPHA_LLM_BASE_URL` / `ALPHA_LLM_API_KEY`, or point at a local Ollama /
  LM-Studio) and run `cargo run -p bestiary-live --features openai`. With `ALPHA_LLM_MODEL` unset it
  prints a hint and exits 0, so CI never makes a network call. `ALPHA_LLM_MAX_ATTEMPTS` (default 3)
  is restricted to `1..=5`; `ALPHA_LLM_TIMEOUT_SECS` (default 60) is restricted to `1..=90`.
- **cluster** is the real-deployment shape: separate Sanctum *processes* across both poles — node A an
  `omega serve` server (the mesh anchor + an idle federator, since the cluster is single-Realm), B/C
  `alpha node` operators — that you drive by hand (or across real machines via `*_HOST` env vars — see
  [`cluster/env.sh`](cluster/env.sh)). Authoring is the α seat, so creatures are authored on B/C and run
  from anywhere, including A. Each step is a numbered `.sh` you run yourself; node logs, PID records,
  and public keys land in `cluster/run/`. Nodes boot `--allow-ai` (headless, so a curl/MCP caller is
  the operator) — on a node you sit at, keep the gate off and use the REPL.

For driving a *single* live node interactively — boot `alpha node`, author live, watch the sense-tape,
then scale up to these demos — see the [operator quickstart](../docs/quickstart/operator.md). To write
your own creature, see the per-tier [quickstarts](../docs/quickstart/).
