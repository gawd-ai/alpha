# TRD-003 — App-surface coherence

- **Status:** Met (v0.4.3), extended for typed functions/jobs (v0.4.4)
- **Theme:** Convergence
- **Resolution:** [ADR-0045](../adr/ADR-0045-demo-registry-coherence.md) records the implemented
  manual-runbook registry shape for the `cluster` demo (R4/R7).
- **Invariant in play:** one verb contract, uniform across surfaces — *the system makes sense AND works.*

## Scope

Alpha exposes one control vocabulary (the [`Verb`](../../cosmos/omni/src/lib.rs) set, dispatched by
`omni::run_verb`) through three surfaces: the **REPL** (`alpha node`), the **MCP** server
(`surface-mcp`, server id `alpha-mcp`), and the **HTTP/WS** API (`surface-http`, `/api/*`). This TRD
fixes the bar that the surface is **coherent**: every verb is reachable on each surface it *should* be,
gating (allow-AI) and read-only/mutating posture are consistent across surfaces, no verb returns
stub/placeholder/canned data, the docs that describe the surface match it, and every affordance an
operator can reach is discoverable (including the *deliberate absences*). The acceptance artifact is a
**verb × surface parity matrix** that a test can pin.

## The parity matrix (built from code)

Sources: verb dispatch `omni::run_verb` + gating set `Verb::is_gated`; MCP catalog
`surface_mcp::tool_list`; HTTP routes `surface_http::router`. Gated = honors the allow-AI gate when the caller
is remote (`ctx.gated`); RO = `readOnlyHint`/never gated.

| Verb | RO/Mut | REPL | MCP tool | HTTP route | Notes |
|---|---|---|---|---|---|
| `Status` | RO | ✅ | `alpha_status` | `GET /api/status` | uniform |
| `List` | RO | ✅ | `alpha_list` | `GET /api/creatures` | **name skew**: tool `alpha_list` ↔ route `/api/creatures` (both → `Verb::List`) |
| `Journal` | RO | ✅ | `alpha_journal` | `GET /api/journal` | uniform |
| `Watch` | RO | ✅ | `alpha_watch` | **— (absent)** | REPL+MCP only; **no `/api/watch`**. Returns an intentional pointer (see R5) |
| `Cluster` | RO | ✅ | `alpha_cluster` | `GET /api/cluster` | uniform |
| `ClusterJoin` | Gated | ✅ (`cluster join`) | `alpha_cluster_connect` | `POST /api/cluster/connect` | uniform |
| `Author` | Gated | ✅ | `alpha_author` | `POST /api/author` | uniform |
| `AuthorCritter` | Gated | ✅ | `alpha_author_critter` | `POST /api/author/critter` | uniform |
| `Load` | Gated | ✅ | `alpha_load` | `POST /api/load` | uniform |
| `RegistryPublish` | Gated | ✅ | `alpha_registry_publish` | `POST /api/registry/publish` | uniform |
| `RegistryFetch` | RO | ✅ | `alpha_registry_fetch` | `GET /api/registry/fetch` | uniform |
| `RegistryList` | RO | ✅ | `alpha_registry_list` | `GET /api/registry/list` | uniform |
| `FetchLoad` | Gated | ✅ | `alpha_registry_fetch_load` | `POST /api/registry/fetch-load` | loads code → gated |
| `BestiaryProve` | RO | ✅ | `alpha_bestiary_prove` | `GET /api/bestiary/prove` | uniform |
| `FunctionResolve` | Gated | ✅ (`function resolve <json>`) | `alpha_function_resolve` | `POST /api/functions/resolve` | signed request; exact signed resolution receipt |
| `FunctionDeploy` | Gated | ✅ (`function deploy <json>`) | `alpha_function_deploy` | `POST /api/functions/deploy` | signed authorization + resolution; manifest/artifact paths are node-local |
| `FunctionUndeploy` | Gated | ✅ (`function undeploy <json>`) | `alpha_function_undeploy` | `POST /api/functions/undeploy` | executor tombstone precedes exact-identity Kernel unload; signed deployment receipt required |
| `FunctionDeployments` | RO | ✅ (`function deployments <json>`) | `alpha_function_deployments` | `POST /api/functions/deployments` | POST carries the structured bounded query; operation remains an ungated read |
| `JobSubmit` | Gated | ✅ (`job submit <json>`) | `alpha_job_submit` | `POST /api/jobs/submit` | returns durable `Accepted` only; never waits for terminal execution |
| `JobGet` | RO | ✅ (`job get <json>`) | `alpha_job_get` | `POST /api/jobs/get` | POST carries the attributable signed read request |
| `JobEvents` | RO | ✅ (`job events <json>`) | `alpha_job_events` | `POST /api/jobs/events` | bounded signed event-page read |
| `JobControl` | Gated | ✅ (`job control <json>`) | `alpha_job_control` | `POST /api/jobs/control` | signed steer/cancel/access mutation |
| `Send` | Gated | ✅ | `alpha_send` | `POST /api/send` | uniform |
| `Intent` | Gated | ✅ | `alpha_intent` | `POST /api/intent` | uniform |
| `Bind` | Gated | ✅ | `alpha_bind` | `POST /api/bind` | uniform |
| `Unload` | Gated | ✅ | `alpha_unload` | `POST /api/unload` | uniform |
| `AiStatus` | Mut, **ungated** | ✅ | `alpha_ai_status` | `POST /api/ai/status` | transparency channel — never gated *by design* |
| `AllowAi` | — | ✅ (`allow-ai on/off`) | **— (refused)** | **— (refused)** | **REPL-only by design**: refused when `ctx.gated`. Not a tool/route |
| `Help` | RO | ✅ (`help`) | — | — | REPL parser-internal (`COMMANDS`) |
| `Quit` | — | ✅ (`quit`/`exit`) | — | — | REPL lifecycle only |

**Counts:** MCP `tool_list` = **27** tools; HTTP = **26** verb endpoints (the 27 minus `alpha_watch`)
\+ `/api/health` + `/api/ws` (public). REPL covers all verbs plus `help`/`quit`. The asymmetries are
**three, all intentional** and must be made *discoverable* rather than removed: `Watch` has no HTTP route
(use `/api/ws`), `AllowAi` is REPL-only, `AiStatus` is mutating-but-ungated.

## Requirements

- **R1 — The parity matrix is the acceptance artifact and is pinned by a test.** The matrix above MUST
  hold: every verb reachable on each surface it should be, gating consistent, RO/mutating consistent. A
  test MUST assert (a) `tool_list` ≡ `known_tool` (already kept in lock-step by the dispatch guard),
  (b) the HTTP route set equals the MCP tool set **minus `alpha_watch`**, and (c) every
  `Verb::is_gated` verb is rejected over a
  gated surface without the allow-AI grant. `alpha/tests/mcp.rs` (`tools.len() == 27`)
  locks the MCP count; extend it to lock the cross-surface set, not just MCP.
  *Met (v0.4.3; extended v0.4.4):* (a) `alpha/tests/mcp.rs` pins the **exact** 27-name catalog (not just the count)
  and asserts no phantom `alpha_allow_ai`; (b) `alpha/tests/node_api.rs`
  `http_route_set_is_the_mcp_verb_set_minus_watch` behaviourally pins the 26 HTTP verb routes (non-404)
  + `/api/watch` absent (404) against the live router; (c) `node_api.rs`
  `health_is_public_auth_required_and_gate_blocks_mutation` asserts a mutating verb is refused
  (`403 ai-not-allowed`) over the gated HTTP surface while a read-only verb succeeds.
- **R2 — The MCP catalog is exactly 27, and docs that enumerate it match.** `tool_list`
  MUST list the 27 named in the matrix — no `alpha_allow_ai` (it does
  not exist; the earlier "20" audit miscounted a phantom verb). Any doc that *enumerates* the tools MUST
  list all 27. README uses "and the rest", so it does not drift.
- **R3 — `allow-ai`'s REPL-only nature is discoverable on the gated surfaces.** `AllowAi` is correctly
  refused when `ctx.gated` with `{"error":"repl-only", ...}`, and is
  correctly *absent* from `tool_list`/`/api/*`. But a host operator reading the MCP/HTTP capability set
  has nothing that explains *why* the gate-flip is missing. v0.4.3 MUST make the absence legible — e.g. a
  one-line note in the MCP `initialize`/`instructions` text or the HTTP capability doc, or surface the
  `repl-only` refusal as a documented capability. The `repl-only` error message text already exists and
  is good; this requirement is about the *discovery* path, not the error. *Met (v0.4.3):* the MCP
  initialize instructions explain self-contained startup gating, target-owned remote gating, and the
  deliberate absence of any remote gate-flip tool.
- **R4 — `demos.json` ↔ docs ↔ `alpha demo list` are consistent.** Before v0.4.3, the registry
  contained only the five runner-launched demos while the documented `cluster` runbook existed only
  on disk; consequently `alpha demo list` omitted it and `alpha demo run cluster` returned
  "unknown demo." *Met (v0.4.3):* `demos/demos.json` now contains **six** entries: five external
  Cargo-package demos (`walkthrough`, `federation`, `distribute`, `bestiary-live`, `dialogue`) and
  `cluster` with `manual: true` plus `runbook: "cluster"`. `alpha demo list` tags that sixth entry
  `(manual runbook)`, while `alpha demo run cluster` prints the numbered runbook pointer and exits
  successfully rather than pretending the multi-process walkthrough is one launchable child.
- **R5 — No verb returns stub/placeholder/canned data.** Every arm of `run_verb`
  MUST act on the live kernel/bus — verified: every arm dispatches to a real handler. The **one**
  non-acting response, `Verb::Watch`, returns a *pointer*
  ("the monitor is tailing PROPRIOCEPTION + FITNESS … connect to `/api/ws` for the live stream"), which
  is **acceptable and intentional** (control replies are request/reply; streaming lives on `/api/ws`).
  This MUST be documented as deliberate so a future audit does not mistake it for a stub.
- **R6 — `omega serve` exposes no half-wired flag.** `omega serve` (`omega/src/serve.rs`) MUST compose a
  complete node: transport + registry-mem + omega-federator (always), the `federation-scheduler`
  companion only under `--pull-interval`, and the HTTP/WS control plane only under `--listen`.
  Verified: `--cluster-listen` is required and checked; `--pull-interval` without `--peer-realm`
  routes warns and stays poke-driven rather than silently no-op'ing. No flag advertises a capability
  it does not deliver.
- **R7 — The cluster-demo disposition is recorded once.** The multi-process shell walkthrough cannot
  be represented honestly as one `cargo run -p` child. *Met (v0.4.3):* ADR-0045 records the
  manual-runbook entry shape; the registry, runner, and `demos/README.md` all distinguish the five
  externally launched demos from the listed-but-manual `cluster` runbook. Tests pin both the list tag
  and the successful runbook-pointer behavior.

## Findings register

| Finding | Status | Evidence |
|---|---|---|
| MCP `tool_list` exposes exactly **27** `alpha_*` tools | **Verified** | `surface-mcp::tool_list`; test `alpha/tests/mcp.rs` |
| Earlier "20 tools incl. `alpha_allow_ai`" was a miscount | **Verified** → corrected | no `alpha_allow_ai` token exists anywhere in tree |
| `tool_list` ≡ `known_tool` (catalog/dispatch lock-step) | **Verified** | `surface_mcp::{tool_list,known_tool}` plus the dispatch guard |
| `allow-ai` is REPL-only; refused when `ctx.gated`, not a tool/route | **Verified** | `omni::run_verb`; absent from `tool_list` and `/api/*` |
| The deliberate absence of a remote gate-flip is discoverable | **Resolved / Verified** | MCP initialize instructions explain self-contained startup, target-owned remote gating, and that no remote tool flips it |
| No verb returns stub/canned data | **Verified** | every `omni::run_verb` arm dispatches live |
| `Verb::Watch` returns a pointer, not a stream | **Verified** → intentional | `omni::run_verb`; streaming is `/api/ws` (`surface-http`) |
| HTTP mirrors MCP **minus** `alpha_watch` (no `/api/watch`) | **Verified** | `surface-http::router` (26 verb routes + health + ws) |
| Tool `alpha_list` ↔ route `/api/creatures` name skew (both → `Verb::List`) | **Verified** → cosmetic | `surface_mcp::tool_list` vs `surface_http::router` |
| Pre-v0.4.3: `cluster` existed on disk but was absent from the five-entry registry | **Resolved** | ADR-0045; retained here as historical problem context |
| Current demo registry contains 6 entries: 5 external children + 1 manual runbook | **Verified** | `demos/demos.json`; `cluster` has `manual: true`, `runbook: "cluster"` |
| `alpha demo list` tags `cluster`; `alpha demo run cluster` prints its runbook and exits 0 | **Verified** | `alpha/tests/demo.rs::{list_shows_the_cluster_manual_runbook_tagged,run_cluster_prints_the_runbook_and_exits_zero}` |
| HTTP auth: Bearer key + constant-time compare + body cap | **Verified** | `surface_http::{router,auth_ok}` and bounded request extraction |
| `omega serve` has no half-wired flag | **Verified** | `omega::serve::{parse_args,run}` and its composition tests |

## Acceptance

- ✅ A test pins the parity matrix: MCP tool set pinned exactly (`alpha/tests/mcp.rs`); HTTP `/api/*`
  verb set == MCP set minus `alpha_watch` (`alpha/tests/node_api.rs`); every `is_gated` verb is refused
  over a gated surface absent the allow-AI grant (`node_api.rs`).
- `docs/design/bus-and-control.md` enumerates all **27** tools; a
  grep-level check (or the matrix here) confirms no doc enumerates a phantom `alpha_allow_ai`.
- `allow-ai`'s REPL-only posture is discoverable from a gated surface (MCP `instructions`/HTTP caps note,
  or documented `repl-only` capability) — verified by reading the surface's own self-description.
- ✅ `alpha demo list` and `demos/README.md` agree on all six registry entries. `cluster` is tagged as
  a manual runbook, and `alpha demo run cluster` prints its step sequence and exits successfully;
  ADR-0045 records why it is not launched as one child.
- `Verb::Watch`'s pointer response is documented as intentional (not a stub) at its definition and in the
  surface design doc.
- `omega serve --help` / boot output matches the wired flags; no flag claims an undelivered capability.
