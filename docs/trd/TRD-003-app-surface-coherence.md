# TRD-003 — App-surface coherence

- **Status:** Met (v0.4.3)
- **Theme:** Convergence
- **Spawns:** [ADR-0045](../adr/ADR-0045-demo-registry-coherence.md) (demo-registry coherence) — *only if the
  cluster-demo disposition is a genuine fork; otherwise folded as R7 below.*
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

Sources: verb dispatch `omni::run_verb` (`cosmos/omni/src/lib.rs:729`) + gating set
`Verb::is_gated` (`cosmos/omni/src/lib.rs:330`); MCP catalog `tool_list`
(`cosmos/creatures/surface-mcp/src/lib.rs:451-472`); HTTP routes `router`
(`cosmos/creatures/surface-http/src/lib.rs:420-444`). Gated = honors the allow-AI gate when the caller
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
| `Send` | Gated | ✅ | `alpha_send` | `POST /api/send` | uniform |
| `Intent` | Gated | ✅ | `alpha_intent` | `POST /api/intent` | uniform |
| `Bind` | Gated | ✅ | `alpha_bind` | `POST /api/bind` | uniform |
| `Unload` | Gated | ✅ | `alpha_unload` | `POST /api/unload` | uniform |
| `AiStatus` | Mut, **ungated** | ✅ | `alpha_ai_status` | `POST /api/ai/status` | transparency channel — never gated *by design* |
| `AllowAi` | — | ✅ (`allow-ai on/off`) | **— (refused)** | **— (refused)** | **REPL-only by design**: refused when `ctx.gated` (`lib.rs:761-766`). Not a tool/route |
| `Help` | RO | ✅ (`help`) | — | — | REPL parser-internal (`COMMANDS`) |
| `Quit` | — | ✅ (`quit`/`exit`) | — | — | REPL lifecycle only |

**Counts:** MCP `tool_list` = **19** tools; HTTP = **18** verb endpoints (the 19 minus `alpha_watch`)
\+ `/api/health` + `/api/ws` (public). REPL covers all verbs plus `help`/`quit`. The asymmetries are
**three, all intentional** and must be made *discoverable* rather than removed: `Watch` has no HTTP route
(use `/api/ws`), `AllowAi` is REPL-only, `AiStatus` is mutating-but-ungated.

## Requirements

- **R1 — The parity matrix is the acceptance artifact and is pinned by a test.** The matrix above MUST
  hold: every verb reachable on each surface it should be, gating consistent, RO/mutating consistent. A
  test MUST assert (a) `tool_list` ≡ `known_tool` (`surface-mcp/src/lib.rs:451,709` — already in
  lock-step via the `unreachable!` at `:598`), (b) the HTTP route set equals the MCP tool set **minus
  `alpha_watch`** (`surface-http/src/lib.rs:420`), and (c) every `Verb::is_gated` verb is rejected over a
  gated surface without the allow-AI grant. The existing `alpha/tests/mcp.rs:98` (`tools.len() == 19`)
  locks the MCP count; extend it to lock the cross-surface set, not just MCP.
  *Met (v0.4.3):* (a) `alpha/tests/mcp.rs` now pins the **exact** 19-name catalog (not just the count)
  and asserts no phantom `alpha_allow_ai`; (b) `alpha/tests/node_api.rs`
  `http_route_set_is_the_mcp_verb_set_minus_watch` behaviourally pins the 18 HTTP verb routes (non-404)
  + `/api/watch` absent (404) against the live router; (c) `node_api.rs`
  `health_is_public_auth_required_and_gate_blocks_mutation` asserts a mutating verb is refused
  (`403 ai-not-allowed`) over the gated HTTP surface while a read-only verb succeeds.
- **R2 — The MCP catalog is exactly 19, and docs that enumerate it match.** `tool_list`
  (`surface-mcp/src/lib.rs:451-472`) MUST list the 19 named in the matrix — no `alpha_allow_ai` (it does
  not exist; the earlier "20" audit miscounted a phantom verb). Any doc that *enumerates* the tools MUST
  list all 19. **Drift to fix:** `docs/design/bus-and-control.md:386-392` enumerates the catalog but omits
  **`alpha_registry_fetch_load`** (lists 18 of 19). README (`README.md:135`) uses "and the rest", so it
  does not drift. The fix is doc-only and additive.
- **R3 — `allow-ai`'s REPL-only nature is discoverable on the gated surfaces.** `AllowAi` is correctly
  refused when `ctx.gated` (`cosmos/omni/src/lib.rs:761-766`) with `{"error":"repl-only", ...}`, and is
  correctly *absent* from `tool_list`/`/api/*`. But a host operator reading the MCP/HTTP capability set
  has nothing that explains *why* the gate-flip is missing. v0.4.3 MUST make the absence legible — e.g. a
  one-line note in the MCP `initialize`/`instructions` text or the HTTP capability doc, or surface the
  `repl-only` refusal as a documented capability. The `repl-only` error message text already exists and
  is good; this requirement is about the *discovery* path, not the error.
- **R4 — `demos.json` ↔ docs ↔ `alpha demo list` are consistent.** `alpha demo list`
  (`alpha/src/demo.rs:111-122`) prints only `demos/demos.json` entries (walkthrough, federation,
  distribute, bestiary-live, dialogue = **5**). The `cluster` demo exists on disk
  (`demos/cluster/*.sh` + `README.md`) and is documented in the same demo table as the managed ones
  (`demos/README.md:15`, plus `AGENTS.md:96`, `docs/quickstart/operator.md:172`, `README.md:114`,
  `CHANGELOG.md:153`) but is **not** in `demos.json`, so `alpha demo list` never shows it and
  `alpha demo run cluster` fails with "unknown demo". v0.4.3 MUST close the gap **one** of two ways
  (see R7 / ADR-0045): register it, or have `alpha demo list` point at the manual runbook so the
  managed-runner output is not silently incomplete.
- **R5 — No verb returns stub/placeholder/canned data.** Every arm of `run_verb`
  (`cosmos/omni/src/lib.rs:736-838`) MUST act on the live kernel/bus — verified: all ~22 arms dispatch to
  a real handler. The **one** non-acting response, `Verb::Watch` (`lib.rs:757-759`), returns a *pointer*
  ("the monitor is tailing PROPRIOCEPTION + FITNESS … connect to `/api/ws` for the live stream"), which
  is **acceptable and intentional** (control replies are request/reply; streaming lives on `/api/ws`).
  This MUST be documented as deliberate so a future audit does not mistake it for a stub.
- **R6 — `omega serve` exposes no half-wired flag.** `omega serve` (`omega/src/serve.rs`) MUST compose a
  complete node: transport + registry-mem + omega-federator (always), the `federation-scheduler`
  companion only under `--pull-interval` (`serve.rs:94-100,226`), and the HTTP/WS control plane only under
  `--listen` (`serve.rs:105,245-284`). Verified: `--cluster-listen` is required-and-checked
  (`serve.rs:132-136`); `--pull-interval` without `--peer-realm` routes warns and stays poke-driven
  (`serve.rs:234`) rather than silently no-op'ing. No flag advertises a capability it does not deliver.
- **R7 — The cluster-demo disposition is recorded once.** If registering `cluster` in `demos.json` is
  awkward (it is a multi-process shell runbook, not a single `cargo run -p`), the decision to keep it
  *manual-only* MUST be recorded — as **ADR-0045** if it is a genuine fork in how demos are surfaced, or
  folded as the R4 fix if it is a one-line registry/pointer change. Either way `alpha demo list` and the
  `demos/README.md` table MUST stop disagreeing about whether `cluster` is a runner-managed demo.

## Findings register

| Finding | Status | Evidence |
|---|---|---|
| MCP `tool_list` exposes exactly **19** `alpha_*` tools | **Verified** | `surface-mcp/src/lib.rs:451-472` (19 enumerated); test `alpha/tests/mcp.rs:98` |
| Earlier "20 tools incl. `alpha_allow_ai`" was a miscount | **Verified** → corrected | no `alpha_allow_ai` token exists anywhere in tree |
| `tool_list` ≡ `known_tool` (catalog/dispatch lock-step) | **Verified** | `surface-mcp/src/lib.rs:451` vs `:709`; `unreachable!` guard `:598` |
| `allow-ai` is REPL-only; refused when `ctx.gated`, not a tool/route | **Verified** | `cosmos/omni/src/lib.rs:761-766`; absent from `tool_list` & `/api/*` |
| `allow-ai` absence is correct-by-design but **undiscoverable** to a host | **Verified** | nothing in MCP `instructions`/HTTP caps explains the missing gate-flip |
| No verb returns stub/canned data | **Verified** | all `run_verb` arms `lib.rs:736-838` dispatch live |
| `Verb::Watch` returns a pointer, not a stream | **Verified** → intentional | `lib.rs:757-759`; streaming is `/api/ws` (`surface-http`) |
| HTTP mirrors MCP **minus** `alpha_watch` (no `/api/watch`) | **Verified** | `surface-http/src/lib.rs:420-444` (18 verb routes + health + ws) |
| Tool `alpha_list` ↔ route `/api/creatures` name skew (both → `Verb::List`) | **Verified** → cosmetic | `surface-mcp:454` vs `surface-http:423` |
| `cluster` demo on disk but **not** in `demos.json` (5 registered, not 6) | **Verified** | `demos/demos.json` (5); `demos/cluster/*.sh` exist; `alpha/src/demo.rs:111` lists only json |
| Docs reference `cluster` as a manual `cd demos/cluster && ./*.sh` runbook | **Verified** | `demos/README.md:15,43-49`; not claimed as `alpha demo run cluster` |
| `docs/design/bus-and-control.md` tool enumeration omits `alpha_registry_fetch_load` | **Verified** (new) | `bus-and-control.md:386-392` lists 18/19 |
| HTTP auth: Bearer key + constant-time compare + body cap | **Verified** | `surface-http/src/lib.rs:443,449,472,55-57` |
| `omega serve` has no half-wired flag | **Verified** | `omega/src/serve.rs:132-136,94-100,234,245-284` |

## Acceptance

- ✅ A test pins the parity matrix: MCP tool set pinned exactly (`alpha/tests/mcp.rs`); HTTP `/api/*`
  verb set == MCP set minus `alpha_watch` (`alpha/tests/node_api.rs`); every `is_gated` verb is refused
  over a gated surface absent the allow-AI grant (`node_api.rs`).
- `docs/design/bus-and-control.md` enumerates all **19** tools (adds `alpha_registry_fetch_load`); a
  grep-level check (or the matrix here) confirms no doc enumerates a phantom `alpha_allow_ai`.
- `allow-ai`'s REPL-only posture is discoverable from a gated surface (MCP `instructions`/HTTP caps note,
  or documented `repl-only` capability) — verified by reading the surface's own self-description.
- `alpha demo list` and `demos/README.md` agree on `cluster`: it is either in `demos.json` (and runs via
  `alpha demo run cluster`) or `alpha demo list` points at the manual runbook; the disposition is
  recorded (R7 / ADR-0045).
- `Verb::Watch`'s pointer response is documented as intentional (not a stub) at its definition and in the
  surface design doc.
- `omega serve --help` / boot output matches the wired flags; no flag claims an undelivered capability.
