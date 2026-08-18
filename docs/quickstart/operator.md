# Run a node and play with it (operator)

The other quickstarts ([critter](./critter.md) / [daemon](./daemon.md) / [beast](./beast.md)) write a
*creature*. This one is about driving the **substrate itself**: boot a live node, look around, make it
author and run code from a plain-English request, watch its sense-tape, then scale up to a small
federation of Realms. In the GAWD universe, the primary operator is an AI; here *you* are the
operator at the terminal.

Everything below is a real command against a live kernel — the same admission → engine → router path
the test suite uses. Nothing here is mocked.

---

## 1. Boot a live node

```sh
cargo run -p alpha -- node
```

A fresh `alpha node` is not an empty shell — it **self-hosts its own organs**: the authoring agent
(bound to `AUTHORING`), the build creatures (`BUILD` — native `cargo` *and* the no-compiler critter
builder), an in-memory registry (`REGISTRY`), and a `monitor` watching the sense streams. It prints a
probe id, the command list, and drops you at a prompt:

```
alpha node — Alpha Sanctum daemon (v0.5.0)
posture: DEV — the dev policy admits everything and the bus signer is a stub; not a hardened deployment.
boot: live substrate — agent-templated→AUTHORING, build-cargo→BUILD (+build-critter), registry-mem→REGISTRY, monitor watching the sense streams.
probe endpoint id = 1
commands: author [--critter] <request> | load <manifest> <artifact> | registry publish <manifest> <artifact> [realm] | registry fetch <artifact-hash> [realm] | registry list [realm] | registry fetch-load <artifact-hash> [<node-id> <registry-id>] [realm] | bestiary prove <artifact-hash> <realm> | function resolve <signed-request-json> | function deploy <request+resolution+paths-json> | function undeploy <request+deployment-receipt-json> | function deployments <query-json> | job submit <request+receipts-json> | job get <signed-request-json> | job events <signed-request-json> | job control <signed-request-json> | send <[node-id:]id> <text> | intent <outcome> <text> | bind <role> <id> | unload <id> | allow-ai <on|off> | cluster [join <id@host:port#pubkey>] | list | status | journal | watch | help | quit
alpha>
```

> Want a bare kernel with nothing bound (to wire it yourself with `bind`/`load`)? Boot with
> `cargo run -p alpha -- node --minimal`.

## 2. Look around

```
alpha> status
loaded creatures: 5
  role authoring        → id=2
  role build            → id=4
  role registry         → id=5
journal entries: 5
allow-ai: OFF

alpha> list
  id=2   agent-templated          [daemon]
  id=3   build-critter            [daemon]
  id=4   build-cargo              [daemon]
  id=5   registry-mem             [daemon]
  id=6   monitor                  [daemon]

alpha> journal          # the last bus envelopes (seq · stamp · from → to)
```

(Ids are assignment-order: the REPL's own probe endpoint takes `id=1`, so the boot organs are
`2..6` and the next creature you author lands at `id=7`.)

`status` is the node at a glance (loaded count, role bindings, journal length, and the allow-AI gate);
`list` is the roster; `journal` is the recent bus history.

## 3. Make it do something — author a creature, live

The headline move: ask for a capability (a keyword the bundled matcher recognizes — see the note
below, or build with `--features openai` for free-form English) and the substrate writes, signs,
admits, and hot-loads it. Start with a **critter** (a sandboxed script — milliseconds, no compiler):

```
alpha> author --critter reverse a string
authored `...` (... bytes of Rhai); signing (no cargo)…
✓ authored → signed → admitted → hot-loaded critter as id=7 (no compiler). Try: send 7 <text>

alpha> send 7 hello
reply: olleh
```

`list` now shows your creature sitting alongside the node's own organs. The native path is the same
verb without `--critter`:

```
alpha> author write a daemon that reverses a string
```

This one shells out to a real `cargo build` to compile the authored Rust, so the **first** call is slow
(tens of seconds while the dependency cache warms); later calls are quick. To load a creature you
already have on disk, use `load <manifest-path> <artifact-path>`.

> The shipped authoring agent is a deterministic *template matcher*, not an LLM — it proves the
> author → compile → sign → admit → load *seam*. An LLM-backed author binds the same `AUTHORING`
> socket. Native `author` matches requests containing `reverse` (→ the native daemon); the bundled
> *critter* templates are reached via `author --critter <request>` (e.g. `reverse a string` or
> `uppercase a message`), which injects the keyword the matcher keys on. A request that matches no
> template fails with a message naming the recognized keywords — it does **not** invent code. For
> free-form English authoring, build with `--features openai` and select a model (`--author-model
> <id>`); the same live LLM then binds `AUTHORING`.

## 4. Watch the substrate's senses

The `monitor` organ prints a live **sense-tape** as creatures load, handle envelopes, and report
fitness — the proprioception-as-a-sense idea, made visible. While you authored above, lines like these
scrolled past (the `┊` marks a sense event):

```
  ┊ [node] sense    · creature #7: loaded
  ┊ [node] fitness  · creature #7: useful
```

`watch` reminds you where the tape is and how to get the live stream over the API; `journal` is the
bounded, in-memory, drop-oldest diagnostic window if you want to scroll back. Durable application
facts live in their owning organs, not in the Router journal.

## 5. Roles, binding, and retiring creatures

The kernel ships *sockets*; creatures fill them. You can rewire the node live:

```
alpha> unload 7                  # retire the critter we authored: deregister → drain → engine::unload
alpha> bind distributor <id>     # plug a placement creature into the DISTRIBUTOR role socket
alpha> intent reverse hello      # capability-addressed: routes to whoever serves that outcome
```

`intent <outcome> <text>` is capability-addressed routing — it goes to whatever creature is bound to
serve that outcome, rather than to a fixed id. A real *placement* creature is what fills `DISTRIBUTOR`
(see the [federation demo](../../demos/federation/) and [`CONTRIBUTING.md`](../../CONTRIBUTING.md)); with
nothing bound to placement, `intent` reports "unrouted" and tells you to `bind` a distributor first.

## 6. Drive the node remotely (HTTP + MCP)

The REPL is the local human seat — never gated, always in full control. A node can *also* expose an
authenticated HTTP-REST + WebSocket control plane for web clients; MCP is a separate spawned
control-hub (`alpha mcp`) that drives the same `Role::CONTROL` bus surface:

```sh
cargo run -p alpha -- node --listen 127.0.0.1:7777     # prints a Bearer key
# For API-only mutation, add both --headless and --allow-ai (there is then no REPL).
curl -s localhost:7777/api/health                                  # public liveness
curl -s -H "Authorization: Bearer $KEY" localhost:7777/api/status  # auth'd; shows the allow-AI gate
```

A remote AI's *mutating* tools are blocked by the **allow-AI gate** (off by default). On an
interactive node, a human flips `allow-ai on|off` at that node's REPL and watches activity on the
sense-tape. A headless target has no REPL: opt in with `--allow-ai` at boot and restart without it to
revoke. In MCP remote mode the target owns this gate; the hub cannot grant itself permission. Full
MCP setup (the `.mcp.json`, required remote-profile flags, gate, and security posture) is in the
README's [*Drive it over MCP*](../../README.md#4-drive-it-over-mcp) rung.

## 7. Cluster real nodes into a mesh (a Realm of alphas)

A single `alpha node` is one node. Give it a cluster transport and it joins a **many-to-many mesh** with
other deployed nodes — gossip-based membership over the authenticated peer transport. `alpha` is the
**control surface**, so a mesh of alpha nodes is a **Realm** you author and drive from any member:

```sh
# node A (the seed) — boot prints its node-id, pubkey, and the `cluster join` line others use:
cargo run -p alpha -- node --node-id A --cluster-listen 127.0.0.1:9101 --listen 127.0.0.1:7101

# node B, handed A as its seed so it can authenticate the first hop:
cargo run -p alpha -- node --node-id B --cluster-listen 127.0.0.1:9102 --listen 127.0.0.1:7102 \
    --seed A@127.0.0.1:9101#<A-pubkey>
```

At a node's REPL (or over the API / MCP):

```
alpha> cluster join B@127.0.0.1:9102#<B-pubkey>   # admit + dial a peer (gossip spreads it onward)
alpha> cluster                                    # this node's view of the graph (● = connected)
alpha> send B:7 hello                             # run creature 7 living on node B, over the mesh
```

You introduce a node **once** (to any existing member); gossip propagates it so the mesh
self-completes — no node is pre-configured with every peer. The graph is also a live sense stream
(peer-connect/disconnect on `/api/ws`), and `GET /api/cluster` / `POST /api/cluster/connect` expose the
same over HTTP/MCP. The hands-on numbered runbook that stands up **three nodes**, forms the mesh,
cross-executes, and attaches one pre-admitted remote MCP hub to a chosen operator is
[`demos/cluster/`](../../demos/cluster/):

```sh
cd demos/cluster && ./00-build.sh && ./01-boot.sh && ./02-join.sh && \
  ./03-graph.sh poll && ./04-cross-run.sh && ./05-connect-ai.sh
```

**Realms meet at Omega.** The mesh above is one Realm of alpha control surfaces. To federate *across*
Realms you run the other pole — **`omega serve`**, a headless gateway per Realm that declares its own
Realm (`--realm`) and maps the others to their gateways (`--peer-realm <realm>=<node-id>`). The gateways
exchange catalogues by pull anti-entropy, federate signed reputation and quarantine, and route
Omega-addressed traffic between Realms — while authoring stays here on the alpha seat. Add
`--pull-interval <seconds>` and the gateway **reconciles itself**: a `federation-scheduler` companion
pokes the federator's anti-entropy on that cadence, so cross-Realm pulls no longer wait for an operator
(without the flag the gateway stays poke-driven — the substrate ships no clock). See the
[cross-Realm quickstart rung in the README](../../README.md#3-mesh-more-omegas-across-realms)
and run the whole cross-Realm story in-process with `cargo run -p federation`.

To run the real two-process Function/Job acceptance lifecycle—signed typed-critter deployment,
changed-id executor recovery, blocking-parent progress/Steer, signed Home migration, faulted GX gap
retry, typed causal child, dual hard restart, and terminal reconciliation—use:

```sh
cargo test -p sanctum --test function_jobs_cross_realm_process -- --test-threads=1
```

The test retries dropped/corrupted transfer gaps in memory and hard-cuts only at durable protocol
boundaries; it does not claim crash-resume inside an unfinished GX transfer.
The complementary in-process custody suite proves the optional root-declared KMS rewrap chain; the
process harness deliberately exercises the legacy no-rewrap branch.

## 8. Narrated demos (in one process)

The cluster above is real, separate processes. Several *narrated* demos run the deeper substrate paths
in a single process, each riding code the tests prove:

```sh
# One node's whole loop: a reference author → compile → sign → run, then a signed local hand-off
# between two bodies in one Sanctum. Cross-Sanctum transport is covered by integration tests.
cargo run -p walkthrough

# The federation fabric: several Sanctums across 2–3 Realms, wired over real ed25519-authenticated TCP
# on loopback. Watch a within-Realm fetch, then cross-Realm pull anti-entropy, signed reputation,
# quarantine propagation, and Omega-addressed routing (Loop 5, Acculturate).
cargo run -p federation                          # 2 Realms × 2 Sanctums (default)
cargo run -p federation -- --realms 3 --sanctums 2

# Credential-free v0.5.0 mechanism regression. This is not live-model product acceptance.
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 \
  cargo run --locked -p dialogue -- --fixture
```

`federation` boots each Sanctum as its own kernel and forms the mesh in front of you — the closest
thing to "stand up a small distributed Alpha deployment and poke it" without leaving one process;
`dialogue --fixture` carries strict scripted draft/review/test/approval decisions over the same wire,
then validates one bounded `affine_i32_v1` profile and uses trusted host templates to lower it into
Rust, no-import WAT, and Rhai. `BuildCargo`/`BuildBeast`/`BuildCritter`, durable
publication/recovery, and one local plus one cross-Realm Job per engine exercise the rest. The three
backend manifests intentionally yield distinct `FunctionId`s; each remains stable across its two
Jobs. Models do not supply executable source in this approved path. The three minds occupy two
in-process Kernel nodes, not three deployed Sanctum processes. One native Cargo compile uses the
shared `target/gawd-build-cache`; beast/critter builds invoke no Cargo.

For v0.5.0 product acceptance, use the protected exact-SHA workflow in the
[release checklist](../../RELEASE.md#additional-v050-live-acceptance-gate); the explicit
OpenAI-feature command in the [demo README](../../demos/README.md#notes) is an exploratory operator
path, not a weaker release gate. The workflow runs only after exact push CI, builds and copies the
candidate binary before materializing provider/operator secrets, and supplies three role-configured
Model injections plus the complete external prior-semantic registry. The same packaged binary then
runs `dialogue verify-live` offline with the pinned candidate SHA, authorized seal signer, evidence
directory, signed seal, and prior digests. It verifies seven provider calls/receipts, signed causal
decisions, trusted-lowered sources, three artifacts and Bestiary proofs, six complete Job bundles,
and source/result identity under the signed index. Raw prompt-bearing evidence is encrypted; the
separate disclosure-safe pack, exact binary, and both packages receive workflow attestations. The
90-day Actions artifacts must be promoted to immutable supported-lifetime storage before tag.
Fixture runs remain regression only. Provider receipts and workflow attestations do not prove model
weights, and the attestations are not a reproducible-build proof; this bounded affine profile is not
arbitrary-code synthesis or general agency.
See [`demos/`](../../demos/) for what each demo shows and the tests it rides on.

## 9. Shut down

```
alpha> quit
```

`quit` (or Ctrl-C, which is caught) runs the kernel's reverse-order `shutdown_all` — an orderly
teardown, not an abrupt kill.

---

### Non-interactive / scripted

For reproducible demos and CI, the same verbs run without the prompt:

```sh
cargo run -p alpha -- node --exec "author --critter reverse a string"   # run one verb, exit
cargo run -p alpha -- node --script demo.txt                            # run a file of verbs (# comments ok)
cargo run -p alpha -- node --json --exec status                         # machine-readable output (same JSON the API returns)
```

---

**Next:** to author your own creature on any tier, see the per-tier quickstarts —
[critter](./critter.md), [daemon](./daemon.md), [beast](./beast.md) — or
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) for adding one to the tree.
