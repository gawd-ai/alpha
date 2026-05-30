# Copilot instructions for Alpha

The AI-agent orientation for this repository lives in **[AGENTS.md](../AGENTS.md)** — read it first.
Alpha is this repository, source release, binary, and current substrate implementation; GAWD is the
company's overall goal and system universe, cosmology, and names that must remain stable across GAWD
systems, such as the `gawd_creature_v1` wire ABI. Commands, crates, release notes, and runtime UI in
this repo say Alpha; cross-system contracts, realm-scale concepts, and the broader objective say
GAWD. `AGENTS.md` is the machine-first map: the mental model, the repository layout (`cosmos/creatures/` organs ·
`cosmos/creatures/prototypes/<seam>/` injected models · `cosmos/creatures/prototypes/fixtures/` test
specimens), the build/run/test commands, and the **load-bearing invariants you must not break** (no
`#[global_allocator]`; never `panic = "abort"`; manifest signing order; the daemon tier is
trusted-by-admission; keep the kernel model-free).

Before authoring or changing a creature, also read [docs/TOPICS.md](../docs/TOPICS.md) (the pub/sub +
SEER consult contract) and [cosmos/sigil/README.md](../cosmos/sigil/README.md) (the manifest contract).
