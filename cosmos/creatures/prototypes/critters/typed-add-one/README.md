# typed-add-one

A real typed Function target in one Rhai file. `function-executor` addresses it through the ordinary
creature ABI with a `gawd.function.call.v1` message. Before parsing, the script uses
`function_call_verify` to verify the Home-signed grant, stable-executor-signed dispatch, and exact
local executor/target route. It then uses the pure, bounded `json_parse` and `json_stringify` helpers
and returns a `FunctionResultV1` containing the exact AttemptId it received.

Its manifest must declare a structured entrypoint named `add_one`, signature
`gawd.function.call.v1`, and `abi.backend: critter` / `abi_tag: gawd_critter_v1`. The composed proof in
[`cosmos/sanctum/tests/function_jobs.rs`](../../../../sanctum/tests/function_jobs.rs) constructs that
manifest, computes the source SHA-256 into
`provenance.build_hash` before the manifest content address, loads this source through the real
`ScriptEngine`, and drives Home → policy → executor → critter → signed terminal receipt.

The JSON helpers are transformations, not capabilities: no filesystem, network, clock, random, or
key access is added. Each conversion is bounded by the critter structural cap plus fixed byte,
nesting, and node ceilings.
