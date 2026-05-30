// echo-critter — the reference critter (script-tier) creature.
//
// The script-tier analog of `fixtures/echo-daemon` (native) and the reverse-beast WAT (wasm): it
// returns its inbound payload unchanged. The critter engine turns a `handle` return value into a
// reply addressed to the envelope's reply target, so this is a complete request→reply creature in
// three lines, with no compile step — shipped as the UTF-8 source bytes you are reading.
//
// The contract: a critter defines `fn handle(env)`. `env` is a map with:
//   env.payload  — a Blob (the request bytes)
//   env.schema   — a string (the request's schema tag)
//   env.from     — an address string (e.g. "creature:7"), echo-able straight back to `emit`
//   env.corr     — an int correlation id, present only on correlated requests
// Return a Blob or string to reply; return `()` for no reply; call
// `emit("creature:N", bytes)` (or "role:R" / "topic:T" / "intent:X" / "kernel") to send additional,
// capability-gated dispatches that the kernel routes. The engine meters this script against
// `capabilities.cpu_ms` (an operation budget) and contains it by construction — no filesystem,
// network, clock, or rand.
fn handle(env) {
    env.payload
}
