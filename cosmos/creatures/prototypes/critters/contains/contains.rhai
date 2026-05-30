// contains — a predicate critter. Replies "yes" if the message TEXT contains the request's SCHEMA
// tag as a substring, else "no".
//
// Shows string work via `env.text` (the lossy-UTF-8 view of the payload) and `env.schema` (the
// request's schema tag, repurposed here as the needle). Honestly per-envelope STATELESS: the engine
// gives each `handle` call a fresh scope, so a critter cannot accumulate state across messages —
// every answer derives only from THIS envelope. (Persistence is a daemon/beast concern.)
//
// Try:  send <id> "hello world"   with schema "world"   →   "yes"
//       send <id> "hello world"   with schema "xyz"     →   "no"
fn handle(env) {
    if env.text.contains(env.schema) {
        "yes"
    } else {
        "no"
    }
}
