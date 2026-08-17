// contains — a predicate critter. Replies "yes" if the message TEXT contains the request's SCHEMA
// tag as a substring, else "no".
//
// Shows string work via `env.text` (the bounded lossy-UTF-8 preview of the payload) and `env.schema`
// (the request's schema tag, repurposed here as the needle). Honestly per-envelope STATELESS: every
// answer derives only from THIS envelope. Critters can opt into bounded instance-local persistence
// through mem_get/mem_set/mem_del; this one deliberately does not.
//
// Example envelope: payload "hello world", schema "world" → "yes"; schema "xyz" → "no".
// (`alpha node`'s convenience `send` verb has no schema argument; the example test constructs the
// schema-bearing Dispatch directly.)
fn handle(env) {
    if env.text.contains(env.schema) {
        "yes"
    } else {
        "no"
    }
}
