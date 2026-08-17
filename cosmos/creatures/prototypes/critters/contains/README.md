# contains — a stateless predicate

Replies `"yes"` if the message **text** contains the request's **schema** tag as a substring, else
`"no"`.

```rhai
fn handle(env) {
    if env.text.contains(env.schema) { "yes" } else { "no" }
}
```

```text
envelope payload "hello world", schema "world"   →   "yes"
envelope payload "hello world", schema "xyz"     →   "no"
```

These are envelope/API examples, not literal `alpha node` `send` commands: that convenience verb
sets payload text but has no schema argument. The example test constructs the schema-bearing
`Dispatch` directly.

The honest **stateless** example: every answer derives only from *this* envelope. Critters can retain
bounded instance-local state explicitly through `mem_get` / `mem_set` / `mem_del`; `contains` does not.
(`env.schema` is just a convenient second string to compare against.)
