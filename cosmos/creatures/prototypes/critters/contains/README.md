# contains — a stateless predicate

Replies `"yes"` if the message **text** contains the request's **schema** tag as a substring, else
`"no"`.

```rhai
fn handle(env) {
    if env.text.contains(env.schema) { "yes" } else { "no" }
}
```

```
send <id> "hello world"   (schema "world")   →   "yes"
send <id> "hello world"   (schema "xyz")     →   "no"
```

The honest **stateless** example: every answer derives only from *this* envelope. Critters can retain
bounded instance-local state explicitly through `mem_get` / `mem_set` / `mem_del`; `contains` does not.
(`env.schema` is just a convenient second string to compare against.)
