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

The honest **stateless** example: the engine gives each `handle` call a fresh scope, so a critter
cannot accumulate state across messages — every answer derives only from *this* envelope. (`env.schema`
is just a convenient second string to compare against; persistence is a `daemon`/`beast` concern.)
