# uppercase — Blob ↔ string

The first step past `echo`: read the payload as text and upper-case it.

```rhai
fn handle(env) { env.text.to_upper() }
```

`env.text` is a bounded lossy UTF-8 preview — the engine has no Blob→String builtin, so this is how a
critter does string work. Check `env.text_truncated` if partial input is not acceptable. Returning a
string replies with its UTF-8 bytes.

```
send <id> "hello, world!"   →   "HELLO, WORLD!"
```

For byte-exact, non-UTF-8-safe upper-casing, walk `env.payload` and subtract 32 from each lowercase
byte — that's what the authored `uppercase-critter` template in `creatures/agent-templated` does.
