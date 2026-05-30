# route-by-prefix — `emit` and the `calls` gate

The keystone critter: it proves a critter's **one** outward authority — `emit` — and the kernel-level
capability gate that governs it. It looks at the first byte of the payload and forwards the whole
payload elsewhere, then returns `()` (no direct reply):

| first byte | forwards to |
|---|---|
| `l` (108) | `topic:fitness` |
| `b` (98) | `role:build` |
| anything else | `kernel` |

```
send <id> "log:hi"   →   (no reply; "log:hi" is re-emitted onto topic:fitness)
```

## The `calls` gate

Every `emit` is checked at the kernel's one routing choke point against the manifest's `calls`
capability. A critter **never holds bus authority itself** — it parks dispatches the kernel chooses
to route:

- `calls` **empty** (the dev default) → all three targets allowed.
- `calls = ["topic:fitness"]` → an `emit("role:build", …)` becomes a kernel-level
  `RouteError::Denied`.

So the same source is safe to load with a tight `calls` allow-list: the policy, not the script,
decides where it may speak.
