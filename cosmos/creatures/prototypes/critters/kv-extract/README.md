# kv-extract — split + map, the JSON substitute

Parses a `k=v;k=v;…` payload into an object map and replies with **one** value, selected by the
request's **schema** tag (the key). Replies `""` if the key is absent.

```
send <id> "a=1;b=2;c=3"   (schema "b")   →   "2"
```

The honest substitute for "a JSON transform": the critter engine has no JSON, but string `split`, an
`#{}` object map, and the `in` operator cover the common shape. A real structured-transform critter
would parse a format it controls — this just shows the building blocks (`env.text`, `split`, a map,
`in`).
