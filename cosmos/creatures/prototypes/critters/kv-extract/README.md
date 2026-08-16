# kv-extract — a tiny split + map grammar

Parses a `k=v;k=v;…` payload into an object map and replies with **one** value, selected by the
request's **schema** tag (the key). Replies `""` if the key is absent.

```
send <id> "a=1;b=2;c=3"   (schema "b")   →   "2"
```

This deliberately uses a tiny format instead of the engine's bounded `json_parse` /
`json_stringify` helpers. String `split`, an `#{}` object map, and the `in` operator are enough when a
critter controls a small text grammar; the example shows those building blocks (`env.text`, `split`,
a map, `in`) without implying that Rhai lacks JSON support.
