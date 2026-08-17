# kv-extract — a tiny split + map grammar

Parses a `k=v;k=v;…` payload into an object map and replies with **one** value, selected by the
request's **schema** tag (the key). Replies `""` if the key is absent.

```text
envelope payload "a=1;b=2;c=3", schema "b"   →   "2"
```

This is an envelope/API example, not a literal `alpha node` `send` command: that convenience verb
has no schema argument. The example test constructs the schema-bearing `Dispatch` directly.

This deliberately uses a tiny format instead of the engine's bounded `json_parse` /
`json_stringify` helpers. String `split`, an `#{}` object map, and the `in` operator are enough when a
critter controls a small text grammar; the example shows those building blocks (`env.text`, `split`,
a map, `in`) without implying that Rhai lacks JSON support.
