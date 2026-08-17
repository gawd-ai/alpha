// kv-extract — parse a `k=v;k=v;...` payload into a map and reply with ONE value, selected by the
// request's SCHEMA tag (the key to look up). Replies "" if the key is absent.
//
// This deliberately uses a tiny grammar instead of the engine's bounded `json_parse` and
// `json_stringify` helpers. String `split` plus a `#{}` object map cover this small controlled format;
// the example shows those building blocks (`env.text`, `split`, a map, the `in` operator).
//
// Example envelope: payload "a=1;b=2;c=3", schema "b" → "2". (`alpha node`'s convenience `send`
// verb has no schema argument; the example test constructs the schema-bearing Dispatch directly.)
fn handle(env) {
    let pairs = env.text.split(";");
    let m = #{};
    let i = 0;
    while i < pairs.len() {
        let kv = pairs[i].split("=");
        if kv.len() == 2 {
            m[kv[0]] = kv[1];
        }
        i += 1;
    }
    let key = env.schema;
    if key in m {
        m[key]
    } else {
        ""
    }
}
