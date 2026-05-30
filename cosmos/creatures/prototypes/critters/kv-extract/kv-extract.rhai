// kv-extract — parse a `k=v;k=v;...` payload into a map and reply with ONE value, selected by the
// request's SCHEMA tag (the key to look up). Replies "" if the key is absent.
//
// The honest substitute for "a JSON transform": the critter engine has no JSON, but string `split`
// plus a `#{}` object map cover the common shape. A real structured-transform critter would parse a
// format it controls; this shows the building blocks (`env.text`, `split`, a map, the `in` operator).
//
// Try:  send <id> "a=1;b=2;c=3"   with schema "b"   →   "2"
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
