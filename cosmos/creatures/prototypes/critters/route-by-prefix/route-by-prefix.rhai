// route-by-prefix — the keystone critter: it proves a critter's ONE outward authority, `emit`.
//
// It looks at the FIRST byte of the payload and forwards the whole payload to a different address:
//   'l' (108) → topic:fitness   (a sense/telemetry topic any creature may subscribe to)
//   'b' (98)  → role:build      (whatever creature is bound to the BUILD role)
//   otherwise → kernel
// It returns `()`, so there is no direct reply — the only effect is the routed `emit`.
//
// Every `emit` is gated by the manifest's `calls` capability, checked at the kernel's one routing
// choke point. With `calls` empty (the dev default) all three targets are allowed; tighten `calls`
// to e.g. ["topic:fitness"] and an `emit("role:build", …)` becomes a kernel-level RouteError::Denied
// — the critter never holds bus authority itself, it only parks dispatches the kernel chooses to route.
fn handle(env) {
    let src = env.payload;
    if src.len() > 0 {
        let first = src[0];
        if first == 108 {            // 'l'
            emit("topic:fitness", src);
        } else if first == 98 {      // 'b'
            emit("role:build", src);
        } else {
            emit("kernel", src);
        }
    }
    ()
}
