// uppercase — the first step past echo: read the payload as text and upper-case it.
//
// `env.text` is the payload decoded as a (lossy) UTF-8 string. The critter engine has no Blob→String
// builtin, so `env.text` is how a critter does string work; returning a string replies with its
// UTF-8 bytes. (For byte-exact, non-UTF-8-safe upper-casing, walk `env.payload` and subtract 32 from
// each lowercase byte — see the authored `uppercase-critter` template in `agent-templated`.)
//
// Try:  send <id> "hello, world!"   →   "HELLO, WORLD!"
fn handle(env) {
    env.text.to_upper()
}
