// rot13 — the classic Caesar cipher (+13 over the ASCII letters; all other bytes pass through).
//
// A bounded single pass over the bytes: the cost is proportional to the input length, which makes
// this the metering-friendly counter-example to a greedy `while true {}` critter (the engine kills
// that one on its operation/fuel cap). Applying rot13 twice returns the original — the test relies
// on it. Pure byte arithmetic on `env.payload`; no string conversion needed.
//
// Try:  send <id> "Hello"   →   "Uryyb"   (and rot13 of "Uryyb" is "Hello" again)
// The arithmetic is split into single-op statements for readability and so each source statement maps
// to one metered operation; the one-liner `(b - 65 + 13) % 26 + 65` compiles fine too (the engine's
// expression-depth cap is far higher) — the stepwise form is a clarity choice, not a requirement.
fn handle(env) {
    let src = env.payload;
    let out = blob();
    let i = 0;
    while i < src.len() {
        let b = src[i];
        let r = b;
        if b >= 65 && b <= 90 {          // 'A'..='Z'
            r = b - 65;
            r = r + 13;
            r = r % 26;
            r = r + 65;
        } else if b >= 97 && b <= 122 {  // 'a'..='z'
            r = b - 97;
            r = r + 13;
            r = r % 26;
            r = r + 97;
        }
        out.push(r);
        i += 1;
    }
    out
}
