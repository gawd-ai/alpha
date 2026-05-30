# rot13 — bounded byte arithmetic

The classic Caesar cipher (+13 over ASCII letters; everything else passes through), working directly
on `env.payload` bytes.

```
send <id> "Hello"   →   "Uryyb"      (and rot13 of "Uryyb" is "Hello" again)
```

Two things it teaches:

- **Metering-friendly by construction.** The cost is a single pass proportional to the input length —
  the honest counter-example to a greedy `while true {}` critter, which the engine kills on its
  operation (fuel) budget. Applying rot13 twice is the identity, which the test relies on.
- **Readable, step-by-step arithmetic.** The cipher is split into single-op statements
  (`r = b - 65; r = r + 13; r = r % 26; r = r + 65;`) rather than the one-liner
  `(b - 65 + 13) % 26 + 65`. Both compile — this is a clarity choice, not a requirement — but the
  stepwise form maps one source statement to one metered operation, so the fuel cost reads straight off
  the code. (The engine *does* pin a parse-time expression-nesting cap, identical in debug and release;
  this expression is nowhere near it.)
